#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <libgen.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <asm/unistd.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <linux/ring_buffer.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <libelf.h>
#include <gelf.h>
#include <zlib.h>

#include "libbpf.h"
#include "bpf.h"
#include "btf.h"
#include "str_error.h"
#include "libbpf_internal.h"
#include "hashmap.h"
#include "bpf_gen_internal.h"
#include "zip.h"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

#define BPF_INSN_SZ (sizeof(struct bpf_insn))
#pragma GCC diagnostic ignored "-Wformat-nonliteral"

#define __printf(a, b) __attribute__((format(printf, a, b)))

static struct bpf_map *bpf_object__add_map(struct bpf_object *obj);
static bool prog_is_subprog(const struct bpf_object *obj, const struct bpf_program *prog);

static const char *const attach_type_name[] = {
    [BPF_CGROUP_INET_INGRESS] = "cgroup_inet_ingress",
    [BPF_CGROUP_INET_EGRESS] = "cgroup_inet_egress",
    [BPF_CGROUP_INET_SOCK_CREATE] = "cgroup_inet_sock_create",
    [BPF_CGROUP_INET_SOCK_RELEASE] = "cgroup_inet_sock_release",
    [BPF_CGROUP_SOCK_OPS] = "cgroup_sock_ops",
    [BPF_CGROUP_DEVICE] = "cgroup_device",
    [BPF_CGROUP_INET4_BIND] = "cgroup_inet4_bind",
    [BPF_CGROUP_INET6_BIND] = "cgroup_inet6_bind",
    [BPF_CGROUP_INET4_CONNECT] = "cgroup_inet4_connect",
    [BPF_CGROUP_INET6_CONNECT] = "cgroup_inet6_connect",
    [BPF_CGROUP_INET4_POST_BIND] = "cgroup_inet4_post_bind",
    [BPF_CGROUP_INET6_POST_BIND] = "cgroup_inet6_post_bind",
    [BPF_CGROUP_INET4_GETPEERNAME] = "cgroup_inet4_getpeername",
    [BPF_CGROUP_INET6_GETPEERNAME] = "cgroup_inet6_getpeername",
    [BPF_CGROUP_INET4_GETSOCKNAME] = "cgroup_inet4_getsockname",
    [BPF_CGROUP_INET6_GETSOCKNAME] = "cgroup_inet6_getsockname",
    [BPF_CGROUP_UDP4_SENDMSG] = "cgroup_udp4_sendmsg",
    [BPF_CGROUP_UDP6_SENDMSG] = "cgroup_udp6_sendmsg",
    [BPF_CGROUP_SYSCTL] = "cgroup_sysctl",
    [BPF_CGROUP_UDP4_RECVMSG] = "cgroup_udp4_recvmsg",
    [BPF_CGROUP_UDP6_RECVMSG] = "cgroup_udp6_recvmsg",
    [BPF_CGROUP_GETSOCKOPT] = "cgroup_getsockopt",
    [BPF_CGROUP_SETSOCKOPT] = "cgroup_setsockopt",
    [BPF_SK_SKB_STREAM_PARSER] = "sk_skb_stream_parser",
    [BPF_SK_SKB_STREAM_VERDICT] = "sk_skb_stream_verdict",
    [BPF_SK_SKB_VERDICT] = "sk_skb_verdict",
    [BPF_SK_MSG_VERDICT] = "sk_msg_verdict",
    [BPF_LIRC_MODE2] = "lirc_mode2",
    [BPF_FLOW_DISSECTOR] = "flow_dissector",
    [BPF_TRACE_RAW_TP] = "trace_raw_tp",
    [BPF_TRACE_FENTRY] = "trace_fentry",
    [BPF_TRACE_FEXIT] = "trace_fexit",
    [BPF_MODIFY_RETURN] = "modify_return",
    [BPF_LSM_MAC] = "lsm_mac",
    [BPF_LSM_CGROUP] = "lsm_cgroup",
    [BPF_SK_LOOKUP] = "sk_lookup",
    [BPF_TRACE_ITER] = "trace_iter",
    [BPF_XDP_DEVMAP] = "xdp_devmap",
    [BPF_XDP_CPUMAP] = "xdp_cpumap",
    [BPF_XDP] = "xdp",
    [BPF_SK_REUSEPORT_SELECT] = "sk_reuseport_select",
    [BPF_SK_REUSEPORT_SELECT_OR_MIGRATE] = "sk_reuseport_select_or_migrate",
    [BPF_PERF_EVENT] = "perf_event",
    [BPF_TRACE_KPROBE_MULTI] = "trace_kprobe_multi",
    [BPF_STRUCT_OPS] = "struct_ops",
};

static const char *const link_type_name[] = {
    [BPF_LINK_TYPE_UNSPEC] = "unspec",
    [BPF_LINK_TYPE_RAW_TRACEPOINT] = "raw_tracepoint",
    [BPF_LINK_TYPE_TRACING] = "tracing",
    [BPF_LINK_TYPE_CGROUP] = "cgroup",
    [BPF_LINK_TYPE_ITER] = "iter",
    [BPF_LINK_TYPE_NETNS] = "netns",
    [BPF_LINK_TYPE_XDP] = "xdp",
    [BPF_LINK_TYPE_PERF_EVENT] = "perf_event",
    [BPF_LINK_TYPE_KPROBE_MULTI] = "kprobe_multi",
    [BPF_LINK_TYPE_STRUCT_OPS] = "struct_ops",
};

static const char *const map_type_name[] = {
    [BPF_MAP_TYPE_UNSPEC] = "unspec",
    [BPF_MAP_TYPE_HASH] = "hash",
    [BPF_MAP_TYPE_ARRAY] = "array",
    [BPF_MAP_TYPE_PROG_ARRAY] = "prog_array",
    [BPF_MAP_TYPE_PERF_EVENT_ARRAY] = "perf_event_array",
    [BPF_MAP_TYPE_PERCPU_HASH] = "percpu_hash",
    [BPF_MAP_TYPE_PERCPU_ARRAY] = "percpu_array",
    [BPF_MAP_TYPE_STACK_TRACE] = "stack_trace",
    [BPF_MAP_TYPE_CGROUP_ARRAY] = "cgroup_array",
    [BPF_MAP_TYPE_LRU_HASH] = "lru_hash",
    [BPF_MAP_TYPE_LRU_PERCPU_HASH] = "lru_percpu_hash",
    [BPF_MAP_TYPE_LPM_TRIE] = "lpm_trie",
    [BPF_MAP_TYPE_ARRAY_OF_MAPS] = "array_of_maps",
    [BPF_MAP_TYPE_HASH_OF_MAPS] = "hash_of_maps",
    [BPF_MAP_TYPE_DEVMAP] = "devmap",
    [BPF_MAP_TYPE_DEVMAP_HASH] = "devmap_hash",
    [BPF_MAP_TYPE_SOCKMAP] = "sockmap",
    [BPF_MAP_TYPE_CPUMAP] = "cpumap",
    [BPF_MAP_TYPE_XSKMAP] = "xskmap",
    [BPF_MAP_TYPE_SOCKHASH] = "sockhash",
    [BPF_MAP_TYPE_CGROUP_STORAGE] = "cgroup_storage",
    [BPF_MAP_TYPE_REUSEPORT_SOCKARRAY] = "reuseport_sockarray",
    [BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE] = "percpu_cgroup_storage",
    [BPF_MAP_TYPE_QUEUE] = "queue",
    [BPF_MAP_TYPE_STACK] = "stack",
    [BPF_MAP_TYPE_SK_STORAGE] = "sk_storage",
    [BPF_MAP_TYPE_STRUCT_OPS] = "struct_ops",
    [BPF_MAP_TYPE_RINGBUF] = "ringbuf",
    [BPF_MAP_TYPE_INODE_STORAGE] = "inode_storage",
    [BPF_MAP_TYPE_TASK_STORAGE] = "task_storage",
    [BPF_MAP_TYPE_BLOOM_FILTER] = "bloom_filter",
    [BPF_MAP_TYPE_USER_RINGBUF] = "user_ringbuf",
    [BPF_MAP_TYPE_CGRP_STORAGE] = "cgrp_storage",
};

static const char *const prog_type_name[] = {
    [BPF_PROG_TYPE_UNSPEC] = "unspec",
    [BPF_PROG_TYPE_SOCKET_FILTER] = "socket_filter",
    [BPF_PROG_TYPE_KPROBE] = "kprobe",
    [BPF_PROG_TYPE_SCHED_CLS] = "sched_cls",
    [BPF_PROG_TYPE_SCHED_ACT] = "sched_act",
    [BPF_PROG_TYPE_TRACEPOINT] = "tracepoint",
    [BPF_PROG_TYPE_XDP] = "xdp",
    [BPF_PROG_TYPE_PERF_EVENT] = "perf_event",
    [BPF_PROG_TYPE_CGROUP_SKB] = "cgroup_skb",
    [BPF_PROG_TYPE_CGROUP_SOCK] = "cgroup_sock",
    [BPF_PROG_TYPE_LWT_IN] = "lwt_in",
    [BPF_PROG_TYPE_LWT_OUT] = "lwt_out",
    [BPF_PROG_TYPE_LWT_XMIT] = "lwt_xmit",
    [BPF_PROG_TYPE_SOCK_OPS] = "sock_ops",
    [BPF_PROG_TYPE_SK_SKB] = "sk_skb",
    [BPF_PROG_TYPE_CGROUP_DEVICE] = "cgroup_device",
    [BPF_PROG_TYPE_SK_MSG] = "sk_msg",
    [BPF_PROG_TYPE_RAW_TRACEPOINT] = "raw_tracepoint",
    [BPF_PROG_TYPE_CGROUP_SOCK_ADDR] = "cgroup_sock_addr",
    [BPF_PROG_TYPE_LWT_SEG6LOCAL] = "lwt_seg6local",
    [BPF_PROG_TYPE_LIRC_MODE2] = "lirc_mode2",
    [BPF_PROG_TYPE_SK_REUSEPORT] = "sk_reuseport",
    [BPF_PROG_TYPE_FLOW_DISSECTOR] = "flow_dissector",
    [BPF_PROG_TYPE_CGROUP_SYSCTL] = "cgroup_sysctl",
    [BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE] = "raw_tracepoint_writable",
    [BPF_PROG_TYPE_CGROUP_SOCKOPT] = "cgroup_sockopt",
    [BPF_PROG_TYPE_TRACING] = "tracing",
    [BPF_PROG_TYPE_STRUCT_OPS] = "struct_ops",
    [BPF_PROG_TYPE_EXT] = "ext",
    [BPF_PROG_TYPE_LSM] = "lsm",
    [BPF_PROG_TYPE_SK_LOOKUP] = "sk_lookup",
    [BPF_PROG_TYPE_SYSCALL] = "syscall",
};

static int __base_pr(enum libbpf_print_level level, const char *format,
                     va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}

static libbpf_print_fn_t __libbpf_pr = __base_pr;

libbpf_print_fn_t libbpf_set_print(libbpf_print_fn_t fn)
{
    libbpf_print_fn_t old_print_fn;

    old_print_fn = __atomic_exchange_n(&__libbpf_pr, fn, __ATOMIC_RELAXED);

    return old_print_fn;
}

__printf(2, 3) void libbpf_print(enum libbpf_print_level level, const char *format, ...)
{
    va_list args;
    int old_errno;
    libbpf_print_fn_t print_fn;

    print_fn = __atomic_load_n(&__libbpf_pr, __ATOMIC_RELAXED);
    if (!print_fn)
        return;

    old_errno = errno;

    va_start(args, format);
    __libbpf_pr(level, format, args);
    va_end(args);

    errno = old_errno;
}

static void pr_perm_msg(int err)
{
    struct rlimit limit;
    char buf[100];

    if (err != -EPERM || geteuid() != 0)
        return;

    err = getrlimit(RLIMIT_MEMLOCK, &limit);
    if (err)
        return;

    if (limit.rlim_cur == RLIM_INFINITY)
        return;

    if (limit.rlim_cur < 1024)
        snprintf(buf, sizeof(buf), "%zu bytes", (size_t)limit.rlim_cur);
    else if (limit.rlim_cur < 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.1f KiB", (double)limit.rlim_cur / 1024);
    else
        snprintf(buf, sizeof(buf), "%.1f MiB", (double)limit.rlim_cur / (1024 * 1024));

    pr_warn("permission error while running as root; try raising 'ulimit -l'? current value: %s\n",
            buf);
}

#define STRERR_BUFSIZE 128

/* Copied from tools/perf/util/util.h */
#ifndef zfree
#define zfree(ptr) ({ free(*ptr); *ptr = NULL; })
#endif

#ifndef zclose
#define zclose(fd) ({			\
	int ___err = 0;			\
	if ((fd) >= 0)			\
		___err = close((fd));	\
	fd = -1;			\
	___err; })
#endif

static inline __u64 ptr_to_u64(const void *ptr)
{
    return (__u64)(unsigned long)ptr;
}

int libbpf_set_strict_mode(enum libbpf_strict_mode mode)
{
    /* as of v1.0 libbpf_set_strict_mode() is a no-op */
    return 0;
}

__u32 libbpf_major_version(void)
{
    return LIBBPF_MAJOR_VERSION;
}

__u32 libbpf_minor_version(void)
{
    return LIBBPF_MINOR_VERSION;
}

const char *libbpf_version_string(void)
{
#define __S(X) #X
#define _S(X) __S(X)
    return "v" _S(LIBBPF_MAJOR_VERSION) "." _S(LIBBPF_MINOR_VERSION);
#undef _S
#undef __S
}

enum reloc_type
{
    RELO_LD64,
    RELO_CALL,
    RELO_DATA,
    RELO_EXTERN_LD64,
    RELO_EXTERN_CALL,
    RELO_SUBPROG_ADDR,
    RELO_CORE,
};

struct reloc_desc
{
    enum reloc_type type;
    int insn_idx;
    union
    {
        const struct bpf_core_relo *core_relo; /* used when type == RELO_CORE */
        struct
        {
            int map_idx;
            int sym_off;
            int ext_idx;
        };
    };
};

enum sec_def_flags
{
    SEC_NONE = 0,
    SEC_EXP_ATTACH_OPT = 1,
    SEC_ATTACHABLE = 2,
    SEC_ATTACHABLE_OPT = SEC_ATTACHABLE | SEC_EXP_ATTACH_OPT,
    SEC_ATTACH_BTF = 4,
    SEC_SLEEPABLE = 8,
    SEC_XDP_FRAGS = 16,
};

struct bpf_sec_def
{
    char *sec;
    enum bpf_prog_type prog_type;
    enum bpf_attach_type expected_attach_type;
    long cookie;
    int handler_id;

    libbpf_prog_setup_fn_t prog_setup_fn;
    libbpf_prog_prepare_load_fn_t prog_prepare_load_fn;
    libbpf_prog_attach_fn_t prog_attach_fn;
};

struct bpf_program
{
    char *name;
    char *sec_name;
    size_t sec_idx;
    const struct bpf_sec_def *sec_def;
    size_t sec_insn_off;
    size_t sec_insn_cnt;
    size_t sub_insn_off;
    struct bpf_insn *insns;
    size_t insns_cnt;
    struct reloc_desc *reloc_desc;
    int nr_reloc;
    char *log_buf;
    size_t log_size;
    __u32 log_level;

    struct bpf_object *obj;
    int fd;
    bool autoload;
    bool autoattach;
    bool mark_btf_static;
    enum bpf_prog_type type;
    enum bpf_attach_type expected_attach_type;

    int prog_ifindex;
    __u32 attach_btf_obj_fd;
    __u32 attach_btf_id;
    __u32 attach_prog_fd;

    void *func_info;
    __u32 func_info_rec_size;
    __u32 func_info_cnt;

    void *line_info;
    __u32 line_info_rec_size;
    __u32 line_info_cnt;
    __u32 prog_flags;
};

struct bpf_struct_ops
{
    const char *tname;
    const struct btf_type *type;
    struct bpf_program **progs;
    __u32 *kern_func_off;
    void *data;
    void *kern_vdata;
    __u32 type_id;
};

#define DATA_SEC ".data"
#define BSS_SEC ".bss"
#define RODATA_SEC ".rodata"
#define KCONFIG_SEC ".kconfig"
#define KSYMS_SEC ".ksyms"
#define STRUCT_OPS_SEC ".struct_ops"
#define STRUCT_OPS_LINK_SEC ".struct_ops.link"

enum libbpf_map_type
{
    LIBBPF_MAP_UNSPEC,
    LIBBPF_MAP_DATA,
    LIBBPF_MAP_BSS,
    LIBBPF_MAP_RODATA,
    LIBBPF_MAP_KCONFIG,
};

struct bpf_map_def
{
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map
{
    struct bpf_object *obj;
    char *name;
    char *real_name;
    int fd;
    int sec_idx;
    size_t sec_offset;
    int map_ifindex;
    int inner_map_fd;
    struct bpf_map_def def;
    __u32 numa_node;
    __u32 btf_var_idx;
    __u32 btf_key_type_id;
    __u32 btf_value_type_id;
    __u32 btf_vmlinux_value_type_id;
    enum libbpf_map_type libbpf_type;
    void *mmaped;
    struct bpf_struct_ops *st_ops;
    struct bpf_map *inner_map;
    void **init_slots;
    int init_slots_sz;
    char *pin_path;
    bool pinned;
    bool reused;
    bool autocreate;
    __u64 map_extra;
};

enum extern_type
{
    EXT_UNKNOWN,
    EXT_KCFG,
    EXT_KSYM,
};

enum kcfg_type
{
    KCFG_UNKNOWN,
    KCFG_CHAR,
    KCFG_BOOL,
    KCFG_INT,
    KCFG_TRISTATE,
    KCFG_CHAR_ARR,
};

struct extern_desc
{
    enum extern_type type;
    int sym_idx;
    int btf_id;
    int sec_btf_id;
    const char *name;
    bool is_set;
    bool is_weak;
    union
    {
        struct
        {
            enum kcfg_type type;
            int sz;
            int align;
            int data_off;
            bool is_signed;
        } kcfg;
        struct
        {
            unsigned long long addr;

            /* target btf_id of the corresponding kernel var. */
            int kernel_btf_obj_fd;
            int kernel_btf_id;

            /* local btf_id of the ksym extern's type. */
            __u32 type_id;
            /* BTF fd index to be patched in for insn->off, this is
             * 0 for vmlinux BTF, index in obj->fd_array for module
             * BTF
             */
            __s16 btf_fd_idx;
        } ksym;
    };
};

struct module_btf
{
    struct btf *btf;
    char *name;
    __u32 id;
    int fd;
    int fd_array_idx;
};

enum sec_type
{
    SEC_UNUSED = 0,
    SEC_RELO,
    SEC_BSS,
    SEC_DATA,
    SEC_RODATA,
};

struct elf_sec_desc
{
    enum sec_type sec_type;
    Elf64_Shdr *shdr;
    Elf_Data *data;
};

struct elf_state
{
    int fd;
    const void *obj_buf;
    size_t obj_buf_sz;
    Elf *elf;
    Elf64_Ehdr *ehdr;
    Elf_Data *symbols;
    Elf_Data *st_ops_data;
    Elf_Data *st_ops_link_data;
    size_t shstrndx; /* section index for section name strings */
    size_t strtabidx;
    struct elf_sec_desc *secs;
    size_t sec_cnt;
    int btf_maps_shndx;
    __u32 btf_maps_sec_btf_id;
    int text_shndx;
    int symbols_shndx;
    int st_ops_shndx;
    int st_ops_link_shndx;
};

struct usdt_manager;

struct bpf_object
{
    char name[BPF_OBJ_NAME_LEN];
    char license[64];
    __u32 kern_version;

    struct bpf_program *programs;
    size_t nr_programs;
    struct bpf_map *maps;
    size_t nr_maps;
    size_t maps_cap;

    char *kconfig;
    struct extern_desc *externs;
    int nr_extern;
    int kconfig_map_idx;

    bool loaded;
    bool has_subcalls;
    bool has_rodata;

    struct bpf_gen *gen_loader;

    /* Information when doing ELF related work. Only valid if efile.elf is not NULL */
    struct elf_state efile;

    struct btf *btf;
    struct btf_ext *btf_ext;

    /* Parse and load BTF vmlinux if any of the programs in the object need
     * it at load time.
     */
    struct btf *btf_vmlinux;
    /* Path to the custom BTF to be used for BPF CO-RE relocations as an
     * override for vmlinux BTF.
     */
    char *btf_custom_path;
    /* vmlinux BTF override for CO-RE relocations */
    struct btf *btf_vmlinux_override;
    /* Lazily initialized kernel module BTFs */
    struct module_btf *btf_modules;
    bool btf_modules_loaded;
    size_t btf_module_cnt;
    size_t btf_module_cap;

    /* optional log settings passed to BPF_BTF_LOAD and BPF_PROG_LOAD commands */
    char *log_buf;
    size_t log_size;
    __u32 log_level;

    int *fd_array;
    size_t fd_array_cap;
    size_t fd_array_cnt;

    struct usdt_manager *usdt_man;

    char path[];
};

static const char *elf_sym_str(const struct bpf_object *obj, size_t off);
static const char *elf_sec_str(const struct bpf_object *obj, size_t off);
static Elf_Scn *elf_sec_by_idx(const struct bpf_object *obj, size_t idx);
static Elf_Scn *elf_sec_by_name(const struct bpf_object *obj, const char *name);
static Elf64_Shdr *elf_sec_hdr(const struct bpf_object *obj, Elf_Scn *scn);
static const char *elf_sec_name(const struct bpf_object *obj, Elf_Scn *scn);
static Elf_Data *elf_sec_data(const struct bpf_object *obj, Elf_Scn *scn);
static Elf64_Sym *elf_sym_by_idx(const struct bpf_object *obj, size_t idx);
static Elf64_Rel *elf_rel_by_idx(Elf_Data *data, size_t idx);

void bpf_program__unload(struct bpf_program *prog)
{
    if (!prog)
        return;

    zclose(prog->fd);

    zfree(&prog->func_info);
    zfree(&prog->line_info);
}

static void bpf_program__exit(struct bpf_program *prog)
{
    if (!prog)
        return;

    bpf_program__unload(prog);
    zfree(&prog->name);
    zfree(&prog->sec_name);
    zfree(&prog->insns);
    zfree(&prog->reloc_desc);

    prog->nr_reloc = 0;
    prog->insns_cnt = 0;
    prog->sec_idx = -1;
}

static bool insn_is_subprog_call(const struct bpf_insn *insn)
{
    return BPF_CLASS(insn->code) == BPF_JMP &&
           BPF_OP(insn->code) == BPF_CALL &&
           BPF_SRC(insn->code) == BPF_K &&
           insn->src_reg == BPF_PSEUDO_CALL &&
           insn->dst_reg == 0 &&
           insn->off == 0;
}

static bool is_call_insn(const struct bpf_insn *insn)
{
    return insn->code == (BPF_JMP | BPF_CALL);
}

static bool insn_is_pseudo_func(struct bpf_insn *insn)
{
    return is_ldimm64_insn(insn) && insn->src_reg == BPF_PSEUDO_FUNC;
}

static int
bpf_object__init_prog(struct bpf_object *obj, struct bpf_program *prog,
                      const char *name, size_t sec_idx, const char *sec_name,
                      size_t sec_off, void *insn_data, size_t insn_data_sz)
{
    if (insn_data_sz == 0 || insn_data_sz % BPF_INSN_SZ || sec_off % BPF_INSN_SZ)
    {
        pr_warn("sec '%s': corrupted program '%s', offset %zu, size %zu\n",
                sec_name, name, sec_off, insn_data_sz);
        return -EINVAL;
    }

    memset(prog, 0, sizeof(*prog));
    prog->obj = obj;

    prog->sec_idx = sec_idx;
    prog->sec_insn_off = sec_off / BPF_INSN_SZ;
    prog->sec_insn_cnt = insn_data_sz / BPF_INSN_SZ;
    /* insns_cnt can later be increased by appending used subprograms */
    prog->insns_cnt = prog->sec_insn_cnt;

    prog->type = BPF_PROG_TYPE_UNSPEC;
    prog->fd = -1;

    /* libbpf's convention for SEC("?abc...") is that it's just like
     * SEC("abc...") but the corresponding bpf_program starts out with
     * autoload set to false.
     */
    if (sec_name[0] == '?')
    {
        prog->autoload = false;
        /* from now on forget there was ? in section name */
        sec_name++;
    }
    else
    {
        prog->autoload = true;
    }

    prog->autoattach = true;

    /* inherit object's log_level */
    prog->log_level = obj->log_level;

    prog->sec_name = strdup(sec_name);
    if (!prog->sec_name)
        goto errout;

    prog->name = strdup(name);
    if (!prog->name)
        goto errout;

    prog->insns = malloc(insn_data_sz);
    if (!prog->insns)
        goto errout;
    memcpy(prog->insns, insn_data, insn_data_sz);

    return 0;
errout:
    pr_warn("sec '%s': failed to allocate memory for prog '%s'\n", sec_name, name);
    bpf_program__exit(prog);
    return -ENOMEM;
}

static int
bpf_object__add_programs(struct bpf_object *obj, Elf_Data *sec_data,
                         const char *sec_name, int sec_idx)
{
    Elf_Data *symbols = obj->efile.symbols;
    struct bpf_program *prog, *progs;
    void *data = sec_data->d_buf;
    size_t sec_sz = sec_data->d_size, sec_off, prog_sz, nr_syms;
    int nr_progs, err, i;
    const char *name;
    Elf64_Sym *sym;

    progs = obj->programs;
    nr_progs = obj->nr_programs;
    nr_syms = symbols->d_size / sizeof(Elf64_Sym);

    for (i = 0; i < nr_syms; i++)
    {
        sym = elf_sym_by_idx(obj, i);

        if (sym->st_shndx != sec_idx)
            continue;
        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;

        prog_sz = sym->st_size;
        sec_off = sym->st_value;

        name = elf_sym_str(obj, sym->st_name);
        if (!name)
        {
            pr_warn("sec '%s': failed to get symbol name for offset %zu\n",
                    sec_name, sec_off);
            return -LIBBPF_ERRNO__FORMAT;
        }

        if (sec_off + prog_sz > sec_sz)
        {
            pr_warn("sec '%s': program at offset %zu crosses section boundary\n",
                    sec_name, sec_off);
            return -LIBBPF_ERRNO__FORMAT;
        }

        if (sec_idx != obj->efile.text_shndx && ELF64_ST_BIND(sym->st_info) == STB_LOCAL)
        {
            pr_warn("sec '%s': program '%s' is static and not supported\n", sec_name, name);
            return -ENOTSUP;
        }

        pr_debug("sec '%s': found program '%s' at insn offset %zu (%zu bytes), code size %zu insns (%zu bytes)\n",
                 sec_name, name, sec_off / BPF_INSN_SZ, sec_off, prog_sz / BPF_INSN_SZ, prog_sz);

        progs = libbpf_reallocarray(progs, nr_progs + 1, sizeof(*progs));
        if (!progs)
        {

            pr_warn("sec '%s': failed to alloc memory for new program '%s'\n",
                    sec_name, name);
            return -ENOMEM;
        }
        obj->programs = progs;

        prog = &progs[nr_progs];

        err = bpf_object__init_prog(obj, prog, name, sec_idx, sec_name,
                                    sec_off, data + sec_off, prog_sz);
        if (err)
            return err;

        if (ELF64_ST_BIND(sym->st_info) != STB_LOCAL && (ELF64_ST_VISIBILITY(sym->st_other) == STV_HIDDEN || ELF64_ST_VISIBILITY(sym->st_other) == STV_INTERNAL))
            prog->mark_btf_static = true;

        nr_progs++;
        obj->nr_programs = nr_progs;
    }

    return 0;
}
