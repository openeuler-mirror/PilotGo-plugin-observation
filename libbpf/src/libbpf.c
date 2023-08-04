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

static const struct btf_member *
find_member_by_offset(const struct btf_type *t, __u32 bit_offset)
{
    struct btf_member *m;
    int i;

    for (i = 0, m = btf_members(t); i < btf_vlen(t); i++, m++)
    {
        if (btf_member_bit_offset(t, i) == bit_offset)
            return m;
    }

    return NULL;
}

static const struct btf_member *
find_member_by_name(const struct btf *btf, const struct btf_type *t,
                    const char *name)
{
    struct btf_member *m;
    int i;

    for (i = 0, m = btf_members(t); i < btf_vlen(t); i++, m++)
    {
        if (!strcmp(btf__name_by_offset(btf, m->name_off), name))
            return m;
    }

    return NULL;
}

#define STRUCT_OPS_VALUE_PREFIX "bpf_struct_ops_"
static int find_btf_by_prefix_kind(const struct btf *btf, const char *prefix,
                                   const char *name, __u32 kind);

static int
find_struct_ops_kern_types(const struct btf *btf, const char *tname,
                           const struct btf_type **type, __u32 *type_id,
                           const struct btf_type **vtype, __u32 *vtype_id,
                           const struct btf_member **data_member)
{
    const struct btf_type *kern_type, *kern_vtype;
    const struct btf_member *kern_data_member;
    __s32 kern_vtype_id, kern_type_id;
    __u32 i;

    kern_type_id = btf__find_by_name_kind(btf, tname, BTF_KIND_STRUCT);
    if (kern_type_id < 0)
    {
        pr_warn("struct_ops init_kern: struct %s is not found in kernel BTF\n",
                tname);
        return kern_type_id;
    }
    kern_type = btf__type_by_id(btf, kern_type_id);
    kern_vtype_id = find_btf_by_prefix_kind(btf, STRUCT_OPS_VALUE_PREFIX,
                                            tname, BTF_KIND_STRUCT);
    if (kern_vtype_id < 0)
    {
        pr_warn("struct_ops init_kern: struct %s%s is not found in kernel BTF\n",
                STRUCT_OPS_VALUE_PREFIX, tname);
        return kern_vtype_id;
    }
    kern_vtype = btf__type_by_id(btf, kern_vtype_id);

    kern_data_member = btf_members(kern_vtype);
    for (i = 0; i < btf_vlen(kern_vtype); i++, kern_data_member++)
    {
        if (kern_data_member->type == kern_type_id)
            break;
    }
    if (i == btf_vlen(kern_vtype))
    {
        pr_warn("struct_ops init_kern: struct %s data is not found in struct %s%s\n",
                tname, STRUCT_OPS_VALUE_PREFIX, tname);
        return -EINVAL;
    }

    *type = kern_type;
    *type_id = kern_type_id;
    *vtype = kern_vtype;
    *vtype_id = kern_vtype_id;
    *data_member = kern_data_member;

    return 0;
}

static bool bpf_map__is_struct_ops(const struct bpf_map *map)
{
    return map->def.type == BPF_MAP_TYPE_STRUCT_OPS;
}

/* Init the map's fields that depend on kern_btf */
static int bpf_map__init_kern_struct_ops(struct bpf_map *map,
                                         const struct btf *btf,
                                         const struct btf *kern_btf)
{
    const struct btf_member *member, *kern_member, *kern_data_member;
    const struct btf_type *type, *kern_type, *kern_vtype;
    __u32 i, kern_type_id, kern_vtype_id, kern_data_off;
    struct bpf_struct_ops *st_ops;
    void *data, *kern_data;
    const char *tname;
    int err;

    st_ops = map->st_ops;
    type = st_ops->type;
    tname = st_ops->tname;
    err = find_struct_ops_kern_types(kern_btf, tname,
                                     &kern_type, &kern_type_id,
                                     &kern_vtype, &kern_vtype_id,
                                     &kern_data_member);
    if (err)
        return err;

    pr_debug("struct_ops init_kern %s: type_id:%u kern_type_id:%u kern_vtype_id:%u\n",
             map->name, st_ops->type_id, kern_type_id, kern_vtype_id);

    map->def.value_size = kern_vtype->size;
    map->btf_vmlinux_value_type_id = kern_vtype_id;

    st_ops->kern_vdata = calloc(1, kern_vtype->size);
    if (!st_ops->kern_vdata)
        return -ENOMEM;

    data = st_ops->data;
    kern_data_off = kern_data_member->offset / 8;
    kern_data = st_ops->kern_vdata + kern_data_off;

    member = btf_members(type);
    for (i = 0; i < btf_vlen(type); i++, member++)
    {
        const struct btf_type *mtype, *kern_mtype;
        __u32 mtype_id, kern_mtype_id;
        void *mdata, *kern_mdata;
        __s64 msize, kern_msize;
        __u32 moff, kern_moff;
        __u32 kern_member_idx;
        const char *mname;

        mname = btf__name_by_offset(btf, member->name_off);
        kern_member = find_member_by_name(kern_btf, kern_type, mname);
        if (!kern_member)
        {
            pr_warn("struct_ops init_kern %s: Cannot find member %s in kernel BTF\n",
                    map->name, mname);
            return -ENOTSUP;
        }

        kern_member_idx = kern_member - btf_members(kern_type);
        if (btf_member_bitfield_size(type, i) ||
            btf_member_bitfield_size(kern_type, kern_member_idx))
        {
            pr_warn("struct_ops init_kern %s: bitfield %s is not supported\n",
                    map->name, mname);
            return -ENOTSUP;
        }

        moff = member->offset / 8;
        kern_moff = kern_member->offset / 8;

        mdata = data + moff;
        kern_mdata = kern_data + kern_moff;

        mtype = skip_mods_and_typedefs(btf, member->type, &mtype_id);
        kern_mtype = skip_mods_and_typedefs(kern_btf, kern_member->type,
                                            &kern_mtype_id);
        if (BTF_INFO_KIND(mtype->info) !=
            BTF_INFO_KIND(kern_mtype->info))
        {
            pr_warn("struct_ops init_kern %s: Unmatched member type %s %u != %u(kernel)\n",
                    map->name, mname, BTF_INFO_KIND(mtype->info),
                    BTF_INFO_KIND(kern_mtype->info));
            return -ENOTSUP;
        }

        if (btf_is_ptr(mtype))
        {
            struct bpf_program *prog;

            prog = st_ops->progs[i];
            if (!prog)
                continue;

            kern_mtype = skip_mods_and_typedefs(kern_btf,
                                                kern_mtype->type,
                                                &kern_mtype_id);

            /* mtype->type must be a func_proto which was
             * guaranteed in bpf_object__collect_st_ops_relos(),
             * so only check kern_mtype for func_proto here.
             */
            if (!btf_is_func_proto(kern_mtype))
            {
                pr_warn("struct_ops init_kern %s: kernel member %s is not a func ptr\n",
                        map->name, mname);
                return -ENOTSUP;
            }

            prog->attach_btf_id = kern_type_id;
            prog->expected_attach_type = kern_member_idx;

            st_ops->kern_func_off[i] = kern_data_off + kern_moff;

            pr_debug("struct_ops init_kern %s: func ptr %s is set to prog %s from data(+%u) to kern_data(+%u)\n",
                     map->name, mname, prog->name, moff,
                     kern_moff);

            continue;
        }

        msize = btf__resolve_size(btf, mtype_id);
        kern_msize = btf__resolve_size(kern_btf, kern_mtype_id);
        if (msize < 0 || kern_msize < 0 || msize != kern_msize)
        {
            pr_warn("struct_ops init_kern %s: Error in size of member %s: %zd != %zd(kernel)\n",
                    map->name, mname, (ssize_t)msize,
                    (ssize_t)kern_msize);
            return -ENOTSUP;
        }

        pr_debug("struct_ops init_kern %s: copy %s %u bytes from data(+%u) to kern_data(+%u)\n",
                 map->name, mname, (unsigned int)msize,
                 moff, kern_moff);
        memcpy(kern_mdata, mdata, msize);
    }

    return 0;
}

static int bpf_object__init_kern_struct_ops_maps(struct bpf_object *obj)
{
    struct bpf_map *map;
    size_t i;
    int err;

    for (i = 0; i < obj->nr_maps; i++)
    {
        map = &obj->maps[i];

        if (!bpf_map__is_struct_ops(map))
            continue;

        err = bpf_map__init_kern_struct_ops(map, obj->btf,
                                            obj->btf_vmlinux);
        if (err)
            return err;
    }

    return 0;
}

static int init_struct_ops_maps(struct bpf_object *obj, const char *sec_name,
                                int shndx, Elf_Data *data, __u32 map_flags)
{
    const struct btf_type *type, *datasec;
    const struct btf_var_secinfo *vsi;
    struct bpf_struct_ops *st_ops;
    const char *tname, *var_name;
    __s32 type_id, datasec_id;
    const struct btf *btf;
    struct bpf_map *map;
    __u32 i;

    if (shndx == -1)
        return 0;

    btf = obj->btf;
    datasec_id = btf__find_by_name_kind(btf, sec_name,
                                        BTF_KIND_DATASEC);
    if (datasec_id < 0)
    {
        pr_warn("struct_ops init: DATASEC %s not found\n",
                sec_name);
        return -EINVAL;
    }

    datasec = btf__type_by_id(btf, datasec_id);
    vsi = btf_var_secinfos(datasec);
    for (i = 0; i < btf_vlen(datasec); i++, vsi++)
    {
        type = btf__type_by_id(obj->btf, vsi->type);
        var_name = btf__name_by_offset(obj->btf, type->name_off);

        type_id = btf__resolve_type(obj->btf, vsi->type);
        if (type_id < 0)
        {
            pr_warn("struct_ops init: Cannot resolve var type_id %u in DATASEC %s\n",
                    vsi->type, sec_name);
            return -EINVAL;
        }

        type = btf__type_by_id(obj->btf, type_id);
        tname = btf__name_by_offset(obj->btf, type->name_off);
        if (!tname[0])
        {
            pr_warn("struct_ops init: anonymous type is not supported\n");
            return -ENOTSUP;
        }
        if (!btf_is_struct(type))
        {
            pr_warn("struct_ops init: %s is not a struct\n", tname);
            return -EINVAL;
        }

        map = bpf_object__add_map(obj);
        if (IS_ERR(map))
            return PTR_ERR(map);

        map->sec_idx = shndx;
        map->sec_offset = vsi->offset;
        map->name = strdup(var_name);
        if (!map->name)
            return -ENOMEM;

        map->def.type = BPF_MAP_TYPE_STRUCT_OPS;
        map->def.key_size = sizeof(int);
        map->def.value_size = type->size;
        map->def.max_entries = 1;
        map->def.map_flags = map_flags;

        map->st_ops = calloc(1, sizeof(*map->st_ops));
        if (!map->st_ops)
            return -ENOMEM;
        st_ops = map->st_ops;
        st_ops->data = malloc(type->size);
        st_ops->progs = calloc(btf_vlen(type), sizeof(*st_ops->progs));
        st_ops->kern_func_off = malloc(btf_vlen(type) *
                                       sizeof(*st_ops->kern_func_off));
        if (!st_ops->data || !st_ops->progs || !st_ops->kern_func_off)
            return -ENOMEM;

        if (vsi->offset + type->size > data->d_size)
        {
            pr_warn("struct_ops init: var %s is beyond the end of DATASEC %s\n",
                    var_name, sec_name);
            return -EINVAL;
        }

        memcpy(st_ops->data,
               data->d_buf + vsi->offset,
               type->size);
        st_ops->tname = tname;
        st_ops->type = type;
        st_ops->type_id = type_id;

        pr_debug("struct_ops init: struct %s(type_id=%u) %s found at offset %u\n",
                 tname, type_id, var_name, vsi->offset);
    }

    return 0;
}

static int bpf_object_init_struct_ops(struct bpf_object *obj)
{
    int err;

    err = init_struct_ops_maps(obj, STRUCT_OPS_SEC, obj->efile.st_ops_shndx,
                               obj->efile.st_ops_data, 0);
    err = err ?: init_struct_ops_maps(obj, STRUCT_OPS_LINK_SEC, obj->efile.st_ops_link_shndx, obj->efile.st_ops_link_data, BPF_F_LINK);
    return err;
}

static struct bpf_object *bpf_object__new(const char *path,
                                          const void *obj_buf,
                                          size_t obj_buf_sz,
                                          const char *obj_name)
{
    struct bpf_object *obj;
    char *end;

    obj = calloc(1, sizeof(struct bpf_object) + strlen(path) + 1);
    if (!obj)
    {
        pr_warn("alloc memory failed for %s\n", path);
        return ERR_PTR(-ENOMEM);
    }

    strcpy(obj->path, path);
    if (obj_name)
    {
        libbpf_strlcpy(obj->name, obj_name, sizeof(obj->name));
    }
    else
    {
        /* Using basename() GNU version which doesn't modify arg. */
        libbpf_strlcpy(obj->name, basename((void *)path), sizeof(obj->name));
        end = strchr(obj->name, '.');
        if (end)
            *end = 0;
    }

    obj->efile.fd = -1;
    obj->efile.obj_buf = obj_buf;
    obj->efile.obj_buf_sz = obj_buf_sz;
    obj->efile.btf_maps_shndx = -1;
    obj->efile.st_ops_shndx = -1;
    obj->efile.st_ops_link_shndx = -1;
    obj->kconfig_map_idx = -1;

    obj->kern_version = get_kernel_version();
    obj->loaded = false;

    return obj;
}

static void bpf_object__elf_finish(struct bpf_object *obj)
{
    if (!obj->efile.elf)
        return;

    elf_end(obj->efile.elf);
    obj->efile.elf = NULL;
    obj->efile.symbols = NULL;
    obj->efile.st_ops_data = NULL;
    obj->efile.st_ops_link_data = NULL;

    zfree(&obj->efile.secs);
    obj->efile.sec_cnt = 0;
    zclose(obj->efile.fd);
    obj->efile.obj_buf = NULL;
    obj->efile.obj_buf_sz = 0;
}

static int bpf_object__elf_init(struct bpf_object *obj)
{
    Elf64_Ehdr *ehdr;
    int err = 0;
    Elf *elf;

    if (obj->efile.elf)
    {
        pr_warn("elf: init internal error\n");
        return -LIBBPF_ERRNO__LIBELF;
    }

    if (obj->efile.obj_buf_sz > 0)
    {
        /* obj_buf should have been validated by bpf_object__open_mem(). */
        elf = elf_memory((char *)obj->efile.obj_buf, obj->efile.obj_buf_sz);
    }
    else
    {
        obj->efile.fd = open(obj->path, O_RDONLY | O_CLOEXEC);
        if (obj->efile.fd < 0)
        {
            char errmsg[STRERR_BUFSIZE], *cp;

            err = -errno;
            cp = libbpf_strerror_r(err, errmsg, sizeof(errmsg));
            pr_warn("elf: failed to open %s: %s\n", obj->path, cp);
            return err;
        }

        elf = elf_begin(obj->efile.fd, ELF_C_READ_MMAP, NULL);
    }

    if (!elf)
    {
        pr_warn("elf: failed to open %s as ELF file: %s\n", obj->path, elf_errmsg(-1));
        err = -LIBBPF_ERRNO__LIBELF;
        goto errout;
    }

    obj->efile.elf = elf;

    if (elf_kind(elf) != ELF_K_ELF)
    {
        err = -LIBBPF_ERRNO__FORMAT;
        pr_warn("elf: '%s' is not a proper ELF object\n", obj->path);
        goto errout;
    }

    if (gelf_getclass(elf) != ELFCLASS64)
    {
        err = -LIBBPF_ERRNO__FORMAT;
        pr_warn("elf: '%s' is not a 64-bit ELF object\n", obj->path);
        goto errout;
    }

    obj->efile.ehdr = ehdr = elf64_getehdr(elf);
    if (!obj->efile.ehdr)
    {
        pr_warn("elf: failed to get ELF header from %s: %s\n", obj->path, elf_errmsg(-1));
        err = -LIBBPF_ERRNO__FORMAT;
        goto errout;
    }

    if (elf_getshdrstrndx(elf, &obj->efile.shstrndx))
    {
        pr_warn("elf: failed to get section names section index for %s: %s\n",
                obj->path, elf_errmsg(-1));
        err = -LIBBPF_ERRNO__FORMAT;
        goto errout;
    }

    /* Elf is corrupted/truncated, avoid calling elf_strptr. */
    if (!elf_rawdata(elf_getscn(elf, obj->efile.shstrndx), NULL))
    {
        pr_warn("elf: failed to get section names strings from %s: %s\n",
                obj->path, elf_errmsg(-1));
        err = -LIBBPF_ERRNO__FORMAT;
        goto errout;
    }

    /* Old LLVM set e_machine to EM_NONE */
    if (ehdr->e_type != ET_REL || (ehdr->e_machine && ehdr->e_machine != EM_BPF))
    {
        pr_warn("elf: %s is not a valid eBPF object file\n", obj->path);
        err = -LIBBPF_ERRNO__FORMAT;
        goto errout;
    }

    return 0;
errout:
    bpf_object__elf_finish(obj);
    return err;
}

static int bpf_object__check_endianness(struct bpf_object *obj)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    if (obj->efile.ehdr->e_ident[EI_DATA] == ELFDATA2LSB)
        return 0;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    if (obj->efile.ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
        return 0;
#else
#error "Unrecognized __BYTE_ORDER__"
#endif
    pr_warn("elf: endianness mismatch in %s.\n", obj->path);
    return -LIBBPF_ERRNO__ENDIAN;
}

static int bpf_object__init_license(struct bpf_object *obj, void *data, size_t size)
{
    if (!data)
    {
        pr_warn("invalid license section in %s\n", obj->path);
        return -LIBBPF_ERRNO__FORMAT;
    }
    /* libbpf_strlcpy() only copies first N - 1 bytes, so size + 1 won't
     * go over allowed ELF data section buffer
     */
    libbpf_strlcpy(obj->license, data, min(size + 1, sizeof(obj->license)));
    pr_debug("license of %s is %s\n", obj->path, obj->license);
    return 0;
}

static int bpf_object__init_kversion(struct bpf_object *obj, void *data, size_t size)
{
    __u32 kver;

    if (!data || size != sizeof(kver))
    {
        pr_warn("invalid kver section in %s\n", obj->path);
        return -LIBBPF_ERRNO__FORMAT;
    }
    memcpy(&kver, data, sizeof(kver));
    obj->kern_version = kver;
    pr_debug("kernel version of %s is %x\n", obj->path, obj->kern_version);
    return 0;
}

static bool bpf_map_type__is_map_in_map(enum bpf_map_type type)
{
    if (type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
        type == BPF_MAP_TYPE_HASH_OF_MAPS)
        return true;
    return false;
}

static int find_elf_sec_sz(const struct bpf_object *obj, const char *name, __u32 *size)
{
    Elf_Data *data;
    Elf_Scn *scn;

    if (!name)
        return -EINVAL;

    scn = elf_sec_by_name(obj, name);
    data = elf_sec_data(obj, scn);
    if (data)
    {
        *size = data->d_size;
        return 0; /* found it */
    }

    return -ENOENT;
}

static Elf64_Sym *find_elf_var_sym(const struct bpf_object *obj, const char *name)
{
    Elf_Data *symbols = obj->efile.symbols;
    const char *sname;
    size_t si;

    for (si = 0; si < symbols->d_size / sizeof(Elf64_Sym); si++)
    {
        Elf64_Sym *sym = elf_sym_by_idx(obj, si);

        if (ELF64_ST_TYPE(sym->st_info) != STT_OBJECT)
            continue;

        if (ELF64_ST_BIND(sym->st_info) != STB_GLOBAL &&
            ELF64_ST_BIND(sym->st_info) != STB_WEAK)
            continue;

        sname = elf_sym_str(obj, sym->st_name);
        if (!sname)
        {
            pr_warn("failed to get sym name string for var %s\n", name);
            return ERR_PTR(-EIO);
        }
        if (strcmp(name, sname) == 0)
            return sym;
    }

    return ERR_PTR(-ENOENT);
}

static struct bpf_map *bpf_object__add_map(struct bpf_object *obj)
{
    struct bpf_map *map;
    int err;

    err = libbpf_ensure_mem((void **)&obj->maps, &obj->maps_cap,
                            sizeof(*obj->maps), obj->nr_maps + 1);
    if (err)
        return ERR_PTR(err);

    map = &obj->maps[obj->nr_maps++];
    map->obj = obj;
    map->fd = -1;
    map->inner_map_fd = -1;
    map->autocreate = true;

    return map;
}

static size_t bpf_map_mmap_sz(const struct bpf_map *map)
{
    long page_sz = sysconf(_SC_PAGE_SIZE);
    size_t map_sz;

    map_sz = (size_t)roundup(map->def.value_size, 8) * map->def.max_entries;
    map_sz = roundup(map_sz, page_sz);
    return map_sz;
}

static char *internal_map_name(struct bpf_object *obj, const char *real_name)
{
    char map_name[BPF_OBJ_NAME_LEN], *p;
    int pfx_len, sfx_len = max((size_t)7, strlen(real_name));
    if (sfx_len >= BPF_OBJ_NAME_LEN)
        sfx_len = BPF_OBJ_NAME_LEN - 1;

    /* if there are two or more dots in map name, it's a custom dot map */
    if (strchr(real_name + 1, '.') != NULL)
        pfx_len = 0;
    else
        pfx_len = min((size_t)BPF_OBJ_NAME_LEN - sfx_len - 1, strlen(obj->name));

    snprintf(map_name, sizeof(map_name), "%.*s%.*s", pfx_len, obj->name,
             sfx_len, real_name);

    /* sanitise map name to characters allowed by kernel */
    for (p = map_name; *p && p < map_name + sizeof(map_name); p++)
        if (!isalnum(*p) && *p != '_' && *p != '.')
            *p = '_';

    return strdup(map_name);
}

static int map_fill_btf_type_info(struct bpf_object *obj, struct bpf_map *map);

static bool map_is_mmapable(struct bpf_object *obj, struct bpf_map *map)
{
    const struct btf_type *t, *vt;
    struct btf_var_secinfo *vsi;
    int i, n;

    if (!map->btf_value_type_id)
        return false;

    t = btf__type_by_id(obj->btf, map->btf_value_type_id);
    if (!btf_is_datasec(t))
        return false;

    vsi = btf_var_secinfos(t);
    for (i = 0, n = btf_vlen(t); i < n; i++, vsi++)
    {
        vt = btf__type_by_id(obj->btf, vsi->type);
        if (!btf_is_var(vt))
            continue;

        if (btf_var(vt)->linkage != BTF_VAR_STATIC)
            return true;
    }

    return false;
}

static int
bpf_object__init_internal_map(struct bpf_object *obj, enum libbpf_map_type type,
                              const char *real_name, int sec_idx, void *data, size_t data_sz)
{
    struct bpf_map_def *def;
    struct bpf_map *map;
    int err;

    map = bpf_object__add_map(obj);
    if (IS_ERR(map))
        return PTR_ERR(map);

    map->libbpf_type = type;
    map->sec_idx = sec_idx;
    map->sec_offset = 0;
    map->real_name = strdup(real_name);
    map->name = internal_map_name(obj, real_name);
    if (!map->real_name || !map->name)
    {
        zfree(&map->real_name);
        zfree(&map->name);
        return -ENOMEM;
    }

    def = &map->def;
    def->type = BPF_MAP_TYPE_ARRAY;
    def->key_size = sizeof(int);
    def->value_size = data_sz;
    def->max_entries = 1;
    def->map_flags = type == LIBBPF_MAP_RODATA || type == LIBBPF_MAP_KCONFIG
                         ? BPF_F_RDONLY_PROG
                         : 0;

    /* failures are fine because of maps like .rodata.str1.1 */
    (void)map_fill_btf_type_info(obj, map);

    if (map_is_mmapable(obj, map))
        def->map_flags |= BPF_F_MMAPABLE;

    pr_debug("map '%s' (global data): at sec_idx %d, offset %zu, flags %x.\n",
             map->name, map->sec_idx, map->sec_offset, def->map_flags);

    map->mmaped = mmap(NULL, bpf_map_mmap_sz(map), PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (map->mmaped == MAP_FAILED)
    {
        err = -errno;
        map->mmaped = NULL;
        pr_warn("failed to alloc map '%s' content buffer: %d\n",
                map->name, err);
        zfree(&map->real_name);
        zfree(&map->name);
        return err;
    }

    if (data)
        memcpy(map->mmaped, data, data_sz);

    pr_debug("map %td is \"%s\"\n", map - obj->maps, map->name);
    return 0;
}

static int bpf_object__init_global_data_maps(struct bpf_object *obj)
{
    struct elf_sec_desc *sec_desc;
    const char *sec_name;
    int err = 0, sec_idx;

    /*
     * Populate obj->maps with libbpf internal maps.
     */
    for (sec_idx = 1; sec_idx < obj->efile.sec_cnt; sec_idx++)
    {
        sec_desc = &obj->efile.secs[sec_idx];

        /* Skip recognized sections with size 0. */
        if (!sec_desc->data || sec_desc->data->d_size == 0)
            continue;

        switch (sec_desc->sec_type)
        {
        case SEC_DATA:
            sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, sec_idx));
            err = bpf_object__init_internal_map(obj, LIBBPF_MAP_DATA,
                                                sec_name, sec_idx,
                                                sec_desc->data->d_buf,
                                                sec_desc->data->d_size);
            break;
        case SEC_RODATA:
            obj->has_rodata = true;
            sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, sec_idx));
            err = bpf_object__init_internal_map(obj, LIBBPF_MAP_RODATA,
                                                sec_name, sec_idx,
                                                sec_desc->data->d_buf,
                                                sec_desc->data->d_size);
            break;
        case SEC_BSS:
            sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, sec_idx));
            err = bpf_object__init_internal_map(obj, LIBBPF_MAP_BSS,
                                                sec_name, sec_idx,
                                                NULL,
                                                sec_desc->data->d_size);
            break;
        default:
            /* skip */
            break;
        }
        if (err)
            return err;
    }
    return 0;
}

static struct extern_desc *find_extern_by_name(const struct bpf_object *obj,
                                               const void *name)
{
    int i;

    for (i = 0; i < obj->nr_extern; i++)
    {
        if (strcmp(obj->externs[i].name, name) == 0)
            return &obj->externs[i];
    }
    return NULL;
}

static int set_kcfg_value_tri(struct extern_desc *ext, void *ext_val,
                              char value)
{
    switch (ext->kcfg.type)
    {
    case KCFG_BOOL:
        if (value == 'm')
        {
            pr_warn("extern (kcfg) '%s': value '%c' implies tristate or char type\n",
                    ext->name, value);
            return -EINVAL;
        }
        *(bool *)ext_val = value == 'y' ? true : false;
        break;
    case KCFG_TRISTATE:
        if (value == 'y')
            *(enum libbpf_tristate *)ext_val = TRI_YES;
        else if (value == 'm')
            *(enum libbpf_tristate *)ext_val = TRI_MODULE;
        else /* value == 'n' */
            *(enum libbpf_tristate *)ext_val = TRI_NO;
        break;
    case KCFG_CHAR:
        *(char *)ext_val = value;
        break;
    case KCFG_UNKNOWN:
    case KCFG_INT:
    case KCFG_CHAR_ARR:
    default:
        pr_warn("extern (kcfg) '%s': value '%c' implies bool, tristate, or char type\n",
                ext->name, value);
        return -EINVAL;
    }
    ext->is_set = true;
    return 0;
}

static int set_kcfg_value_str(struct extern_desc *ext, char *ext_val,
                              const char *value)
{
    size_t len;

    if (ext->kcfg.type != KCFG_CHAR_ARR)
    {
        pr_warn("extern (kcfg) '%s': value '%s' implies char array type\n",
                ext->name, value);
        return -EINVAL;
    }

    len = strlen(value);
    if (value[len - 1] != '"')
    {
        pr_warn("extern (kcfg) '%s': invalid string config '%s'\n",
                ext->name, value);
        return -EINVAL;
    }

    /* strip quotes */
    len -= 2;
    if (len >= ext->kcfg.sz)
    {
        pr_warn("extern (kcfg) '%s': long string '%s' of (%zu bytes) truncated to %d bytes\n",
                ext->name, value, len, ext->kcfg.sz - 1);
        len = ext->kcfg.sz - 1;
    }
    memcpy(ext_val, value + 1, len);
    ext_val[len] = '\0';
    ext->is_set = true;
    return 0;
}

static int parse_u64(const char *value, __u64 *res)
{
    char *value_end;
    int err;

    errno = 0;
    *res = strtoull(value, &value_end, 0);
    if (errno)
    {
        err = -errno;
        pr_warn("failed to parse '%s' as integer: %d\n", value, err);
        return err;
    }
    if (*value_end)
    {
        pr_warn("failed to parse '%s' as integer completely\n", value);
        return -EINVAL;
    }
    return 0;
}