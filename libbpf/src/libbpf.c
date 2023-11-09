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

static bool is_kcfg_value_in_range(const struct extern_desc *ext, __u64 v)
{
    int bit_sz = ext->kcfg.sz * 8;

    if (ext->kcfg.sz == 8)
        return true;

    if (ext->kcfg.is_signed)
        return v + (1ULL << (bit_sz - 1)) < (1ULL << bit_sz);
    else
        return (v >> bit_sz) == 0;
}

static int set_kcfg_value_num(struct extern_desc *ext, void *ext_val,
                              __u64 value)
{
    if (ext->kcfg.type != KCFG_INT && ext->kcfg.type != KCFG_CHAR &&
        ext->kcfg.type != KCFG_BOOL)
    {
        pr_warn("extern (kcfg) '%s': value '%llu' implies integer, char, or boolean type\n",
                ext->name, (unsigned long long)value);
        return -EINVAL;
    }
    if (ext->kcfg.type == KCFG_BOOL && value > 1)
    {
        pr_warn("extern (kcfg) '%s': value '%llu' isn't boolean compatible\n",
                ext->name, (unsigned long long)value);
        return -EINVAL;
    }
    if (!is_kcfg_value_in_range(ext, value))
    {
        pr_warn("extern (kcfg) '%s': value '%llu' doesn't fit in %d bytes\n",
                ext->name, (unsigned long long)value, ext->kcfg.sz);
        return -ERANGE;
    }
    switch (ext->kcfg.sz)
    {
    case 1:
        *(__u8 *)ext_val = value;
        break;
    case 2:
        *(__u16 *)ext_val = value;
        break;
    case 4:
        *(__u32 *)ext_val = value;
        break;
    case 8:
        *(__u64 *)ext_val = value;
        break;
    default:
        return -EINVAL;
    }
    ext->is_set = true;
    return 0;
}

static int bpf_object__process_kconfig_line(struct bpf_object *obj,
                                            char *buf, void *data)
{
    struct extern_desc *ext;
    char *sep, *value;
    int len, err = 0;
    void *ext_val;
    __u64 num;

    if (!str_has_pfx(buf, "CONFIG_"))
        return 0;

    sep = strchr(buf, '=');
    if (!sep)
    {
        pr_warn("failed to parse '%s': no separator\n", buf);
        return -EINVAL;
    }

    /* Trim ending '\n' */
    len = strlen(buf);
    if (buf[len - 1] == '\n')
        buf[len - 1] = '\0';
    /* Split on '=' and ensure that a value is present. */
    *sep = '\0';
    if (!sep[1])
    {
        *sep = '=';
        pr_warn("failed to parse '%s': no value\n", buf);
        return -EINVAL;
    }

    ext = find_extern_by_name(obj, buf);
    if (!ext || ext->is_set)
        return 0;

    ext_val = data + ext->kcfg.data_off;
    value = sep + 1;

    switch (*value)
    {
    case 'y':
    case 'n':
    case 'm':
        err = set_kcfg_value_tri(ext, ext_val, *value);
        break;
    case '"':
        err = set_kcfg_value_str(ext, ext_val, value);
        break;
    default:
        /* assume integer */
        err = parse_u64(value, &num);
        if (err)
        {
            pr_warn("extern (kcfg) '%s': value '%s' isn't a valid integer\n", ext->name, value);
            return err;
        }
        if (ext->kcfg.type != KCFG_INT && ext->kcfg.type != KCFG_CHAR)
        {
            pr_warn("extern (kcfg) '%s': value '%s' implies integer type\n", ext->name, value);
            return -EINVAL;
        }
        err = set_kcfg_value_num(ext, ext_val, num);
        break;
    }
    if (err)
        return err;
    pr_debug("extern (kcfg) '%s': set to %s\n", ext->name, value);
    return 0;
}

static int bpf_object__read_kconfig_file(struct bpf_object *obj, void *data)
{
    char buf[PATH_MAX];
    struct utsname uts;
    int len, err = 0;
    gzFile file;

    uname(&uts);
    len = snprintf(buf, PATH_MAX, "/boot/config-%s", uts.release);
    if (len < 0)
        return -EINVAL;
    else if (len >= PATH_MAX)
        return -ENAMETOOLONG;

    /* gzopen also accepts uncompressed files. */
    file = gzopen(buf, "r");
    if (!file)
        file = gzopen("/proc/config.gz", "r");

    if (!file)
    {
        pr_warn("failed to open system Kconfig\n");
        return -ENOENT;
    }

    while (gzgets(file, buf, sizeof(buf)))
    {
        err = bpf_object__process_kconfig_line(obj, buf, data);
        if (err)
        {
            pr_warn("error parsing system Kconfig line '%s': %d\n",
                    buf, err);
            goto out;
        }
    }

out:
    gzclose(file);
    return err;
}

static int bpf_object__read_kconfig_mem(struct bpf_object *obj,
                                        const char *config, void *data)
{
    char buf[PATH_MAX];
    int err = 0;
    FILE *file;

    file = fmemopen((void *)config, strlen(config), "r");
    if (!file)
    {
        err = -errno;
        pr_warn("failed to open in-memory Kconfig: %d\n", err);
        return err;
    }

    while (fgets(buf, sizeof(buf), file))
    {
        err = bpf_object__process_kconfig_line(obj, buf, data);
        if (err)
        {
            pr_warn("error parsing in-memory Kconfig line '%s': %d\n",
                    buf, err);
            break;
        }
    }

    fclose(file);
    return err;
}

static int bpf_object__init_kconfig_map(struct bpf_object *obj)
{
    struct extern_desc *last_ext = NULL, *ext;
    size_t map_sz;
    int i, err;

    for (i = 0; i < obj->nr_extern; i++)
    {
        ext = &obj->externs[i];
        if (ext->type == EXT_KCFG)
            last_ext = ext;
    }

    if (!last_ext)
        return 0;

    map_sz = last_ext->kcfg.data_off + last_ext->kcfg.sz;
    err = bpf_object__init_internal_map(obj, LIBBPF_MAP_KCONFIG,
                                        ".kconfig", obj->efile.symbols_shndx,
                                        NULL, map_sz);
    if (err)
        return err;

    obj->kconfig_map_idx = obj->nr_maps - 1;

    return 0;
}

const struct btf_type *
skip_mods_and_typedefs(const struct btf *btf, __u32 id, __u32 *res_id)
{
    const struct btf_type *t = btf__type_by_id(btf, id);

    if (res_id)
        *res_id = id;

    while (btf_is_mod(t) || btf_is_typedef(t))
    {
        if (res_id)
            *res_id = t->type;
        t = btf__type_by_id(btf, t->type);
    }

    return t;
}

static const struct btf_type *
resolve_func_ptr(const struct btf *btf, __u32 id, __u32 *res_id)
{
    const struct btf_type *t;

    t = skip_mods_and_typedefs(btf, id, NULL);
    if (!btf_is_ptr(t))
        return NULL;

    t = skip_mods_and_typedefs(btf, t->type, res_id);

    return btf_is_func_proto(t) ? t : NULL;
}

static const char *__btf_kind_str(__u16 kind)
{
    switch (kind)
    {
    case BTF_KIND_UNKN:
        return "void";
    case BTF_KIND_INT:
        return "int";
    case BTF_KIND_PTR:
        return "ptr";
    case BTF_KIND_ARRAY:
        return "array";
    case BTF_KIND_STRUCT:
        return "struct";
    case BTF_KIND_UNION:
        return "union";
    case BTF_KIND_ENUM:
        return "enum";
    case BTF_KIND_FWD:
        return "fwd";
    case BTF_KIND_TYPEDEF:
        return "typedef";
    case BTF_KIND_VOLATILE:
        return "volatile";
    case BTF_KIND_CONST:
        return "const";
    case BTF_KIND_RESTRICT:
        return "restrict";
    case BTF_KIND_FUNC:
        return "func";
    case BTF_KIND_FUNC_PROTO:
        return "func_proto";
    case BTF_KIND_VAR:
        return "var";
    case BTF_KIND_DATASEC:
        return "datasec";
    case BTF_KIND_FLOAT:
        return "float";
    case BTF_KIND_DECL_TAG:
        return "decl_tag";
    case BTF_KIND_TYPE_TAG:
        return "type_tag";
    case BTF_KIND_ENUM64:
        return "enum64";
    default:
        return "unknown";
    }
}

const char *btf_kind_str(const struct btf_type *t)
{
    return __btf_kind_str(btf_kind(t));
}

static bool get_map_field_int(const char *map_name, const struct btf *btf,
                              const struct btf_member *m, __u32 *res)
{
    const struct btf_type *t = skip_mods_and_typedefs(btf, m->type, NULL);
    const char *name = btf__name_by_offset(btf, m->name_off);
    const struct btf_array *arr_info;
    const struct btf_type *arr_t;

    if (!btf_is_ptr(t))
    {
        pr_warn("map '%s': attr '%s': expected PTR, got %s.\n",
                map_name, name, btf_kind_str(t));
        return false;
    }

    arr_t = btf__type_by_id(btf, t->type);
    if (!arr_t)
    {
        pr_warn("map '%s': attr '%s': type [%u] not found.\n",
                map_name, name, t->type);
        return false;
    }
    if (!btf_is_array(arr_t))
    {
        pr_warn("map '%s': attr '%s': expected ARRAY, got %s.\n",
                map_name, name, btf_kind_str(arr_t));
        return false;
    }
    arr_info = btf_array(arr_t);
    *res = arr_info->nelems;
    return true;
}

static int pathname_concat(char *buf, size_t buf_sz, const char *path, const char *name)
{
    int len;

    len = snprintf(buf, buf_sz, "%s/%s", path, name);
    if (len < 0)
        return -EINVAL;
    if (len >= buf_sz)
        return -ENAMETOOLONG;

    return 0;
}

static int build_map_pin_path(struct bpf_map *map, const char *path)
{
    char buf[PATH_MAX];
    int err;

    if (!path)
        path = "/sys/fs/bpf";

    err = pathname_concat(buf, sizeof(buf), path, bpf_map__name(map));
    if (err)
        return err;

    return bpf_map__set_pin_path(map, buf);
}

enum libbpf_pin_type
{
    LIBBPF_PIN_NONE,
    /* PIN_BY_NAME: pin maps by name (in /sys/fs/bpf by default) */
    LIBBPF_PIN_BY_NAME,
};

int parse_btf_map_def(const char *map_name, struct btf *btf,
                      const struct btf_type *def_t, bool strict,
                      struct btf_map_def *map_def, struct btf_map_def *inner_def)
{
    const struct btf_type *t;
    const struct btf_member *m;
    bool is_inner = inner_def == NULL;
    int vlen, i;

    vlen = btf_vlen(def_t);
    m = btf_members(def_t);
    for (i = 0; i < vlen; i++, m++)
    {
        const char *name = btf__name_by_offset(btf, m->name_off);

        if (!name)
        {
            pr_warn("map '%s': invalid field #%d.\n", map_name, i);
            return -EINVAL;
        }
        if (strcmp(name, "type") == 0)
        {
            if (!get_map_field_int(map_name, btf, m, &map_def->map_type))
                return -EINVAL;
            map_def->parts |= MAP_DEF_MAP_TYPE;
        }
        else if (strcmp(name, "max_entries") == 0)
        {
            if (!get_map_field_int(map_name, btf, m, &map_def->max_entries))
                return -EINVAL;
            map_def->parts |= MAP_DEF_MAX_ENTRIES;
        }
        else if (strcmp(name, "map_flags") == 0)
        {
            if (!get_map_field_int(map_name, btf, m, &map_def->map_flags))
                return -EINVAL;
            map_def->parts |= MAP_DEF_MAP_FLAGS;
        }
        else if (strcmp(name, "numa_node") == 0)
        {
            if (!get_map_field_int(map_name, btf, m, &map_def->numa_node))
                return -EINVAL;
            map_def->parts |= MAP_DEF_NUMA_NODE;
        }
        else if (strcmp(name, "key_size") == 0)
        {
            __u32 sz;

            if (!get_map_field_int(map_name, btf, m, &sz))
                return -EINVAL;
            if (map_def->key_size && map_def->key_size != sz)
            {
                pr_warn("map '%s': conflicting key size %u != %u.\n",
                        map_name, map_def->key_size, sz);
                return -EINVAL;
            }
            map_def->key_size = sz;
            map_def->parts |= MAP_DEF_KEY_SIZE;
        }
        else if (strcmp(name, "key") == 0)
        {
            __s64 sz;

            t = btf__type_by_id(btf, m->type);
            if (!t)
            {
                pr_warn("map '%s': key type [%d] not found.\n",
                        map_name, m->type);
                return -EINVAL;
            }
            if (!btf_is_ptr(t))
            {
                pr_warn("map '%s': key spec is not PTR: %s.\n",
                        map_name, btf_kind_str(t));
                return -EINVAL;
            }
            sz = btf__resolve_size(btf, t->type);
            if (sz < 0)
            {
                pr_warn("map '%s': can't determine key size for type [%u]: %zd.\n",
                        map_name, t->type, (ssize_t)sz);
                return sz;
            }
            if (map_def->key_size && map_def->key_size != sz)
            {
                pr_warn("map '%s': conflicting key size %u != %zd.\n",
                        map_name, map_def->key_size, (ssize_t)sz);
                return -EINVAL;
            }
            map_def->key_size = sz;
            map_def->key_type_id = t->type;
            map_def->parts |= MAP_DEF_KEY_SIZE | MAP_DEF_KEY_TYPE;
        }
        else if (strcmp(name, "value_size") == 0)
        {
            __u32 sz;

            if (!get_map_field_int(map_name, btf, m, &sz))
                return -EINVAL;
            if (map_def->value_size && map_def->value_size != sz)
            {
                pr_warn("map '%s': conflicting value size %u != %u.\n",
                        map_name, map_def->value_size, sz);
                return -EINVAL;
            }
            map_def->value_size = sz;
            map_def->parts |= MAP_DEF_VALUE_SIZE;
        }
        else if (strcmp(name, "value") == 0)
        {
            __s64 sz;

            t = btf__type_by_id(btf, m->type);
            if (!t)
            {
                pr_warn("map '%s': value type [%d] not found.\n",
                        map_name, m->type);
                return -EINVAL;
            }
            if (!btf_is_ptr(t))
            {
                pr_warn("map '%s': value spec is not PTR: %s.\n",
                        map_name, btf_kind_str(t));
                return -EINVAL;
            }
            sz = btf__resolve_size(btf, t->type);
            if (sz < 0)
            {
                pr_warn("map '%s': can't determine value size for type [%u]: %zd.\n",
                        map_name, t->type, (ssize_t)sz);
                return sz;
            }
            if (map_def->value_size && map_def->value_size != sz)
            {
                pr_warn("map '%s': conflicting value size %u != %zd.\n",
                        map_name, map_def->value_size, (ssize_t)sz);
                return -EINVAL;
            }
            map_def->value_size = sz;
            map_def->value_type_id = t->type;
            map_def->parts |= MAP_DEF_VALUE_SIZE | MAP_DEF_VALUE_TYPE;
        }
        else if (strcmp(name, "values") == 0)
        {
            bool is_map_in_map = bpf_map_type__is_map_in_map(map_def->map_type);
            bool is_prog_array = map_def->map_type == BPF_MAP_TYPE_PROG_ARRAY;
            const char *desc = is_map_in_map ? "map-in-map inner" : "prog-array value";
            char inner_map_name[128];
            int err;

            if (is_inner)
            {
                pr_warn("map '%s': multi-level inner maps not supported.\n",
                        map_name);
                return -ENOTSUP;
            }
            if (i != vlen - 1)
            {
                pr_warn("map '%s': '%s' member should be last.\n",
                        map_name, name);
                return -EINVAL;
            }
            if (!is_map_in_map && !is_prog_array)
            {
                pr_warn("map '%s': should be map-in-map or prog-array.\n",
                        map_name);
                return -ENOTSUP;
            }
            if (map_def->value_size && map_def->value_size != 4)
            {
                pr_warn("map '%s': conflicting value size %u != 4.\n",
                        map_name, map_def->value_size);
                return -EINVAL;
            }
            map_def->value_size = 4;
            t = btf__type_by_id(btf, m->type);
            if (!t)
            {
                pr_warn("map '%s': %s type [%d] not found.\n",
                        map_name, desc, m->type);
                return -EINVAL;
            }
            if (!btf_is_array(t) || btf_array(t)->nelems)
            {
                pr_warn("map '%s': %s spec is not a zero-sized array.\n",
                        map_name, desc);
                return -EINVAL;
            }
            t = skip_mods_and_typedefs(btf, btf_array(t)->type, NULL);
            if (!btf_is_ptr(t))
            {
                pr_warn("map '%s': %s def is of unexpected kind %s.\n",
                        map_name, desc, btf_kind_str(t));
                return -EINVAL;
            }
            t = skip_mods_and_typedefs(btf, t->type, NULL);
            if (is_prog_array)
            {
                if (!btf_is_func_proto(t))
                {
                    pr_warn("map '%s': prog-array value def is of unexpected kind %s.\n",
                            map_name, btf_kind_str(t));
                    return -EINVAL;
                }
                continue;
            }
            if (!btf_is_struct(t))
            {
                pr_warn("map '%s': map-in-map inner def is of unexpected kind %s.\n",
                        map_name, btf_kind_str(t));
                return -EINVAL;
            }

            snprintf(inner_map_name, sizeof(inner_map_name), "%s.inner", map_name);
            err = parse_btf_map_def(inner_map_name, btf, t, strict, inner_def, NULL);
            if (err)
                return err;

            map_def->parts |= MAP_DEF_INNER_MAP;
        }
        else if (strcmp(name, "pinning") == 0)
        {
            __u32 val;

            if (is_inner)
            {
                pr_warn("map '%s': inner def can't be pinned.\n", map_name);
                return -EINVAL;
            }
            if (!get_map_field_int(map_name, btf, m, &val))
                return -EINVAL;
            if (val != LIBBPF_PIN_NONE && val != LIBBPF_PIN_BY_NAME)
            {
                pr_warn("map '%s': invalid pinning value %u.\n",
                        map_name, val);
                return -EINVAL;
            }
            map_def->pinning = val;
            map_def->parts |= MAP_DEF_PINNING;
        }
        else if (strcmp(name, "map_extra") == 0)
        {
            __u32 map_extra;

            if (!get_map_field_int(map_name, btf, m, &map_extra))
                return -EINVAL;
            map_def->map_extra = map_extra;
            map_def->parts |= MAP_DEF_MAP_EXTRA;
        }
        else
        {
            if (strict)
            {
                pr_warn("map '%s': unknown field '%s'.\n", map_name, name);
                return -ENOTSUP;
            }
            pr_debug("map '%s': ignoring unknown field '%s'.\n", map_name, name);
        }
    }

    if (map_def->map_type == BPF_MAP_TYPE_UNSPEC)
    {
        pr_warn("map '%s': map type isn't specified.\n", map_name);
        return -EINVAL;
    }

    return 0;
}

static size_t adjust_ringbuf_sz(size_t sz)
{
    __u32 page_sz = sysconf(_SC_PAGE_SIZE);
    __u32 mul;

    /* if user forgot to set any size, make sure they see error */
    if (sz == 0)
        return 0;
    /* Kernel expects BPF_MAP_TYPE_RINGBUF's max_entries to be
     * a power-of-2 multiple of kernel's page size. If user diligently
     * satisified these conditions, pass the size through.
     */
    if ((sz % page_sz) == 0 && is_pow_of_2(sz / page_sz))
        return sz;

    /* Otherwise find closest (page_sz * power_of_2) product bigger than
     * user-set size to satisfy both user size request and kernel
     * requirements and substitute correct max_entries for map creation.
     */
    for (mul = 1; mul <= UINT_MAX / page_sz; mul <<= 1)
    {
        if (mul * page_sz > sz)
            return mul * page_sz;
    }

    /* if it's impossible to satisfy the conditions (i.e., user size is
     * very close to UINT_MAX but is not a power-of-2 multiple of
     * page_size) then just return original size and let kernel reject it
     */
    return sz;
}

static bool map_is_ringbuf(const struct bpf_map *map)
{
    return map->def.type == BPF_MAP_TYPE_RINGBUF ||
           map->def.type == BPF_MAP_TYPE_USER_RINGBUF;
}

static void fill_map_from_def(struct bpf_map *map, const struct btf_map_def *def)
{
    map->def.type = def->map_type;
    map->def.key_size = def->key_size;
    map->def.value_size = def->value_size;
    map->def.max_entries = def->max_entries;
    map->def.map_flags = def->map_flags;
    map->map_extra = def->map_extra;

    map->numa_node = def->numa_node;
    map->btf_key_type_id = def->key_type_id;
    map->btf_value_type_id = def->value_type_id;

    /* auto-adjust BPF ringbuf map max_entries to be a multiple of page size */
    if (map_is_ringbuf(map))
        map->def.max_entries = adjust_ringbuf_sz(map->def.max_entries);

    if (def->parts & MAP_DEF_MAP_TYPE)
        pr_debug("map '%s': found type = %u.\n", map->name, def->map_type);

    if (def->parts & MAP_DEF_KEY_TYPE)
        pr_debug("map '%s': found key [%u], sz = %u.\n",
                 map->name, def->key_type_id, def->key_size);
    else if (def->parts & MAP_DEF_KEY_SIZE)
        pr_debug("map '%s': found key_size = %u.\n", map->name, def->key_size);

    if (def->parts & MAP_DEF_VALUE_TYPE)
        pr_debug("map '%s': found value [%u], sz = %u.\n",
                 map->name, def->value_type_id, def->value_size);
    else if (def->parts & MAP_DEF_VALUE_SIZE)
        pr_debug("map '%s': found value_size = %u.\n", map->name, def->value_size);

    if (def->parts & MAP_DEF_MAX_ENTRIES)
        pr_debug("map '%s': found max_entries = %u.\n", map->name, def->max_entries);
    if (def->parts & MAP_DEF_MAP_FLAGS)
        pr_debug("map '%s': found map_flags = 0x%x.\n", map->name, def->map_flags);
    if (def->parts & MAP_DEF_MAP_EXTRA)
        pr_debug("map '%s': found map_extra = 0x%llx.\n", map->name,
                 (unsigned long long)def->map_extra);
    if (def->parts & MAP_DEF_PINNING)
        pr_debug("map '%s': found pinning = %u.\n", map->name, def->pinning);
    if (def->parts & MAP_DEF_NUMA_NODE)
        pr_debug("map '%s': found numa_node = %u.\n", map->name, def->numa_node);

    if (def->parts & MAP_DEF_INNER_MAP)
        pr_debug("map '%s': found inner map definition.\n", map->name);
}

static const char *btf_var_linkage_str(__u32 linkage)
{
    switch (linkage)
    {
    case BTF_VAR_STATIC:
        return "static";
    case BTF_VAR_GLOBAL_ALLOCATED:
        return "global";
    case BTF_VAR_GLOBAL_EXTERN:
        return "extern";
    default:
        return "unknown";
    }
}

static int bpf_object__init_user_btf_map(struct bpf_object *obj,
                                         const struct btf_type *sec,
                                         int var_idx, int sec_idx,
                                         const Elf_Data *data, bool strict,
                                         const char *pin_root_path)
{
    struct btf_map_def map_def = {}, inner_def = {};
    const struct btf_type *var, *def;
    const struct btf_var_secinfo *vi;
    const struct btf_var *var_extra;
    const char *map_name;
    struct bpf_map *map;
    int err;

    vi = btf_var_secinfos(sec) + var_idx;
    var = btf__type_by_id(obj->btf, vi->type);
    var_extra = btf_var(var);
    map_name = btf__name_by_offset(obj->btf, var->name_off);

    if (map_name == NULL || map_name[0] == '\0')
    {
        pr_warn("map #%d: empty name.\n", var_idx);
        return -EINVAL;
    }
    if ((__u64)vi->offset + vi->size > data->d_size)
    {
        pr_warn("map '%s' BTF data is corrupted.\n", map_name);
        return -EINVAL;
    }
    if (!btf_is_var(var))
    {
        pr_warn("map '%s': unexpected var kind %s.\n",
                map_name, btf_kind_str(var));
        return -EINVAL;
    }
    if (var_extra->linkage != BTF_VAR_GLOBAL_ALLOCATED)
    {
        pr_warn("map '%s': unsupported map linkage %s.\n",
                map_name, btf_var_linkage_str(var_extra->linkage));
        return -EOPNOTSUPP;
    }

    def = skip_mods_and_typedefs(obj->btf, var->type, NULL);
    if (!btf_is_struct(def))
    {
        pr_warn("map '%s': unexpected def kind %s.\n",
                map_name, btf_kind_str(var));
        return -EINVAL;
    }
    if (def->size > vi->size)
    {
        pr_warn("map '%s': invalid def size.\n", map_name);
        return -EINVAL;
    }

    map = bpf_object__add_map(obj);
    if (IS_ERR(map))
        return PTR_ERR(map);
    map->name = strdup(map_name);
    if (!map->name)
    {
        pr_warn("map '%s': failed to alloc map name.\n", map_name);
        return -ENOMEM;
    }
    map->libbpf_type = LIBBPF_MAP_UNSPEC;
    map->def.type = BPF_MAP_TYPE_UNSPEC;
    map->sec_idx = sec_idx;
    map->sec_offset = vi->offset;
    map->btf_var_idx = var_idx;
    pr_debug("map '%s': at sec_idx %d, offset %zu.\n",
             map_name, map->sec_idx, map->sec_offset);

    err = parse_btf_map_def(map->name, obj->btf, def, strict, &map_def, &inner_def);
    if (err)
        return err;

    fill_map_from_def(map, &map_def);

    if (map_def.pinning == LIBBPF_PIN_BY_NAME)
    {
        err = build_map_pin_path(map, pin_root_path);
        if (err)
        {
            pr_warn("map '%s': couldn't build pin path.\n", map->name);
            return err;
        }
    }

    if (map_def.parts & MAP_DEF_INNER_MAP)
    {
        map->inner_map = calloc(1, sizeof(*map->inner_map));
        if (!map->inner_map)
            return -ENOMEM;
        map->inner_map->fd = -1;
        map->inner_map->sec_idx = sec_idx;
        map->inner_map->name = malloc(strlen(map_name) + sizeof(".inner") + 1);
        if (!map->inner_map->name)
            return -ENOMEM;
        sprintf(map->inner_map->name, "%s.inner", map_name);

        fill_map_from_def(map->inner_map, &inner_def);
    }

    err = map_fill_btf_type_info(obj, map);
    if (err)
        return err;

    return 0;
}

static int bpf_object__init_user_btf_maps(struct bpf_object *obj, bool strict,
                                          const char *pin_root_path)
{
    const struct btf_type *sec = NULL;
    int nr_types, i, vlen, err;
    const struct btf_type *t;
    const char *name;
    Elf_Data *data;
    Elf_Scn *scn;

    if (obj->efile.btf_maps_shndx < 0)
        return 0;

    scn = elf_sec_by_idx(obj, obj->efile.btf_maps_shndx);
    data = elf_sec_data(obj, scn);
    if (!scn || !data)
    {
        pr_warn("elf: failed to get %s map definitions for %s\n",
                MAPS_ELF_SEC, obj->path);
        return -EINVAL;
    }

    nr_types = btf__type_cnt(obj->btf);
    for (i = 1; i < nr_types; i++)
    {
        t = btf__type_by_id(obj->btf, i);
        if (!btf_is_datasec(t))
            continue;
        name = btf__name_by_offset(obj->btf, t->name_off);
        if (strcmp(name, MAPS_ELF_SEC) == 0)
        {
            sec = t;
            obj->efile.btf_maps_sec_btf_id = i;
            break;
        }
    }

    if (!sec)
    {
        pr_warn("DATASEC '%s' not found.\n", MAPS_ELF_SEC);
        return -ENOENT;
    }

    vlen = btf_vlen(sec);
    for (i = 0; i < vlen; i++)
    {
        err = bpf_object__init_user_btf_map(obj, sec, i,
                                            obj->efile.btf_maps_shndx,
                                            data, strict,
                                            pin_root_path);
        if (err)
            return err;
    }

    return 0;
}

static int bpf_object__init_maps(struct bpf_object *obj,
                                 const struct bpf_object_open_opts *opts)
{
    const char *pin_root_path;
    bool strict;
    int err = 0;

    strict = !OPTS_GET(opts, relaxed_maps, false);
    pin_root_path = OPTS_GET(opts, pin_root_path, NULL);

    err = bpf_object__init_user_btf_maps(obj, strict, pin_root_path);
    err = err ?: bpf_object__init_global_data_maps(obj);
    err = err ?: bpf_object__init_kconfig_map(obj);
    err = err ?: bpf_object_init_struct_ops(obj);

    return err;
}

static bool section_have_execinstr(struct bpf_object *obj, int idx)
{
    Elf64_Shdr *sh;

    sh = elf_sec_hdr(obj, elf_sec_by_idx(obj, idx));
    if (!sh)
        return false;

    return sh->sh_flags & SHF_EXECINSTR;
}

static bool btf_needs_sanitization(struct bpf_object *obj)
{
    bool has_func_global = kernel_supports(obj, FEAT_BTF_GLOBAL_FUNC);
    bool has_datasec = kernel_supports(obj, FEAT_BTF_DATASEC);
    bool has_float = kernel_supports(obj, FEAT_BTF_FLOAT);
    bool has_func = kernel_supports(obj, FEAT_BTF_FUNC);
    bool has_decl_tag = kernel_supports(obj, FEAT_BTF_DECL_TAG);
    bool has_type_tag = kernel_supports(obj, FEAT_BTF_TYPE_TAG);
    bool has_enum64 = kernel_supports(obj, FEAT_BTF_ENUM64);

    return !has_func || !has_datasec || !has_func_global || !has_float ||
           !has_decl_tag || !has_type_tag || !has_enum64;
}

static int bpf_object__sanitize_btf(struct bpf_object *obj, struct btf *btf)
{
    bool has_func_global = kernel_supports(obj, FEAT_BTF_GLOBAL_FUNC);
    bool has_datasec = kernel_supports(obj, FEAT_BTF_DATASEC);
    bool has_float = kernel_supports(obj, FEAT_BTF_FLOAT);
    bool has_func = kernel_supports(obj, FEAT_BTF_FUNC);
    bool has_decl_tag = kernel_supports(obj, FEAT_BTF_DECL_TAG);
    bool has_type_tag = kernel_supports(obj, FEAT_BTF_TYPE_TAG);
    bool has_enum64 = kernel_supports(obj, FEAT_BTF_ENUM64);
    int enum64_placeholder_id = 0;
    struct btf_type *t;
    int i, j, vlen;

    for (i = 1; i < btf__type_cnt(btf); i++)
    {
        t = (struct btf_type *)btf__type_by_id(btf, i);

        if ((!has_datasec && btf_is_var(t)) || (!has_decl_tag && btf_is_decl_tag(t)))
        {
            /* replace VAR/DECL_TAG with INT */
            t->info = BTF_INFO_ENC(BTF_KIND_INT, 0, 0);
            /*
             * using size = 1 is the safest choice, 4 will be too
             * big and cause kernel BTF validation failure if
             * original variable took less than 4 bytes
             */
            t->size = 1;
            *(int *)(t + 1) = BTF_INT_ENC(0, 0, 8);
        }
        else if (!has_datasec && btf_is_datasec(t))
        {
            /* replace DATASEC with STRUCT */
            const struct btf_var_secinfo *v = btf_var_secinfos(t);
            struct btf_member *m = btf_members(t);
            struct btf_type *vt;
            char *name;

            name = (char *)btf__name_by_offset(btf, t->name_off);
            while (*name)
            {
                if (*name == '.')
                    *name = '_';
                name++;
            }

            vlen = btf_vlen(t);
            t->info = BTF_INFO_ENC(BTF_KIND_STRUCT, 0, vlen);
            for (j = 0; j < vlen; j++, v++, m++)
            {
                /* order of field assignments is important */
                m->offset = v->offset * 8;
                m->type = v->type;
                /* preserve variable name as member name */
                vt = (void *)btf__type_by_id(btf, v->type);
                m->name_off = vt->name_off;
            }
        }
        else if (!has_func && btf_is_func_proto(t))
        {
            /* replace FUNC_PROTO with ENUM */
            vlen = btf_vlen(t);
            t->info = BTF_INFO_ENC(BTF_KIND_ENUM, 0, vlen);
            t->size = sizeof(__u32); /* kernel enforced */
        }
        else if (!has_func && btf_is_func(t))
        {
            /* replace FUNC with TYPEDEF */
            t->info = BTF_INFO_ENC(BTF_KIND_TYPEDEF, 0, 0);
        }
        else if (!has_func_global && btf_is_func(t))
        {
            /* replace BTF_FUNC_GLOBAL with BTF_FUNC_STATIC */
            t->info = BTF_INFO_ENC(BTF_KIND_FUNC, 0, 0);
        }
        else if (!has_float && btf_is_float(t))
        {
            /* replace FLOAT with an equally-sized empty STRUCT;
             * since C compilers do not accept e.g. "float" as a
             * valid struct name, make it anonymous
             */
            t->name_off = 0;
            t->info = BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 0);
        }
        else if (!has_type_tag && btf_is_type_tag(t))
        {
            /* replace TYPE_TAG with a CONST */
            t->name_off = 0;
            t->info = BTF_INFO_ENC(BTF_KIND_CONST, 0, 0);
        }
        else if (!has_enum64 && btf_is_enum(t))
        {
            /* clear the kflag */
            t->info = btf_type_info(btf_kind(t), btf_vlen(t), false);
        }
        else if (!has_enum64 && btf_is_enum64(t))
        {
            /* replace ENUM64 with a union */
            struct btf_member *m;

            if (enum64_placeholder_id == 0)
            {
                enum64_placeholder_id = btf__add_int(btf, "enum64_placeholder", 1, 0);
                if (enum64_placeholder_id < 0)
                    return enum64_placeholder_id;

                t = (struct btf_type *)btf__type_by_id(btf, i);
            }

            m = btf_members(t);
            vlen = btf_vlen(t);
            t->info = BTF_INFO_ENC(BTF_KIND_UNION, 0, vlen);
            for (j = 0; j < vlen; j++, m++)
            {
                m->type = enum64_placeholder_id;
                m->offset = 0;
            }
        }
    }

    return 0;
}

static bool libbpf_needs_btf(const struct bpf_object *obj)
{
    return obj->efile.btf_maps_shndx >= 0 ||
           obj->efile.st_ops_shndx >= 0 ||
           obj->efile.st_ops_link_shndx >= 0 ||
           obj->nr_extern > 0;
}

static bool kernel_needs_btf(const struct bpf_object *obj)
{
    return obj->efile.st_ops_shndx >= 0 || obj->efile.st_ops_link_shndx >= 0;
}

static int bpf_object__init_btf(struct bpf_object *obj,
                                Elf_Data *btf_data,
                                Elf_Data *btf_ext_data)
{
    int err = -ENOENT;

    if (btf_data)
    {
        obj->btf = btf__new(btf_data->d_buf, btf_data->d_size);
        err = libbpf_get_error(obj->btf);
        if (err)
        {
            obj->btf = NULL;
            pr_warn("Error loading ELF section %s: %d.\n", BTF_ELF_SEC, err);
            goto out;
        }
        /* enforce 8-byte pointers for BPF-targeted BTFs */
        btf__set_pointer_size(obj->btf, 8);
    }
    if (btf_ext_data)
    {
        struct btf_ext_info *ext_segs[3];
        int seg_num, sec_num;

        if (!obj->btf)
        {
            pr_debug("Ignore ELF section %s because its depending ELF section %s is not found.\n",
                     BTF_EXT_ELF_SEC, BTF_ELF_SEC);
            goto out;
        }
        obj->btf_ext = btf_ext__new(btf_ext_data->d_buf, btf_ext_data->d_size);
        err = libbpf_get_error(obj->btf_ext);
        if (err)
        {
            pr_warn("Error loading ELF section %s: %d. Ignored and continue.\n",
                    BTF_EXT_ELF_SEC, err);
            obj->btf_ext = NULL;
            goto out;
        }

        /* setup .BTF.ext to ELF section mapping */
        ext_segs[0] = &obj->btf_ext->func_info;
        ext_segs[1] = &obj->btf_ext->line_info;
        ext_segs[2] = &obj->btf_ext->core_relo_info;
        for (seg_num = 0; seg_num < ARRAY_SIZE(ext_segs); seg_num++)
        {
            struct btf_ext_info *seg = ext_segs[seg_num];
            const struct btf_ext_info_sec *sec;
            const char *sec_name;
            Elf_Scn *scn;

            if (seg->sec_cnt == 0)
                continue;

            seg->sec_idxs = calloc(seg->sec_cnt, sizeof(*seg->sec_idxs));
            if (!seg->sec_idxs)
            {
                err = -ENOMEM;
                goto out;
            }

            sec_num = 0;
            for_each_btf_ext_sec(seg, sec)
            {
                /* preventively increment index to avoid doing
                 * this before every continue below
                 */
                sec_num++;

                sec_name = btf__name_by_offset(obj->btf, sec->sec_name_off);
                if (str_is_empty(sec_name))
                    continue;
                scn = elf_sec_by_name(obj, sec_name);
                if (!scn)
                    continue;

                seg->sec_idxs[sec_num - 1] = elf_ndxscn(scn);
            }
        }
    }
out:
    if (err && libbpf_needs_btf(obj))
    {
        pr_warn("BTF is required, but is missing or corrupted.\n");
        return err;
    }
    return 0;
}

static int compare_vsi_off(const void *_a, const void *_b)
{
    const struct btf_var_secinfo *a = _a;
    const struct btf_var_secinfo *b = _b;

    return a->offset - b->offset;
}

static int btf_fixup_datasec(struct bpf_object *obj, struct btf *btf,
                             struct btf_type *t)
{
    __u32 size = 0, i, vars = btf_vlen(t);
    const char *sec_name = btf__name_by_offset(btf, t->name_off);
    struct btf_var_secinfo *vsi;
    bool fixup_offsets = false;
    int err;

    if (!sec_name)
    {
        pr_debug("No name found in string section for DATASEC kind.\n");
        return -ENOENT;
    }

    if (strcmp(sec_name, KCONFIG_SEC) == 0 || strcmp(sec_name, KSYMS_SEC) == 0)
        goto sort_vars;

    if (t->size == 0)
    {
        err = find_elf_sec_sz(obj, sec_name, &size);
        if (err || !size)
        {
            pr_debug("sec '%s': failed to determine size from ELF: size %u, err %d\n",
                     sec_name, size, err);
            return -ENOENT;
        }

        t->size = size;
        fixup_offsets = true;
    }

    for (i = 0, vsi = btf_var_secinfos(t); i < vars; i++, vsi++)
    {
        const struct btf_type *t_var;
        struct btf_var *var;
        const char *var_name;
        Elf64_Sym *sym;

        t_var = btf__type_by_id(btf, vsi->type);
        if (!t_var || !btf_is_var(t_var))
        {
            pr_debug("sec '%s': unexpected non-VAR type found\n", sec_name);
            return -EINVAL;
        }

        var = btf_var(t_var);
        if (var->linkage == BTF_VAR_STATIC || var->linkage == BTF_VAR_GLOBAL_EXTERN)
            continue;

        var_name = btf__name_by_offset(btf, t_var->name_off);
        if (!var_name)
        {
            pr_debug("sec '%s': failed to find name of DATASEC's member #%d\n",
                     sec_name, i);
            return -ENOENT;
        }

        sym = find_elf_var_sym(obj, var_name);
        if (IS_ERR(sym))
        {
            pr_debug("sec '%s': failed to find ELF symbol for VAR '%s'\n",
                     sec_name, var_name);
            return -ENOENT;
        }

        if (fixup_offsets)
            vsi->offset = sym->st_value;

        if (ELF64_ST_VISIBILITY(sym->st_other) == STV_HIDDEN || ELF64_ST_VISIBILITY(sym->st_other) == STV_INTERNAL)
            var->linkage = BTF_VAR_STATIC;
    }

sort_vars:
    qsort(btf_var_secinfos(t), vars, sizeof(*vsi), compare_vsi_off);
    return 0;
}

static int bpf_object_fixup_btf(struct bpf_object *obj)
{
    int i, n, err = 0;

    if (!obj->btf)
        return 0;

    n = btf__type_cnt(obj->btf);
    for (i = 1; i < n; i++)
    {
        struct btf_type *t = btf_type_by_id(obj->btf, i);

        if (btf_is_datasec(t))
        {
            err = btf_fixup_datasec(obj, obj->btf, t);
            if (err)
                return err;
        }
    }

    return 0;
}

static bool prog_needs_vmlinux_btf(struct bpf_program *prog)
{
    if (prog->type == BPF_PROG_TYPE_STRUCT_OPS ||
        prog->type == BPF_PROG_TYPE_LSM)
        return true;

    if (prog->type == BPF_PROG_TYPE_TRACING && !prog->attach_prog_fd)
        return true;

    return false;
}

static bool obj_needs_vmlinux_btf(const struct bpf_object *obj)
{
    struct bpf_program *prog;
    int i;
    if (obj->btf_ext && obj->btf_ext->core_relo_info.len && !obj->btf_custom_path)
        return true;

    /* Support for typed ksyms needs kernel BTF */
    for (i = 0; i < obj->nr_extern; i++)
    {
        const struct extern_desc *ext;

        ext = &obj->externs[i];
        if (ext->type == EXT_KSYM && ext->ksym.type_id)
            return true;
    }

    bpf_object__for_each_program(prog, obj)
    {
        if (!prog->autoload)
            continue;
        if (prog_needs_vmlinux_btf(prog))
            return true;
    }

    return false;
}

static int bpf_object__load_vmlinux_btf(struct bpf_object *obj, bool force)
{
    int err;

    /* btf_vmlinux could be loaded earlier */
    if (obj->btf_vmlinux || obj->gen_loader)
        return 0;

    if (!force && !obj_needs_vmlinux_btf(obj))
        return 0;

    obj->btf_vmlinux = btf__load_vmlinux_btf();
    err = libbpf_get_error(obj->btf_vmlinux);
    if (err)
    {
        pr_warn("Error loading vmlinux BTF: %d\n", err);
        obj->btf_vmlinux = NULL;
        return err;
    }
    return 0;
}

static int bpf_object__sanitize_and_load_btf(struct bpf_object *obj)
{
    struct btf *kern_btf = obj->btf;
    bool btf_mandatory, sanitize;
    int i, err = 0;

    if (!obj->btf)
        return 0;

    if (!kernel_supports(obj, FEAT_BTF))
    {
        if (kernel_needs_btf(obj))
        {
            err = -EOPNOTSUPP;
            goto report;
        }
        pr_debug("Kernel doesn't support BTF, skipping uploading it.\n");
        return 0;
    }

    for (i = 0; i < obj->nr_programs; i++)
    {
        struct bpf_program *prog = &obj->programs[i];
        struct btf_type *t;
        const char *name;
        int j, n;

        if (!prog->mark_btf_static || !prog_is_subprog(obj, prog))
            continue;

        n = btf__type_cnt(obj->btf);
        for (j = 1; j < n; j++)
        {
            t = btf_type_by_id(obj->btf, j);
            if (!btf_is_func(t) || btf_func_linkage(t) != BTF_FUNC_GLOBAL)
                continue;

            name = btf__str_by_offset(obj->btf, t->name_off);
            if (strcmp(name, prog->name) != 0)
                continue;

            t->info = btf_type_info(BTF_KIND_FUNC, BTF_FUNC_STATIC, 0);
            break;
        }
    }

    sanitize = btf_needs_sanitization(obj);
    if (sanitize)
    {
        const void *raw_data;
        __u32 sz;

        /* clone BTF to sanitize a copy and leave the original intact */
        raw_data = btf__raw_data(obj->btf, &sz);
        kern_btf = btf__new(raw_data, sz);
        err = libbpf_get_error(kern_btf);
        if (err)
            return err;

        /* enforce 8-byte pointers for BPF-targeted BTFs */
        btf__set_pointer_size(obj->btf, 8);
        err = bpf_object__sanitize_btf(obj, kern_btf);
        if (err)
            return err;
    }

    if (obj->gen_loader)
    {
        __u32 raw_size = 0;
        const void *raw_data = btf__raw_data(kern_btf, &raw_size);

        if (!raw_data)
            return -ENOMEM;
        bpf_gen__load_btf(obj->gen_loader, raw_data, raw_size);
        /* Pretend to have valid FD to pass various fd >= 0 checks.
         * This fd == 0 will not be used with any syscall and will be reset to -1 eventually.
         */
        btf__set_fd(kern_btf, 0);
    }
    else
    {
        /* currently BPF_BTF_LOAD only supports log_level 1 */
        err = btf_load_into_kernel(kern_btf, obj->log_buf, obj->log_size,
                                   obj->log_level ? 1 : 0);
    }
    if (sanitize)
    {
        if (!err)
        {
            /* move fd to libbpf's BTF */
            btf__set_fd(obj->btf, btf__fd(kern_btf));
            btf__set_fd(kern_btf, -1);
        }
        btf__free(kern_btf);
    }
report:
    if (err)
    {
        btf_mandatory = kernel_needs_btf(obj);
        pr_warn("Error loading .BTF into kernel: %d. %s\n", err,
                btf_mandatory ? "BTF is mandatory, can't proceed."
                              : "BTF is optional, ignoring.");
        if (!btf_mandatory)
            err = 0;
    }
    return err;
}

static const char *elf_sym_str(const struct bpf_object *obj, size_t off)
{
    const char *name;

    name = elf_strptr(obj->efile.elf, obj->efile.strtabidx, off);
    if (!name)
    {
        pr_warn("elf: failed to get section name string at offset %zu from %s: %s\n",
                off, obj->path, elf_errmsg(-1));
        return NULL;
    }

    return name;
}

static const char *elf_sec_str(const struct bpf_object *obj, size_t off)
{
    const char *name;

    name = elf_strptr(obj->efile.elf, obj->efile.shstrndx, off);
    if (!name)
    {
        pr_warn("elf: failed to get section name string at offset %zu from %s: %s\n",
                off, obj->path, elf_errmsg(-1));
        return NULL;
    }

    return name;
}

static Elf_Scn *elf_sec_by_idx(const struct bpf_object *obj, size_t idx)
{
    Elf_Scn *scn;

    scn = elf_getscn(obj->efile.elf, idx);
    if (!scn)
    {
        pr_warn("elf: failed to get section(%zu) from %s: %s\n",
                idx, obj->path, elf_errmsg(-1));
        return NULL;
    }
    return scn;
}

static Elf_Scn *elf_sec_by_name(const struct bpf_object *obj, const char *name)
{
    Elf_Scn *scn = NULL;
    Elf *elf = obj->efile.elf;
    const char *sec_name;

    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        sec_name = elf_sec_name(obj, scn);
        if (!sec_name)
            return NULL;

        if (strcmp(sec_name, name) != 0)
            continue;

        return scn;
    }
    return NULL;
}

static Elf64_Shdr *elf_sec_hdr(const struct bpf_object *obj, Elf_Scn *scn)
{
    Elf64_Shdr *shdr;

    if (!scn)
        return NULL;

    shdr = elf64_getshdr(scn);
    if (!shdr)
    {
        pr_warn("elf: failed to get section(%zu) header from %s: %s\n",
                elf_ndxscn(scn), obj->path, elf_errmsg(-1));
        return NULL;
    }

    return shdr;
}

static const char *elf_sec_name(const struct bpf_object *obj, Elf_Scn *scn)
{
    const char *name;
    Elf64_Shdr *sh;

    if (!scn)
        return NULL;

    sh = elf_sec_hdr(obj, scn);
    if (!sh)
        return NULL;

    name = elf_sec_str(obj, sh->sh_name);
    if (!name)
    {
        pr_warn("elf: failed to get section(%zu) name from %s: %s\n",
                elf_ndxscn(scn), obj->path, elf_errmsg(-1));
        return NULL;
    }

    return name;
}

static Elf_Data *elf_sec_data(const struct bpf_object *obj, Elf_Scn *scn)
{
    Elf_Data *data;

    if (!scn)
        return NULL;

    data = elf_getdata(scn, 0);
    if (!data)
    {
        pr_warn("elf: failed to get section(%zu) %s data from %s: %s\n",
                elf_ndxscn(scn), elf_sec_name(obj, scn) ?: "<?>",
                obj->path, elf_errmsg(-1));
        return NULL;
    }

    return data;
}

static Elf64_Sym *elf_sym_by_idx(const struct bpf_object *obj, size_t idx)
{
    if (idx >= obj->efile.symbols->d_size / sizeof(Elf64_Sym))
        return NULL;

    return (Elf64_Sym *)obj->efile.symbols->d_buf + idx;
}

static Elf64_Rel *elf_rel_by_idx(Elf_Data *data, size_t idx)
{
    if (idx >= data->d_size / sizeof(Elf64_Rel))
        return NULL;

    return (Elf64_Rel *)data->d_buf + idx;
}

static bool is_sec_name_dwarf(const char *name)
{
    /* approximation, but the actual list is too long */
    return str_has_pfx(name, ".debug_");
}

static bool ignore_elf_section(Elf64_Shdr *hdr, const char *name)
{
    /* no special handling of .strtab */
    if (hdr->sh_type == SHT_STRTAB)
        return true;

    /* ignore .llvm_addrsig section as well */
    if (hdr->sh_type == SHT_LLVM_ADDRSIG)
        return true;

    /* no subprograms will lead to an empty .text section, ignore it */
    if (hdr->sh_type == SHT_PROGBITS && hdr->sh_size == 0 &&
        strcmp(name, ".text") == 0)
        return true;

    /* DWARF sections */
    if (is_sec_name_dwarf(name))
        return true;

    if (str_has_pfx(name, ".rel"))
    {
        name += sizeof(".rel") - 1;
        /* DWARF section relocations */
        if (is_sec_name_dwarf(name))
            return true;

        /* .BTF and .BTF.ext don't need relocations */
        if (strcmp(name, BTF_ELF_SEC) == 0 ||
            strcmp(name, BTF_EXT_ELF_SEC) == 0)
            return true;
    }

    return false;
}

static int cmp_progs(const void *_a, const void *_b)
{
    const struct bpf_program *a = _a;
    const struct bpf_program *b = _b;

    if (a->sec_idx != b->sec_idx)
        return a->sec_idx < b->sec_idx ? -1 : 1;

    /* sec_insn_off can't be the same within the section */
    return a->sec_insn_off < b->sec_insn_off ? -1 : 1;
}

static int bpf_object__elf_collect(struct bpf_object *obj)
{
    struct elf_sec_desc *sec_desc;
    Elf *elf = obj->efile.elf;
    Elf_Data *btf_ext_data = NULL;
    Elf_Data *btf_data = NULL;
    int idx = 0, err = 0;
    const char *name;
    Elf_Data *data;
    Elf_Scn *scn;
    Elf64_Shdr *sh;

    /* ELF section indices are 0-based, but sec #0 is special "invalid"
     * section. Since section count retrieved by elf_getshdrnum() does
     * include sec #0, it is already the necessary size of an array to keep
     * all the sections.
     */
    if (elf_getshdrnum(obj->efile.elf, &obj->efile.sec_cnt))
    {
        pr_warn("elf: failed to get the number of sections for %s: %s\n",
                obj->path, elf_errmsg(-1));
        return -LIBBPF_ERRNO__FORMAT;
    }
    obj->efile.secs = calloc(obj->efile.sec_cnt, sizeof(*obj->efile.secs));
    if (!obj->efile.secs)
        return -ENOMEM;

    /* a bunch of ELF parsing functionality depends on processing symbols,
     * so do the first pass and find the symbol table
     */
    scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        sh = elf_sec_hdr(obj, scn);
        if (!sh)
            return -LIBBPF_ERRNO__FORMAT;

        if (sh->sh_type == SHT_SYMTAB)
        {
            if (obj->efile.symbols)
            {
                pr_warn("elf: multiple symbol tables in %s\n", obj->path);
                return -LIBBPF_ERRNO__FORMAT;
            }

            data = elf_sec_data(obj, scn);
            if (!data)
                return -LIBBPF_ERRNO__FORMAT;

            idx = elf_ndxscn(scn);

            obj->efile.symbols = data;
            obj->efile.symbols_shndx = idx;
            obj->efile.strtabidx = sh->sh_link;
        }
    }

    if (!obj->efile.symbols)
    {
        pr_warn("elf: couldn't find symbol table in %s, stripped object file?\n",
                obj->path);
        return -ENOENT;
    }

    scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        idx = elf_ndxscn(scn);
        sec_desc = &obj->efile.secs[idx];

        sh = elf_sec_hdr(obj, scn);
        if (!sh)
            return -LIBBPF_ERRNO__FORMAT;

        name = elf_sec_str(obj, sh->sh_name);
        if (!name)
            return -LIBBPF_ERRNO__FORMAT;

        if (ignore_elf_section(sh, name))
            continue;

        data = elf_sec_data(obj, scn);
        if (!data)
            return -LIBBPF_ERRNO__FORMAT;

        pr_debug("elf: section(%d) %s, size %ld, link %d, flags %lx, type=%d\n",
                 idx, name, (unsigned long)data->d_size,
                 (int)sh->sh_link, (unsigned long)sh->sh_flags,
                 (int)sh->sh_type);

        if (strcmp(name, "license") == 0)
        {
            err = bpf_object__init_license(obj, data->d_buf, data->d_size);
            if (err)
                return err;
        }
        else if (strcmp(name, "version") == 0)
        {
            err = bpf_object__init_kversion(obj, data->d_buf, data->d_size);
            if (err)
                return err;
        }
        else if (strcmp(name, "maps") == 0)
        {
            pr_warn("elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+\n");
            return -ENOTSUP;
        }
        else if (strcmp(name, MAPS_ELF_SEC) == 0)
        {
            obj->efile.btf_maps_shndx = idx;
        }
        else if (strcmp(name, BTF_ELF_SEC) == 0)
        {
            if (sh->sh_type != SHT_PROGBITS)
                return -LIBBPF_ERRNO__FORMAT;
            btf_data = data;
        }
        else if (strcmp(name, BTF_EXT_ELF_SEC) == 0)
        {
            if (sh->sh_type != SHT_PROGBITS)
                return -LIBBPF_ERRNO__FORMAT;
            btf_ext_data = data;
        }
        else if (sh->sh_type == SHT_SYMTAB)
        {
            /* already processed during the first pass above */
        }
        else if (sh->sh_type == SHT_PROGBITS && data->d_size > 0)
        {
            if (sh->sh_flags & SHF_EXECINSTR)
            {
                if (strcmp(name, ".text") == 0)
                    obj->efile.text_shndx = idx;
                err = bpf_object__add_programs(obj, data, name, idx);
                if (err)
                    return err;
            }
            else if (strcmp(name, DATA_SEC) == 0 ||
                     str_has_pfx(name, DATA_SEC "."))
            {
                sec_desc->sec_type = SEC_DATA;
                sec_desc->shdr = sh;
                sec_desc->data = data;
            }
            else if (strcmp(name, RODATA_SEC) == 0 ||
                     str_has_pfx(name, RODATA_SEC "."))
            {
                sec_desc->sec_type = SEC_RODATA;
                sec_desc->shdr = sh;
                sec_desc->data = data;
            }
            else if (strcmp(name, STRUCT_OPS_SEC) == 0)
            {
                obj->efile.st_ops_data = data;
                obj->efile.st_ops_shndx = idx;
            }
            else if (strcmp(name, STRUCT_OPS_LINK_SEC) == 0)
            {
                obj->efile.st_ops_link_data = data;
                obj->efile.st_ops_link_shndx = idx;
            }
            else
            {
                pr_info("elf: skipping unrecognized data section(%d) %s\n",
                        idx, name);
            }
        }
        else if (sh->sh_type == SHT_REL)
        {
            int targ_sec_idx = sh->sh_info; /* points to other section */

            if (sh->sh_entsize != sizeof(Elf64_Rel) ||
                targ_sec_idx >= obj->efile.sec_cnt)
                return -LIBBPF_ERRNO__FORMAT;

            /* Only do relo for section with exec instructions */
            if (!section_have_execinstr(obj, targ_sec_idx) &&
                strcmp(name, ".rel" STRUCT_OPS_SEC) &&
                strcmp(name, ".rel" STRUCT_OPS_LINK_SEC) &&
                strcmp(name, ".rel" MAPS_ELF_SEC))
            {
                pr_info("elf: skipping relo section(%d) %s for section(%d) %s\n",
                        idx, name, targ_sec_idx,
                        elf_sec_name(obj, elf_sec_by_idx(obj, targ_sec_idx)) ?: "<?>");
                continue;
            }

            sec_desc->sec_type = SEC_RELO;
            sec_desc->shdr = sh;
            sec_desc->data = data;
        }
        else if (sh->sh_type == SHT_NOBITS && (strcmp(name, BSS_SEC) == 0 ||
                                               str_has_pfx(name, BSS_SEC ".")))
        {
            sec_desc->sec_type = SEC_BSS;
            sec_desc->shdr = sh;
            sec_desc->data = data;
        }
        else
        {
            pr_info("elf: skipping section(%d) %s (size %zu)\n", idx, name,
                    (size_t)sh->sh_size);
        }
    }

    if (!obj->efile.strtabidx || obj->efile.strtabidx > idx)
    {
        pr_warn("elf: symbol strings section missing or invalid in %s\n", obj->path);
        return -LIBBPF_ERRNO__FORMAT;
    }

    /* sort BPF programs by section name and in-section instruction offset
     * for faster search
     */
    if (obj->nr_programs)
        qsort(obj->programs, obj->nr_programs, sizeof(*obj->programs), cmp_progs);

    return bpf_object__init_btf(obj, btf_data, btf_ext_data);
}

static bool sym_is_extern(const Elf64_Sym *sym)
{
    int bind = ELF64_ST_BIND(sym->st_info);
    /* externs are symbols w/ type=NOTYPE, bind=GLOBAL|WEAK, section=UND */
    return sym->st_shndx == SHN_UNDEF &&
           (bind == STB_GLOBAL || bind == STB_WEAK) &&
           ELF64_ST_TYPE(sym->st_info) == STT_NOTYPE;
}

static bool sym_is_subprog(const Elf64_Sym *sym, int text_shndx)
{
    int bind = ELF64_ST_BIND(sym->st_info);
    int type = ELF64_ST_TYPE(sym->st_info);

    /* in .text section */
    if (sym->st_shndx != text_shndx)
        return false;

    /* local function */
    if (bind == STB_LOCAL && type == STT_SECTION)
        return true;

    /* global function */
    return bind == STB_GLOBAL && type == STT_FUNC;
}

static int find_extern_btf_id(const struct btf *btf, const char *ext_name)
{
    const struct btf_type *t;
    const char *tname;
    int i, n;

    if (!btf)
        return -ESRCH;

    n = btf__type_cnt(btf);
    for (i = 1; i < n; i++)
    {
        t = btf__type_by_id(btf, i);

        if (!btf_is_var(t) && !btf_is_func(t))
            continue;

        tname = btf__name_by_offset(btf, t->name_off);
        if (strcmp(tname, ext_name))
            continue;

        if (btf_is_var(t) &&
            btf_var(t)->linkage != BTF_VAR_GLOBAL_EXTERN)
            return -EINVAL;

        if (btf_is_func(t) && btf_func_linkage(t) != BTF_FUNC_EXTERN)
            return -EINVAL;

        return i;
    }

    return -ENOENT;
}

static int find_extern_sec_btf_id(struct btf *btf, int ext_btf_id)
{
    const struct btf_var_secinfo *vs;
    const struct btf_type *t;
    int i, j, n;

    if (!btf)
        return -ESRCH;

    n = btf__type_cnt(btf);
    for (i = 1; i < n; i++)
    {
        t = btf__type_by_id(btf, i);

        if (!btf_is_datasec(t))
            continue;

        vs = btf_var_secinfos(t);
        for (j = 0; j < btf_vlen(t); j++, vs++)
        {
            if (vs->type == ext_btf_id)
                return i;
        }
    }

    return -ENOENT;
}

static enum kcfg_type find_kcfg_type(const struct btf *btf, int id,
                                     bool *is_signed)
{
    const struct btf_type *t;
    const char *name;

    t = skip_mods_and_typedefs(btf, id, NULL);
    name = btf__name_by_offset(btf, t->name_off);

    if (is_signed)
        *is_signed = false;
    switch (btf_kind(t))
    {
    case BTF_KIND_INT:
    {
        int enc = btf_int_encoding(t);

        if (enc & BTF_INT_BOOL)
            return t->size == 1 ? KCFG_BOOL : KCFG_UNKNOWN;
        if (is_signed)
            *is_signed = enc & BTF_INT_SIGNED;
        if (t->size == 1)
            return KCFG_CHAR;
        if (t->size < 1 || t->size > 8 || (t->size & (t->size - 1)))
            return KCFG_UNKNOWN;
        return KCFG_INT;
    }
    case BTF_KIND_ENUM:
        if (t->size != 4)
            return KCFG_UNKNOWN;
        if (strcmp(name, "libbpf_tristate"))
            return KCFG_UNKNOWN;
        return KCFG_TRISTATE;
    case BTF_KIND_ENUM64:
        if (strcmp(name, "libbpf_tristate"))
            return KCFG_UNKNOWN;
        return KCFG_TRISTATE;
    case BTF_KIND_ARRAY:
        if (btf_array(t)->nelems == 0)
            return KCFG_UNKNOWN;
        if (find_kcfg_type(btf, btf_array(t)->type, NULL) != KCFG_CHAR)
            return KCFG_UNKNOWN;
        return KCFG_CHAR_ARR;
    default:
        return KCFG_UNKNOWN;
    }
}

static int cmp_externs(const void *_a, const void *_b)
{
    const struct extern_desc *a = _a;
    const struct extern_desc *b = _b;

    if (a->type != b->type)
        return a->type < b->type ? -1 : 1;

    if (a->type == EXT_KCFG)
    {
        /* descending order by alignment requirements */
        if (a->kcfg.align != b->kcfg.align)
            return a->kcfg.align > b->kcfg.align ? -1 : 1;
        /* ascending order by size, within same alignment class */
        if (a->kcfg.sz != b->kcfg.sz)
            return a->kcfg.sz < b->kcfg.sz ? -1 : 1;
    }

    /* resolve ties by name */
    return strcmp(a->name, b->name);
}

static int find_int_btf_id(const struct btf *btf)
{
    const struct btf_type *t;
    int i, n;

    n = btf__type_cnt(btf);
    for (i = 1; i < n; i++)
    {
        t = btf__type_by_id(btf, i);

        if (btf_is_int(t) && btf_int_bits(t) == 32)
            return i;
    }

    return 0;
}

static int add_dummy_ksym_var(struct btf *btf)
{
    int i, int_btf_id, sec_btf_id, dummy_var_btf_id;
    const struct btf_var_secinfo *vs;
    const struct btf_type *sec;

    if (!btf)
        return 0;

    sec_btf_id = btf__find_by_name_kind(btf, KSYMS_SEC,
                                        BTF_KIND_DATASEC);
    if (sec_btf_id < 0)
        return 0;

    sec = btf__type_by_id(btf, sec_btf_id);
    vs = btf_var_secinfos(sec);
    for (i = 0; i < btf_vlen(sec); i++, vs++)
    {
        const struct btf_type *vt;

        vt = btf__type_by_id(btf, vs->type);
        if (btf_is_func(vt))
            break;
    }

    /* No func in ksyms sec.  No need to add dummy var. */
    if (i == btf_vlen(sec))
        return 0;

    int_btf_id = find_int_btf_id(btf);
    dummy_var_btf_id = btf__add_var(btf,
                                    "dummy_ksym",
                                    BTF_VAR_GLOBAL_ALLOCATED,
                                    int_btf_id);
    if (dummy_var_btf_id < 0)
        pr_warn("cannot create a dummy_ksym var\n");

    return dummy_var_btf_id;
}

static int bpf_object__collect_externs(struct bpf_object *obj)
{
    struct btf_type *sec, *kcfg_sec = NULL, *ksym_sec = NULL;
    const struct btf_type *t;
    struct extern_desc *ext;
    int i, n, off, dummy_var_btf_id;
    const char *ext_name, *sec_name;
    Elf_Scn *scn;
    Elf64_Shdr *sh;

    if (!obj->efile.symbols)
        return 0;

    scn = elf_sec_by_idx(obj, obj->efile.symbols_shndx);
    sh = elf_sec_hdr(obj, scn);
    if (!sh || sh->sh_entsize != sizeof(Elf64_Sym))
        return -LIBBPF_ERRNO__FORMAT;

    dummy_var_btf_id = add_dummy_ksym_var(obj->btf);
    if (dummy_var_btf_id < 0)
        return dummy_var_btf_id;

    n = sh->sh_size / sh->sh_entsize;
    pr_debug("looking for externs among %d symbols...\n", n);

    for (i = 0; i < n; i++)
    {
        Elf64_Sym *sym = elf_sym_by_idx(obj, i);

        if (!sym)
            return -LIBBPF_ERRNO__FORMAT;
        if (!sym_is_extern(sym))
            continue;
        ext_name = elf_sym_str(obj, sym->st_name);
        if (!ext_name || !ext_name[0])
            continue;

        ext = obj->externs;
        ext = libbpf_reallocarray(ext, obj->nr_extern + 1, sizeof(*ext));
        if (!ext)
            return -ENOMEM;
        obj->externs = ext;
        ext = &ext[obj->nr_extern];
        memset(ext, 0, sizeof(*ext));
        obj->nr_extern++;

        ext->btf_id = find_extern_btf_id(obj->btf, ext_name);
        if (ext->btf_id <= 0)
        {
            pr_warn("failed to find BTF for extern '%s': %d\n",
                    ext_name, ext->btf_id);
            return ext->btf_id;
        }
        t = btf__type_by_id(obj->btf, ext->btf_id);
        ext->name = btf__name_by_offset(obj->btf, t->name_off);
        ext->sym_idx = i;
        ext->is_weak = ELF64_ST_BIND(sym->st_info) == STB_WEAK;

        ext->sec_btf_id = find_extern_sec_btf_id(obj->btf, ext->btf_id);
        if (ext->sec_btf_id <= 0)
        {
            pr_warn("failed to find BTF for extern '%s' [%d] section: %d\n",
                    ext_name, ext->btf_id, ext->sec_btf_id);
            return ext->sec_btf_id;
        }
        sec = (void *)btf__type_by_id(obj->btf, ext->sec_btf_id);
        sec_name = btf__name_by_offset(obj->btf, sec->name_off);

        if (strcmp(sec_name, KCONFIG_SEC) == 0)
        {
            if (btf_is_func(t))
            {
                pr_warn("extern function %s is unsupported under %s section\n",
                        ext->name, KCONFIG_SEC);
                return -ENOTSUP;
            }
            kcfg_sec = sec;
            ext->type = EXT_KCFG;
            ext->kcfg.sz = btf__resolve_size(obj->btf, t->type);
            if (ext->kcfg.sz <= 0)
            {
                pr_warn("failed to resolve size of extern (kcfg) '%s': %d\n",
                        ext_name, ext->kcfg.sz);
                return ext->kcfg.sz;
            }
            ext->kcfg.align = btf__align_of(obj->btf, t->type);
            if (ext->kcfg.align <= 0)
            {
                pr_warn("failed to determine alignment of extern (kcfg) '%s': %d\n",
                        ext_name, ext->kcfg.align);
                return -EINVAL;
            }
            ext->kcfg.type = find_kcfg_type(obj->btf, t->type,
                                            &ext->kcfg.is_signed);
            if (ext->kcfg.type == KCFG_UNKNOWN)
            {
                pr_warn("extern (kcfg) '%s': type is unsupported\n", ext_name);
                return -ENOTSUP;
            }
        }
        else if (strcmp(sec_name, KSYMS_SEC) == 0)
        {
            ksym_sec = sec;
            ext->type = EXT_KSYM;
            skip_mods_and_typedefs(obj->btf, t->type,
                                   &ext->ksym.type_id);
        }
        else
        {
            pr_warn("unrecognized extern section '%s'\n", sec_name);
            return -ENOTSUP;
        }
    }
    pr_debug("collected %d externs total\n", obj->nr_extern);

    if (!obj->nr_extern)
        return 0;

    /* sort externs by type, for kcfg ones also by (align, size, name) */
    qsort(obj->externs, obj->nr_extern, sizeof(*ext), cmp_externs);

    if (ksym_sec)
    {
        /
            int int_btf_id = find_int_btf_id(obj->btf);

        const struct btf_type *dummy_var;

        dummy_var = btf__type_by_id(obj->btf, dummy_var_btf_id);
        for (i = 0; i < obj->nr_extern; i++)
        {
            ext = &obj->externs[i];
            if (ext->type != EXT_KSYM)
                continue;
            pr_debug("extern (ksym) #%d: symbol %d, name %s\n",
                     i, ext->sym_idx, ext->name);
        }

        sec = ksym_sec;
        n = btf_vlen(sec);
        for (i = 0, off = 0; i < n; i++, off += sizeof(int))
        {
            struct btf_var_secinfo *vs = btf_var_secinfos(sec) + i;
            struct btf_type *vt;

            vt = (void *)btf__type_by_id(obj->btf, vs->type);
            ext_name = btf__name_by_offset(obj->btf, vt->name_off);
            ext = find_extern_by_name(obj, ext_name);
            if (!ext)
            {
                pr_warn("failed to find extern definition for BTF %s '%s'\n",
                        btf_kind_str(vt), ext_name);
                return -ESRCH;
            }
            if (btf_is_func(vt))
            {
                const struct btf_type *func_proto;
                struct btf_param *param;
                int j;

                func_proto = btf__type_by_id(obj->btf,
                                             vt->type);
                param = btf_params(func_proto);
                /* Reuse the dummy_var string if the
                 * func proto does not have param name.
                 */
                for (j = 0; j < btf_vlen(func_proto); j++)
                    if (param[j].type && !param[j].name_off)
                        param[j].name_off =
                            dummy_var->name_off;
                vs->type = dummy_var_btf_id;
                vt->info &= ~0xffff;
                vt->info |= BTF_FUNC_GLOBAL;
            }
            else
            {
                btf_var(vt)->linkage = BTF_VAR_GLOBAL_ALLOCATED;
                vt->type = int_btf_id;
            }
            vs->offset = off;
            vs->size = sizeof(int);
        }
        sec->size = off;
    }

    if (kcfg_sec)
    {
        sec = kcfg_sec;
        /* for kcfg externs calculate their offsets within a .kconfig map */
        off = 0;
        for (i = 0; i < obj->nr_extern; i++)
        {
            ext = &obj->externs[i];
            if (ext->type != EXT_KCFG)
                continue;

            ext->kcfg.data_off = roundup(off, ext->kcfg.align);
            off = ext->kcfg.data_off + ext->kcfg.sz;
            pr_debug("extern (kcfg) #%d: symbol %d, off %u, name %s\n",
                     i, ext->sym_idx, ext->kcfg.data_off, ext->name);
        }
        sec->size = off;
        n = btf_vlen(sec);
        for (i = 0; i < n; i++)
        {
            struct btf_var_secinfo *vs = btf_var_secinfos(sec) + i;

            t = btf__type_by_id(obj->btf, vs->type);
            ext_name = btf__name_by_offset(obj->btf, t->name_off);
            ext = find_extern_by_name(obj, ext_name);
            if (!ext)
            {
                pr_warn("failed to find extern definition for BTF var '%s'\n",
                        ext_name);
                return -ESRCH;
            }
            btf_var(t)->linkage = BTF_VAR_GLOBAL_ALLOCATED;
            vs->offset = ext->kcfg.data_off;
        }
    }
    return 0;
}

static bool prog_is_subprog(const struct bpf_object *obj, const struct bpf_program *prog)
{
    return prog->sec_idx == obj->efile.text_shndx && obj->nr_programs > 1;
}

struct bpf_program *
bpf_object__find_program_by_name(const struct bpf_object *obj,
                                 const char *name)
{
    struct bpf_program *prog;

    bpf_object__for_each_program(prog, obj)
    {
        if (prog_is_subprog(obj, prog))
            continue;
        if (!strcmp(prog->name, name))
            return prog;
    }
    return errno = ENOENT, NULL;
}

static bool bpf_object__shndx_is_data(const struct bpf_object *obj,
                                      int shndx)
{
    switch (obj->efile.secs[shndx].sec_type)
    {
    case SEC_BSS:
    case SEC_DATA:
    case SEC_RODATA:
        return true;
    default:
        return false;
    }
}

static bool bpf_object__shndx_is_maps(const struct bpf_object *obj,
                                      int shndx)
{
    return shndx == obj->efile.btf_maps_shndx;
}

static enum libbpf_map_type
bpf_object__section_to_libbpf_map_type(const struct bpf_object *obj, int shndx)
{
    if (shndx == obj->efile.symbols_shndx)
        return LIBBPF_MAP_KCONFIG;

    switch (obj->efile.secs[shndx].sec_type)
    {
    case SEC_BSS:
        return LIBBPF_MAP_BSS;
    case SEC_DATA:
        return LIBBPF_MAP_DATA;
    case SEC_RODATA:
        return LIBBPF_MAP_RODATA;
    default:
        return LIBBPF_MAP_UNSPEC;
    }
}

static int bpf_program__record_reloc(struct bpf_program *prog,
                                     struct reloc_desc *reloc_desc,
                                     __u32 insn_idx, const char *sym_name,
                                     const Elf64_Sym *sym, const Elf64_Rel *rel)
{
    struct bpf_insn *insn = &prog->insns[insn_idx];
    size_t map_idx, nr_maps = prog->obj->nr_maps;
    struct bpf_object *obj = prog->obj;
    __u32 shdr_idx = sym->st_shndx;
    enum libbpf_map_type type;
    const char *sym_sec_name;
    struct bpf_map *map;

    if (!is_call_insn(insn) && !is_ldimm64_insn(insn))
    {
        pr_warn("prog '%s': invalid relo against '%s' for insns[%d].code 0x%x\n",
                prog->name, sym_name, insn_idx, insn->code);
        return -LIBBPF_ERRNO__RELOC;
    }

    if (sym_is_extern(sym))
    {
        int sym_idx = ELF64_R_SYM(rel->r_info);
        int i, n = obj->nr_extern;
        struct extern_desc *ext;

        for (i = 0; i < n; i++)
        {
            ext = &obj->externs[i];
            if (ext->sym_idx == sym_idx)
                break;
        }
        if (i >= n)
        {
            pr_warn("prog '%s': extern relo failed to find extern for '%s' (%d)\n",
                    prog->name, sym_name, sym_idx);
            return -LIBBPF_ERRNO__RELOC;
        }
        pr_debug("prog '%s': found extern #%d '%s' (sym %d) for insn #%u\n",
                 prog->name, i, ext->name, ext->sym_idx, insn_idx);
        if (insn->code == (BPF_JMP | BPF_CALL))
            reloc_desc->type = RELO_EXTERN_CALL;
        else
            reloc_desc->type = RELO_EXTERN_LD64;
        reloc_desc->insn_idx = insn_idx;
        reloc_desc->ext_idx = i;
        return 0;
    }

    /* sub-program call relocation */
    if (is_call_insn(insn))
    {
        if (insn->src_reg != BPF_PSEUDO_CALL)
        {
            pr_warn("prog '%s': incorrect bpf_call opcode\n", prog->name);
            return -LIBBPF_ERRNO__RELOC;
        }
        /* text_shndx can be 0, if no default "main" program exists */
        if (!shdr_idx || shdr_idx != obj->efile.text_shndx)
        {
            sym_sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, shdr_idx));
            pr_warn("prog '%s': bad call relo against '%s' in section '%s'\n",
                    prog->name, sym_name, sym_sec_name);
            return -LIBBPF_ERRNO__RELOC;
        }
        if (sym->st_value % BPF_INSN_SZ)
        {
            pr_warn("prog '%s': bad call relo against '%s' at offset %zu\n",
                    prog->name, sym_name, (size_t)sym->st_value);
            return -LIBBPF_ERRNO__RELOC;
        }
        reloc_desc->type = RELO_CALL;
        reloc_desc->insn_idx = insn_idx;
        reloc_desc->sym_off = sym->st_value;
        return 0;
    }

    if (!shdr_idx || shdr_idx >= SHN_LORESERVE)
    {
        pr_warn("prog '%s': invalid relo against '%s' in special section 0x%x; forgot to initialize global var?..\n",
                prog->name, sym_name, shdr_idx);
        return -LIBBPF_ERRNO__RELOC;
    }

    /* loading subprog addresses */
    if (sym_is_subprog(sym, obj->efile.text_shndx))
    {
        /* global_func: sym->st_value = offset in the section, insn->imm = 0.
         * local_func: sym->st_value = 0, insn->imm = offset in the section.
         */
        if ((sym->st_value % BPF_INSN_SZ) || (insn->imm % BPF_INSN_SZ))
        {
            pr_warn("prog '%s': bad subprog addr relo against '%s' at offset %zu+%d\n",
                    prog->name, sym_name, (size_t)sym->st_value, insn->imm);
            return -LIBBPF_ERRNO__RELOC;
        }

        reloc_desc->type = RELO_SUBPROG_ADDR;
        reloc_desc->insn_idx = insn_idx;
        reloc_desc->sym_off = sym->st_value;
        return 0;
    }

    type = bpf_object__section_to_libbpf_map_type(obj, shdr_idx);
    sym_sec_name = elf_sec_name(obj, elf_sec_by_idx(obj, shdr_idx));

    /* generic map reference relocation */
    if (type == LIBBPF_MAP_UNSPEC)
    {
        if (!bpf_object__shndx_is_maps(obj, shdr_idx))
        {
            pr_warn("prog '%s': bad map relo against '%s' in section '%s'\n",
                    prog->name, sym_name, sym_sec_name);
            return -LIBBPF_ERRNO__RELOC;
        }
        for (map_idx = 0; map_idx < nr_maps; map_idx++)
        {
            map = &obj->maps[map_idx];
            if (map->libbpf_type != type ||
                map->sec_idx != sym->st_shndx ||
                map->sec_offset != sym->st_value)
                continue;
            pr_debug("prog '%s': found map %zd (%s, sec %d, off %zu) for insn #%u\n",
                     prog->name, map_idx, map->name, map->sec_idx,
                     map->sec_offset, insn_idx);
            break;
        }
        if (map_idx >= nr_maps)
        {
            pr_warn("prog '%s': map relo failed to find map for section '%s', off %zu\n",
                    prog->name, sym_sec_name, (size_t)sym->st_value);
            return -LIBBPF_ERRNO__RELOC;
        }
        reloc_desc->type = RELO_LD64;
        reloc_desc->insn_idx = insn_idx;
        reloc_desc->map_idx = map_idx;
        reloc_desc->sym_off = 0; /* sym->st_value determines map_idx */
        return 0;
    }

    /* global data map relocation */
    if (!bpf_object__shndx_is_data(obj, shdr_idx))
    {
        pr_warn("prog '%s': bad data relo against section '%s'\n",
                prog->name, sym_sec_name);
        return -LIBBPF_ERRNO__RELOC;
    }
    for (map_idx = 0; map_idx < nr_maps; map_idx++)
    {
        map = &obj->maps[map_idx];
        if (map->libbpf_type != type || map->sec_idx != sym->st_shndx)
            continue;
        pr_debug("prog '%s': found data map %zd (%s, sec %d, off %zu) for insn %u\n",
                 prog->name, map_idx, map->name, map->sec_idx,
                 map->sec_offset, insn_idx);
        break;
    }
    if (map_idx >= nr_maps)
    {
        pr_warn("prog '%s': data relo failed to find map for section '%s'\n",
                prog->name, sym_sec_name);
        return -LIBBPF_ERRNO__RELOC;
    }

    reloc_desc->type = RELO_DATA;
    reloc_desc->insn_idx = insn_idx;
    reloc_desc->map_idx = map_idx;
    reloc_desc->sym_off = sym->st_value;
    return 0;
}

static bool prog_contains_insn(const struct bpf_program *prog, size_t insn_idx)
{
	return insn_idx >= prog->sec_insn_off &&
	       insn_idx < prog->sec_insn_off + prog->sec_insn_cnt;
}

static struct bpf_program *find_prog_by_sec_insn(const struct bpf_object *obj,
						 size_t sec_idx, size_t insn_idx)
{
	int l = 0, r = obj->nr_programs - 1, m;
	struct bpf_program *prog;

	if (!obj->nr_programs)
		return NULL;

	while (l < r) {
		m = l + (r - l + 1) / 2;
		prog = &obj->programs[m];

		if (prog->sec_idx < sec_idx ||
		    (prog->sec_idx == sec_idx && prog->sec_insn_off <= insn_idx))
			l = m;
		else
			r = m - 1;
	}
	/* matching program could be at index l, but it still might be the
	 * wrong one, so we need to double check conditions for the last time
	 */
	prog = &obj->programs[l];
	if (prog->sec_idx == sec_idx && prog_contains_insn(prog, insn_idx))
		return prog;
	return NULL;
}

static int
bpf_object__collect_prog_relos(struct bpf_object *obj, Elf64_Shdr *shdr, Elf_Data *data)
{
	const char *relo_sec_name, *sec_name;
	size_t sec_idx = shdr->sh_info, sym_idx;
	struct bpf_program *prog;
	struct reloc_desc *relos;
	int err, i, nrels;
	const char *sym_name;
	__u32 insn_idx;
	Elf_Scn *scn;
	Elf_Data *scn_data;
	Elf64_Sym *sym;
	Elf64_Rel *rel;

	if (sec_idx >= obj->efile.sec_cnt)
		return -EINVAL;

	scn = elf_sec_by_idx(obj, sec_idx);
	scn_data = elf_sec_data(obj, scn);

	relo_sec_name = elf_sec_str(obj, shdr->sh_name);
	sec_name = elf_sec_name(obj, scn);
	if (!relo_sec_name || !sec_name)
		return -EINVAL;

	pr_debug("sec '%s': collecting relocation for section(%zu) '%s'\n",
		 relo_sec_name, sec_idx, sec_name);
	nrels = shdr->sh_size / shdr->sh_entsize;

	for (i = 0; i < nrels; i++) {
		rel = elf_rel_by_idx(data, i);
		if (!rel) {
			pr_warn("sec '%s': failed to get relo #%d\n", relo_sec_name, i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		sym_idx = ELF64_R_SYM(rel->r_info);
		sym = elf_sym_by_idx(obj, sym_idx);
		if (!sym) {
			pr_warn("sec '%s': symbol #%zu not found for relo #%d\n",
				relo_sec_name, sym_idx, i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		if (sym->st_shndx >= obj->efile.sec_cnt) {
			pr_warn("sec '%s': corrupted symbol #%zu pointing to invalid section #%zu for relo #%d\n",
				relo_sec_name, sym_idx, (size_t)sym->st_shndx, i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		if (rel->r_offset % BPF_INSN_SZ || rel->r_offset >= scn_data->d_size) {
			pr_warn("sec '%s': invalid offset 0x%zx for relo #%d\n",
				relo_sec_name, (size_t)rel->r_offset, i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		insn_idx = rel->r_offset / BPF_INSN_SZ;
		/* relocations against static functions are recorded as
		 * relocations against the section that contains a function;
		 * in such case, symbol will be STT_SECTION and sym.st_name
		 * will point to empty string (0), so fetch section name
		 * instead
		 */
		if (ELF64_ST_TYPE(sym->st_info) == STT_SECTION && sym->st_name == 0)
			sym_name = elf_sec_name(obj, elf_sec_by_idx(obj, sym->st_shndx));
		else
			sym_name = elf_sym_str(obj, sym->st_name);
		sym_name = sym_name ?: "<?";

		pr_debug("sec '%s': relo #%d: insn #%u against '%s'\n",
			 relo_sec_name, i, insn_idx, sym_name);

		prog = find_prog_by_sec_insn(obj, sec_idx, insn_idx);
		if (!prog) {
			pr_debug("sec '%s': relo #%d: couldn't find program in section '%s' for insn #%u, probably overridden weak function, skipping...\n",
				relo_sec_name, i, sec_name, insn_idx);
			continue;
		}

		relos = libbpf_reallocarray(prog->reloc_desc,
					    prog->nr_reloc + 1, sizeof(*relos));
		if (!relos)
			return -ENOMEM;
		prog->reloc_desc = relos;

		/* adjust insn_idx to local BPF program frame of reference */
		insn_idx -= prog->sec_insn_off;
		err = bpf_program__record_reloc(prog, &relos[prog->nr_reloc],
						insn_idx, sym_name, sym, rel);
		if (err)
			return err;

		prog->nr_reloc++;
	}
	return 0;
}

static int map_fill_btf_type_info(struct bpf_object *obj, struct bpf_map *map)
{
	int id;

	if (!obj->btf)
		return -ENOENT;

	/* if it's BTF-defined map, we don't need to search for type IDs.
	 * For struct_ops map, it does not need btf_key_type_id and
	 * btf_value_type_id.
	 */
	if (map->sec_idx == obj->efile.btf_maps_shndx || bpf_map__is_struct_ops(map))
		return 0;

	/*
	 * LLVM annotates global data differently in BTF, that is,
	 * only as '.data', '.bss' or '.rodata'.
	 */
	if (!bpf_map__is_internal(map))
		return -ENOENT;

	id = btf__find_by_name(obj->btf, map->real_name);
	if (id < 0)
		return id;

	map->btf_key_type_id = 0;
	map->btf_value_type_id = id;
	return 0;
}

static int bpf_get_map_info_from_fdinfo(int fd, struct bpf_map_info *info)
{
	char file[PATH_MAX], buff[4096];
	FILE *fp;
	__u32 val;
	int err;

	snprintf(file, sizeof(file), "/proc/%d/fdinfo/%d", getpid(), fd);
	memset(info, 0, sizeof(*info));

	fp = fopen(file, "r");
	if (!fp) {
		err = -errno;
		pr_warn("failed to open %s: %d. No procfs support?\n", file,
			err);
		return err;
	}

	while (fgets(buff, sizeof(buff), fp)) {
		if (sscanf(buff, "map_type:\t%u", &val) == 1)
			info->type = val;
		else if (sscanf(buff, "key_size:\t%u", &val) == 1)
			info->key_size = val;
		else if (sscanf(buff, "value_size:\t%u", &val) == 1)
			info->value_size = val;
		else if (sscanf(buff, "max_entries:\t%u", &val) == 1)
			info->max_entries = val;
		else if (sscanf(buff, "map_flags:\t%i", &val) == 1)
			info->map_flags = val;
	}

	fclose(fp);

	return 0;
}

bool bpf_map__autocreate(const struct bpf_map *map)
{
	return map->autocreate;
}

int bpf_map__set_autocreate(struct bpf_map *map, bool autocreate)
{
	if (map->obj->loaded)
		return libbpf_err(-EBUSY);

	map->autocreate = autocreate;
	return 0;
}

int bpf_map__reuse_fd(struct bpf_map *map, int fd)
{
	struct bpf_map_info info;
	__u32 len = sizeof(info), name_len;
	int new_fd, err;
	char *new_name;

	memset(&info, 0, len);
	err = bpf_map_get_info_by_fd(fd, &info, &len);
	if (err && errno == EINVAL)
		err = bpf_get_map_info_from_fdinfo(fd, &info);
	if (err)
		return libbpf_err(err);

	name_len = strlen(info.name);
	if (name_len == BPF_OBJ_NAME_LEN - 1 && strncmp(map->name, info.name, name_len) == 0)
		new_name = strdup(map->name);
	else
		new_name = strdup(info.name);

	if (!new_name)
		return libbpf_err(-errno);

	new_fd = open("/", O_RDONLY | O_CLOEXEC);
	if (new_fd < 0) {
		err = -errno;
		goto err_free_new_name;
	}

	new_fd = dup3(fd, new_fd, O_CLOEXEC);
	if (new_fd < 0) {
		err = -errno;
		goto err_close_new_fd;
	}

	err = zclose(map->fd);
	if (err) {
		err = -errno;
		goto err_close_new_fd;
	}
	free(map->name);

	map->fd = new_fd;
	map->name = new_name;
	map->def.type = info.type;
	map->def.key_size = info.key_size;
	map->def.value_size = info.value_size;
	map->def.max_entries = info.max_entries;
	map->def.map_flags = info.map_flags;
	map->btf_key_type_id = info.btf_key_type_id;
	map->btf_value_type_id = info.btf_value_type_id;
	map->reused = true;
	map->map_extra = info.map_extra;

	return 0;

err_close_new_fd:
	close(new_fd);
err_free_new_name:
	free(new_name);
	return libbpf_err(err);
}

__u32 bpf_map__max_entries(const struct bpf_map *map)
{
	return map->def.max_entries;
}

struct bpf_map *bpf_map__inner_map(struct bpf_map *map)
{
	if (!bpf_map_type__is_map_in_map(map->def.type))
		return errno = EINVAL, NULL;

	return map->inner_map;
}

int bpf_map__set_max_entries(struct bpf_map *map, __u32 max_entries)
{
	if (map->obj->loaded)
		return libbpf_err(-EBUSY);

	map->def.max_entries = max_entries;

	/* auto-adjust BPF ringbuf map max_entries to be a multiple of page size */
	if (map_is_ringbuf(map))
		map->def.max_entries = adjust_ringbuf_sz(map->def.max_entries);

	return 0;
}

static int
bpf_object__probe_loading(struct bpf_object *obj)
{
	char *cp, errmsg[STRERR_BUFSIZE];
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int ret, insn_cnt = ARRAY_SIZE(insns);

	if (obj->gen_loader)
		return 0;

	ret = bump_rlimit_memlock();
	if (ret)
		pr_warn("Failed to bump RLIMIT_MEMLOCK (err = %d), you might need to do it explicitly!\n", ret);

	/* make sure basic loading works */
	ret = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL", insns, insn_cnt, NULL);
	if (ret < 0)
		ret = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, NULL, "GPL", insns, insn_cnt, NULL);
	if (ret < 0) {
		ret = errno;
		cp = libbpf_strerror_r(ret, errmsg, sizeof(errmsg));
		pr_warn("Error in %s():%s(%d). Couldn't load trivial BPF "
			"program. Make sure your kernel supports BPF "
			"(CONFIG_BPF_SYSCALL=y) and/or that RLIMIT_MEMLOCK is "
			"set to big enough value.\n", __func__, cp, ret);
		return -ret;
	}
	close(ret);

	return 0;
}

static int probe_fd(int fd)
{
	if (fd >= 0)
		close(fd);
	return fd >= 0;
}

static int probe_kern_prog_name(void)
{
	const size_t attr_sz = offsetofend(union bpf_attr, prog_name);
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.license = ptr_to_u64("GPL");
	attr.insns = ptr_to_u64(insns);
	attr.insn_cnt = (__u32)ARRAY_SIZE(insns);
	libbpf_strlcpy(attr.prog_name, "libbpf_nametest", sizeof(attr.prog_name));

	/* make sure loading with name works */
	ret = sys_bpf_prog_load(&attr, attr_sz, PROG_LOAD_ATTEMPTS);
	return probe_fd(ret);
}

static int probe_kern_global_data(void)
{
	char *cp, errmsg[STRERR_BUFSIZE];
	struct bpf_insn insns[] = {
		BPF_LD_MAP_VALUE(BPF_REG_1, 0, 16),
		BPF_ST_MEM(BPF_DW, BPF_REG_1, 0, 42),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int ret, map, insn_cnt = ARRAY_SIZE(insns);

	map = bpf_map_create(BPF_MAP_TYPE_ARRAY, "libbpf_global", sizeof(int), 32, 1, NULL);
	if (map < 0) {
		ret = -errno;
		cp = libbpf_strerror_r(ret, errmsg, sizeof(errmsg));
		pr_warn("Error in %s():%s(%d). Couldn't create simple array map.\n",
			__func__, cp, -ret);
		return ret;
	}

	insns[0].imm = map;

	ret = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL", insns, insn_cnt, NULL);
	close(map);
	return probe_fd(ret);
}

static int probe_kern_btf(void)
{
	static const char strs[] = "\0int";
	__u32 types[] = {
		/* int */
		BTF_TYPE_INT_ENC(1, BTF_INT_SIGNED, 0, 32, 4),
	};

	return probe_fd(libbpf__load_raw_btf((char *)types, sizeof(types),
					     strs, sizeof(strs)));
}

static int probe_kern_btf_func(void)
{
	static const char strs[] = "\0int\0x\0a";
	/* void x(int a) {} */
	__u32 types[] = {
		/* int */
		BTF_TYPE_INT_ENC(1, BTF_INT_SIGNED, 0, 32, 4),  /* [1] */
		/* FUNC_PROTO */                                /* [2] */
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_FUNC_PROTO, 0, 1), 0),
		BTF_PARAM_ENC(7, 1),
		/* FUNC x */                                    /* [3] */
		BTF_TYPE_ENC(5, BTF_INFO_ENC(BTF_KIND_FUNC, 0, 0), 2),
	};

	return probe_fd(libbpf__load_raw_btf((char *)types, sizeof(types),
					     strs, sizeof(strs)));
}

static int probe_kern_btf_func_global(void)
{
	static const char strs[] = "\0int\0x\0a";
	/* static void x(int a) {} */
	__u32 types[] = {
		/* int */
		BTF_TYPE_INT_ENC(1, BTF_INT_SIGNED, 0, 32, 4),  /* [1] */
		/* FUNC_PROTO */                                /* [2] */
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_FUNC_PROTO, 0, 1), 0),
		BTF_PARAM_ENC(7, 1),
		/* FUNC x BTF_FUNC_GLOBAL */                    /* [3] */
		BTF_TYPE_ENC(5, BTF_INFO_ENC(BTF_KIND_FUNC, 0, BTF_FUNC_GLOBAL), 2),
	};

	return probe_fd(libbpf__load_raw_btf((char *)types, sizeof(types),
					     strs, sizeof(strs)));
}

static int probe_kern_btf_datasec(void)
{
	static const char strs[] = "\0x\0.data";
	/* static int a; */
	__u32 types[] = {
		/* int */
		BTF_TYPE_INT_ENC(0, BTF_INT_SIGNED, 0, 32, 4),  /* [1] */
		/* VAR x */                                     /* [2] */
		BTF_TYPE_ENC(1, BTF_INFO_ENC(BTF_KIND_VAR, 0, 0), 1),
		BTF_VAR_STATIC,
		/* DATASEC val */                               /* [3] */
		BTF_TYPE_ENC(3, BTF_INFO_ENC(BTF_KIND_DATASEC, 0, 1), 4),
		BTF_VAR_SECINFO_ENC(2, 0, 4),
	};

	return probe_fd(libbpf__load_raw_btf((char *)types, sizeof(types),
					     strs, sizeof(strs)));
}

static int probe_kern_btf_float(void)
{
	static const char strs[] = "\0float";
	__u32 types[] = {
		/* float */
		BTF_TYPE_FLOAT_ENC(1, 4),
	};

	return probe_fd(libbpf__load_raw_btf((char *)types, sizeof(types),
					     strs, sizeof(strs)));
}

static int probe_kern_btf_decl_tag(void)
{
	static const char strs[] = "\0tag";
	__u32 types[] = {
		/* int */
		BTF_TYPE_INT_ENC(0, BTF_INT_SIGNED, 0, 32, 4),  /* [1] */
		/* VAR x */                                     /* [2] */
		BTF_TYPE_ENC(1, BTF_INFO_ENC(BTF_KIND_VAR, 0, 0), 1),
		BTF_VAR_STATIC,
		/* attr */
		BTF_TYPE_DECL_TAG_ENC(1, 2, -1),
	};

	return probe_fd(libbpf__load_raw_btf((char *)types, sizeof(types),
					     strs, sizeof(strs)));
}

static int probe_kern_btf_type_tag(void)
{
	static const char strs[] = "\0tag";
	__u32 types[] = {
		/* int */
		BTF_TYPE_INT_ENC(0, BTF_INT_SIGNED, 0, 32, 4),		/* [1] */
		/* attr */
		BTF_TYPE_TYPE_TAG_ENC(1, 1),				/* [2] */
		/* ptr */
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_PTR, 0, 0), 2),	/* [3] */
	};

	return probe_fd(libbpf__load_raw_btf((char *)types, sizeof(types),
					     strs, sizeof(strs)));
}

static int probe_kern_array_mmap(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE);
	int fd;

	fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "libbpf_mmap", sizeof(int), sizeof(int), 1, &opts);
	return probe_fd(fd);
}

static int probe_kern_exp_attach_type(void)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .expected_attach_type = BPF_CGROUP_INET_SOCK_CREATE);
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int fd, insn_cnt = ARRAY_SIZE(insns);

	/* use any valid combination of program type and (optional)
	 * non-zero expected attach type (i.e., not a BPF_CGROUP_INET_INGRESS)
	 * to see if kernel supports expected_attach_type field for
	 * BPF_PROG_LOAD command
	 */
	fd = bpf_prog_load(BPF_PROG_TYPE_CGROUP_SOCK, NULL, "GPL", insns, insn_cnt, &opts);
	return probe_fd(fd);
}
