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

static int probe_kern_probe_read_kernel(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),	/* r1 = r10 (fp) */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),	/* r1 += -8 */
		BPF_MOV64_IMM(BPF_REG_2, 8),		/* r2 = 8 */
		BPF_MOV64_IMM(BPF_REG_3, 0),		/* r3 = 0 */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_probe_read_kernel),
		BPF_EXIT_INSN(),
	};
	int fd, insn_cnt = ARRAY_SIZE(insns);

	fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, NULL, "GPL", insns, insn_cnt, NULL);
	return probe_fd(fd);
}

static int probe_prog_bind_map(void)
{
	char *cp, errmsg[STRERR_BUFSIZE];
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int ret, map, prog, insn_cnt = ARRAY_SIZE(insns);

	map = bpf_map_create(BPF_MAP_TYPE_ARRAY, "libbpf_det_bind", sizeof(int), 32, 1, NULL);
	if (map < 0) {
		ret = -errno;
		cp = libbpf_strerror_r(ret, errmsg, sizeof(errmsg));
		pr_warn("Error in %s():%s(%d). Couldn't create simple array map.\n",
			__func__, cp, -ret);
		return ret;
	}

	prog = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL", insns, insn_cnt, NULL);
	if (prog < 0) {
		close(map);
		return 0;
	}

	ret = bpf_prog_bind_map(prog, map, NULL);

	close(map);
	close(prog);

	return ret >= 0;
}

static int probe_module_btf(void)
{
	static const char strs[] = "\0int";
	__u32 types[] = {
		/* int */
		BTF_TYPE_INT_ENC(1, BTF_INT_SIGNED, 0, 32, 4),
	};
	struct bpf_btf_info info;
	__u32 len = sizeof(info);
	char name[16];
	int fd, err;

	fd = libbpf__load_raw_btf((char *)types, sizeof(types), strs, sizeof(strs));
	if (fd < 0)
		return 0; /* BTF not supported at all */

	memset(&info, 0, sizeof(info));
	info.name = ptr_to_u64(name);
	info.name_len = sizeof(name);

	/* check that BPF_OBJ_GET_INFO_BY_FD supports specifying name pointer;
	 * kernel's module BTF support coincides with support for
	 * name/name_len fields in struct bpf_btf_info.
	 */
	err = bpf_btf_get_info_by_fd(fd, &info, &len);
	close(fd);
	return !err;
}

static int probe_perf_link(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd, link_fd, err;

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, NULL, "GPL",
				insns, ARRAY_SIZE(insns), NULL);
	if (prog_fd < 0)
		return -errno;

	/* use invalid perf_event FD to get EBADF, if link is supported;
	 * otherwise EINVAL should be returned
	 */
	link_fd = bpf_link_create(prog_fd, -1, BPF_PERF_EVENT, NULL);
	err = -errno; /* close() can clobber errno */

	if (link_fd >= 0)
		close(link_fd);
	close(prog_fd);

	return link_fd < 0 && err == -EBADF;
}

static int probe_kern_bpf_cookie(void)
{
	struct bpf_insn insns[] = {
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_attach_cookie),
		BPF_EXIT_INSN(),
	};
	int ret, insn_cnt = ARRAY_SIZE(insns);

	ret = bpf_prog_load(BPF_PROG_TYPE_KPROBE, NULL, "GPL", insns, insn_cnt, NULL);
	return probe_fd(ret);
}

static int probe_kern_btf_enum64(void)
{
	static const char strs[] = "\0enum64";
	__u32 types[] = {
		BTF_TYPE_ENC(1, BTF_INFO_ENC(BTF_KIND_ENUM64, 0, 0), 8),
	};

	return probe_fd(libbpf__load_raw_btf((char *)types, sizeof(types),
					     strs, sizeof(strs)));
}

static int probe_kern_syscall_wrapper(void);

enum kern_feature_result {
	FEAT_UNKNOWN = 0,
	FEAT_SUPPORTED = 1,
	FEAT_MISSING = 2,
};

typedef int (*feature_probe_fn)(void);

static struct kern_feature_desc {
	const char *desc;
	feature_probe_fn probe;
	enum kern_feature_result res;
} feature_probes[__FEAT_CNT] = {
	[FEAT_PROG_NAME] = {
		"BPF program name", probe_kern_prog_name,
	},
	[FEAT_GLOBAL_DATA] = {
		"global variables", probe_kern_global_data,
	},
	[FEAT_BTF] = {
		"minimal BTF", probe_kern_btf,
	},
	[FEAT_BTF_FUNC] = {
		"BTF functions", probe_kern_btf_func,
	},
	[FEAT_BTF_GLOBAL_FUNC] = {
		"BTF global function", probe_kern_btf_func_global,
	},
	[FEAT_BTF_DATASEC] = {
		"BTF data section and variable", probe_kern_btf_datasec,
	},
	[FEAT_ARRAY_MMAP] = {
		"ARRAY map mmap()", probe_kern_array_mmap,
	},
	[FEAT_EXP_ATTACH_TYPE] = {
		"BPF_PROG_LOAD expected_attach_type attribute",
		probe_kern_exp_attach_type,
	},
	[FEAT_PROBE_READ_KERN] = {
		"bpf_probe_read_kernel() helper", probe_kern_probe_read_kernel,
	},
	[FEAT_PROG_BIND_MAP] = {
		"BPF_PROG_BIND_MAP support", probe_prog_bind_map,
	},
	[FEAT_MODULE_BTF] = {
		"module BTF support", probe_module_btf,
	},
	[FEAT_BTF_FLOAT] = {
		"BTF_KIND_FLOAT support", probe_kern_btf_float,
	},
	[FEAT_PERF_LINK] = {
		"BPF perf link support", probe_perf_link,
	},
	[FEAT_BTF_DECL_TAG] = {
		"BTF_KIND_DECL_TAG support", probe_kern_btf_decl_tag,
	},
	[FEAT_BTF_TYPE_TAG] = {
		"BTF_KIND_TYPE_TAG support", probe_kern_btf_type_tag,
	},
	[FEAT_MEMCG_ACCOUNT] = {
		"memcg-based memory accounting", probe_memcg_account,
	},
	[FEAT_BPF_COOKIE] = {
		"BPF cookie support", probe_kern_bpf_cookie,
	},
	[FEAT_BTF_ENUM64] = {
		"BTF_KIND_ENUM64 support", probe_kern_btf_enum64,
	},
	[FEAT_SYSCALL_WRAPPER] = {
		"Kernel using syscall wrapper", probe_kern_syscall_wrapper,
	},
};

bool kernel_supports(const struct bpf_object *obj, enum kern_feature_id feat_id)
{
	struct kern_feature_desc *feat = &feature_probes[feat_id];
	int ret;

	if (obj && obj->gen_loader)
		/* To generate loader program assume the latest kernel
		 * to avoid doing extra prog_load, map_create syscalls.
		 */
		return true;

	if (READ_ONCE(feat->res) == FEAT_UNKNOWN) {
		ret = feat->probe();
		if (ret > 0) {
			WRITE_ONCE(feat->res, FEAT_SUPPORTED);
		} else if (ret == 0) {
			WRITE_ONCE(feat->res, FEAT_MISSING);
		} else {
			pr_warn("Detection of kernel %s support failed: %d\n", feat->desc, ret);
			WRITE_ONCE(feat->res, FEAT_MISSING);
		}
	}

	return READ_ONCE(feat->res) == FEAT_SUPPORTED;
}

static bool map_is_reuse_compat(const struct bpf_map *map, int map_fd)
{
	struct bpf_map_info map_info;
	char msg[STRERR_BUFSIZE];
	__u32 map_info_len = sizeof(map_info);
	int err;

	memset(&map_info, 0, map_info_len);
	err = bpf_map_get_info_by_fd(map_fd, &map_info, &map_info_len);
	if (err && errno == EINVAL)
		err = bpf_get_map_info_from_fdinfo(map_fd, &map_info);
	if (err) {
		pr_warn("failed to get map info for map FD %d: %s\n", map_fd,
			libbpf_strerror_r(errno, msg, sizeof(msg)));
		return false;
	}

	return (map_info.type == map->def.type &&
		map_info.key_size == map->def.key_size &&
		map_info.value_size == map->def.value_size &&
		map_info.max_entries == map->def.max_entries &&
		map_info.map_flags == map->def.map_flags &&
		map_info.map_extra == map->map_extra);
}

static int
bpf_object__reuse_map(struct bpf_map *map)
{
	char *cp, errmsg[STRERR_BUFSIZE];
	int err, pin_fd;

	pin_fd = bpf_obj_get(map->pin_path);
	if (pin_fd < 0) {
		err = -errno;
		if (err == -ENOENT) {
			pr_debug("found no pinned map to reuse at '%s'\n",
				 map->pin_path);
			return 0;
		}

		cp = libbpf_strerror_r(-err, errmsg, sizeof(errmsg));
		pr_warn("couldn't retrieve pinned map '%s': %s\n",
			map->pin_path, cp);
		return err;
	}

	if (!map_is_reuse_compat(map, pin_fd)) {
		pr_warn("couldn't reuse pinned map at '%s': parameter mismatch\n",
			map->pin_path);
		close(pin_fd);
		return -EINVAL;
	}

	err = bpf_map__reuse_fd(map, pin_fd);
	close(pin_fd);
	if (err)
		return err;

	map->pinned = true;
	pr_debug("reused pinned map at '%s'\n", map->pin_path);

	return 0;
}

static int
bpf_object__populate_internal_map(struct bpf_object *obj, struct bpf_map *map)
{
	enum libbpf_map_type map_type = map->libbpf_type;
	char *cp, errmsg[STRERR_BUFSIZE];
	int err, zero = 0;

	if (obj->gen_loader) {
		bpf_gen__map_update_elem(obj->gen_loader, map - obj->maps,
					 map->mmaped, map->def.value_size);
		if (map_type == LIBBPF_MAP_RODATA || map_type == LIBBPF_MAP_KCONFIG)
			bpf_gen__map_freeze(obj->gen_loader, map - obj->maps);
		return 0;
	}
	err = bpf_map_update_elem(map->fd, &zero, map->mmaped, 0);
	if (err) {
		err = -errno;
		cp = libbpf_strerror_r(err, errmsg, sizeof(errmsg));
		pr_warn("Error setting initial map(%s) contents: %s\n",
			map->name, cp);
		return err;
	}

	/* Freeze .rodata and .kconfig map as read-only from syscall side. */
	if (map_type == LIBBPF_MAP_RODATA || map_type == LIBBPF_MAP_KCONFIG) {
		err = bpf_map_freeze(map->fd);
		if (err) {
			err = -errno;
			cp = libbpf_strerror_r(err, errmsg, sizeof(errmsg));
			pr_warn("Error freezing map(%s) as read-only: %s\n",
				map->name, cp);
			return err;
		}
	}
	return 0;
}

static void bpf_map__destroy(struct bpf_map *map);

static int bpf_object__create_map(struct bpf_object *obj, struct bpf_map *map, bool is_inner)
{
	LIBBPF_OPTS(bpf_map_create_opts, create_attr);
	struct bpf_map_def *def = &map->def;
	const char *map_name = NULL;
	int err = 0;

	if (kernel_supports(obj, FEAT_PROG_NAME))
		map_name = map->name;
	create_attr.map_ifindex = map->map_ifindex;
	create_attr.map_flags = def->map_flags;
	create_attr.numa_node = map->numa_node;
	create_attr.map_extra = map->map_extra;

	if (bpf_map__is_struct_ops(map))
		create_attr.btf_vmlinux_value_type_id = map->btf_vmlinux_value_type_id;

	if (obj->btf && btf__fd(obj->btf) >= 0) {
		create_attr.btf_fd = btf__fd(obj->btf);
		create_attr.btf_key_type_id = map->btf_key_type_id;
		create_attr.btf_value_type_id = map->btf_value_type_id;
	}

	if (bpf_map_type__is_map_in_map(def->type)) {
		if (map->inner_map) {
			err = bpf_object__create_map(obj, map->inner_map, true);
			if (err) {
				pr_warn("map '%s': failed to create inner map: %d\n",
					map->name, err);
				return err;
			}
			map->inner_map_fd = bpf_map__fd(map->inner_map);
		}
		if (map->inner_map_fd >= 0)
			create_attr.inner_map_fd = map->inner_map_fd;
	}

	switch (def->type) {
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
	case BPF_MAP_TYPE_CGROUP_ARRAY:
	case BPF_MAP_TYPE_STACK_TRACE:
	case BPF_MAP_TYPE_ARRAY_OF_MAPS:
	case BPF_MAP_TYPE_HASH_OF_MAPS:
	case BPF_MAP_TYPE_DEVMAP:
	case BPF_MAP_TYPE_DEVMAP_HASH:
	case BPF_MAP_TYPE_CPUMAP:
	case BPF_MAP_TYPE_XSKMAP:
	case BPF_MAP_TYPE_SOCKMAP:
	case BPF_MAP_TYPE_SOCKHASH:
	case BPF_MAP_TYPE_QUEUE:
	case BPF_MAP_TYPE_STACK:
		create_attr.btf_fd = 0;
		create_attr.btf_key_type_id = 0;
		create_attr.btf_value_type_id = 0;
		map->btf_key_type_id = 0;
		map->btf_value_type_id = 0;
	default:
		break;
	}

	if (obj->gen_loader) {
		bpf_gen__map_create(obj->gen_loader, def->type, map_name,
				    def->key_size, def->value_size, def->max_entries,
				    &create_attr, is_inner ? -1 : map - obj->maps);
		/* Pretend to have valid FD to pass various fd >= 0 checks.
		 * This fd == 0 will not be used with any syscall and will be reset to -1 eventually.
		 */
		map->fd = 0;
	} else {
		map->fd = bpf_map_create(def->type, map_name,
					 def->key_size, def->value_size,
					 def->max_entries, &create_attr);
	}
	if (map->fd < 0 && (create_attr.btf_key_type_id ||
			    create_attr.btf_value_type_id)) {
		char *cp, errmsg[STRERR_BUFSIZE];

		err = -errno;
		cp = libbpf_strerror_r(err, errmsg, sizeof(errmsg));
		pr_warn("Error in bpf_create_map_xattr(%s):%s(%d). Retrying without BTF.\n",
			map->name, cp, err);
		create_attr.btf_fd = 0;
		create_attr.btf_key_type_id = 0;
		create_attr.btf_value_type_id = 0;
		map->btf_key_type_id = 0;
		map->btf_value_type_id = 0;
		map->fd = bpf_map_create(def->type, map_name,
					 def->key_size, def->value_size,
					 def->max_entries, &create_attr);
	}

	err = map->fd < 0 ? -errno : 0;

	if (bpf_map_type__is_map_in_map(def->type) && map->inner_map) {
		if (obj->gen_loader)
			map->inner_map->fd = -1;
		bpf_map__destroy(map->inner_map);
		zfree(&map->inner_map);
	}

	return err;
}

static int init_map_in_map_slots(struct bpf_object *obj, struct bpf_map *map)
{
	const struct bpf_map *targ_map;
	unsigned int i;
	int fd, err = 0;

	for (i = 0; i < map->init_slots_sz; i++) {
		if (!map->init_slots[i])
			continue;

		targ_map = map->init_slots[i];
		fd = bpf_map__fd(targ_map);

		if (obj->gen_loader) {
			bpf_gen__populate_outer_map(obj->gen_loader,
						    map - obj->maps, i,
						    targ_map - obj->maps);
		} else {
			err = bpf_map_update_elem(map->fd, &i, &fd, 0);
		}
		if (err) {
			err = -errno;
			pr_warn("map '%s': failed to initialize slot [%d] to map '%s' fd=%d: %d\n",
				map->name, i, targ_map->name, fd, err);
			return err;
		}
		pr_debug("map '%s': slot [%d] set to map '%s' fd=%d\n",
			 map->name, i, targ_map->name, fd);
	}

	zfree(&map->init_slots);
	map->init_slots_sz = 0;

	return 0;
}

static int init_prog_array_slots(struct bpf_object *obj, struct bpf_map *map)
{
	const struct bpf_program *targ_prog;
	unsigned int i;
	int fd, err;

	if (obj->gen_loader)
		return -ENOTSUP;

	for (i = 0; i < map->init_slots_sz; i++) {
		if (!map->init_slots[i])
			continue;

		targ_prog = map->init_slots[i];
		fd = bpf_program__fd(targ_prog);

		err = bpf_map_update_elem(map->fd, &i, &fd, 0);
		if (err) {
			err = -errno;
			pr_warn("map '%s': failed to initialize slot [%d] to prog '%s' fd=%d: %d\n",
				map->name, i, targ_prog->name, fd, err);
			return err;
		}
		pr_debug("map '%s': slot [%d] set to prog '%s' fd=%d\n",
			 map->name, i, targ_prog->name, fd);
	}

	zfree(&map->init_slots);
	map->init_slots_sz = 0;

	return 0;
}

static int bpf_object_init_prog_arrays(struct bpf_object *obj)
{
	struct bpf_map *map;
	int i, err;

	for (i = 0; i < obj->nr_maps; i++) {
		map = &obj->maps[i];

		if (!map->init_slots_sz || map->def.type != BPF_MAP_TYPE_PROG_ARRAY)
			continue;

		err = init_prog_array_slots(obj, map);
		if (err < 0) {
			zclose(map->fd);
			return err;
		}
	}
	return 0;
}

static int map_set_def_max_entries(struct bpf_map *map)
{
	if (map->def.type == BPF_MAP_TYPE_PERF_EVENT_ARRAY && !map->def.max_entries) {
		int nr_cpus;

		nr_cpus = libbpf_num_possible_cpus();
		if (nr_cpus < 0) {
			pr_warn("map '%s': failed to determine number of system CPUs: %d\n",
				map->name, nr_cpus);
			return nr_cpus;
		}
		pr_debug("map '%s': setting size to %d\n", map->name, nr_cpus);
		map->def.max_entries = nr_cpus;
	}

	return 0;
}

static int
bpf_object__create_maps(struct bpf_object *obj)
{
	struct bpf_map *map;
	char *cp, errmsg[STRERR_BUFSIZE];
	unsigned int i, j;
	int err;
	bool retried;

	for (i = 0; i < obj->nr_maps; i++) {
		map = &obj->maps[i];

		if (bpf_map__is_internal(map) && !kernel_supports(obj, FEAT_GLOBAL_DATA))
			map->autocreate = false;

		if (!map->autocreate) {
			pr_debug("map '%s': skipped auto-creating...\n", map->name);
			continue;
		}

		err = map_set_def_max_entries(map);
		if (err)
			goto err_out;

		retried = false;
retry:
		if (map->pin_path) {
			err = bpf_object__reuse_map(map);
			if (err) {
				pr_warn("map '%s': error reusing pinned map\n",
					map->name);
				goto err_out;
			}
			if (retried && map->fd < 0) {
				pr_warn("map '%s': cannot find pinned map\n",
					map->name);
				err = -ENOENT;
				goto err_out;
			}
		}

		if (map->fd >= 0) {
			pr_debug("map '%s': skipping creation (preset fd=%d)\n",
				 map->name, map->fd);
		} else {
			err = bpf_object__create_map(obj, map, false);
			if (err)
				goto err_out;

			pr_debug("map '%s': created successfully, fd=%d\n",
				 map->name, map->fd);

			if (bpf_map__is_internal(map)) {
				err = bpf_object__populate_internal_map(obj, map);
				if (err < 0) {
					zclose(map->fd);
					goto err_out;
				}
			}

			if (map->init_slots_sz && map->def.type != BPF_MAP_TYPE_PROG_ARRAY) {
				err = init_map_in_map_slots(obj, map);
				if (err < 0) {
					zclose(map->fd);
					goto err_out;
				}
			}
		}

		if (map->pin_path && !map->pinned) {
			err = bpf_map__pin(map, NULL);
			if (err) {
				zclose(map->fd);
				if (!retried && err == -EEXIST) {
					retried = true;
					goto retry;
				}
				pr_warn("map '%s': failed to auto-pin at '%s': %d\n",
					map->name, map->pin_path, err);
				goto err_out;
			}
		}
	}

	return 0;

err_out:
	cp = libbpf_strerror_r(err, errmsg, sizeof(errmsg));
	pr_warn("map '%s': failed to create: %s(%d)\n", map->name, cp, err);
	pr_perm_msg(err);
	for (j = 0; j < i; j++)
		zclose(obj->maps[j].fd);
	return err;
}

static bool bpf_core_is_flavor_sep(const char *s)
{
	/* check X___Y name pattern, where X and Y are not underscores */
	return s[0] != '_' &&				      /* X */
	       s[1] == '_' && s[2] == '_' && s[3] == '_' &&   /* ___ */
	       s[4] != '_';				      /* Y */
}

/* Given 'some_struct_name___with_flavor' return the length of a name prefix
 * before last triple underscore. Struct name part after last triple
 * underscore is ignored by BPF CO-RE relocation during relocation matching.
 */
size_t bpf_core_essential_name_len(const char *name)
{
	size_t n = strlen(name);
	int i;

	for (i = n - 5; i >= 0; i--) {
		if (bpf_core_is_flavor_sep(name + i))
			return i + 1;
	}
	return n;
}

void bpf_core_free_cands(struct bpf_core_cand_list *cands)
{
	if (!cands)
		return;

	free(cands->cands);
	free(cands);
}

int bpf_core_add_cands(struct bpf_core_cand *local_cand,
		       size_t local_essent_len,
		       const struct btf *targ_btf,
		       const char *targ_btf_name,
		       int targ_start_id,
		       struct bpf_core_cand_list *cands)
{
	struct bpf_core_cand *new_cands, *cand;
	const struct btf_type *t, *local_t;
	const char *targ_name, *local_name;
	size_t targ_essent_len;
	int n, i;

	local_t = btf__type_by_id(local_cand->btf, local_cand->id);
	local_name = btf__str_by_offset(local_cand->btf, local_t->name_off);

	n = btf__type_cnt(targ_btf);
	for (i = targ_start_id; i < n; i++) {
		t = btf__type_by_id(targ_btf, i);
		if (!btf_kind_core_compat(t, local_t))
			continue;

		targ_name = btf__name_by_offset(targ_btf, t->name_off);
		if (str_is_empty(targ_name))
			continue;

		targ_essent_len = bpf_core_essential_name_len(targ_name);
		if (targ_essent_len != local_essent_len)
			continue;

		if (strncmp(local_name, targ_name, local_essent_len) != 0)
			continue;

		pr_debug("CO-RE relocating [%d] %s %s: found target candidate [%d] %s %s in [%s]\n",
			 local_cand->id, btf_kind_str(local_t),
			 local_name, i, btf_kind_str(t), targ_name,
			 targ_btf_name);
		new_cands = libbpf_reallocarray(cands->cands, cands->len + 1,
					      sizeof(*cands->cands));
		if (!new_cands)
			return -ENOMEM;

		cand = &new_cands[cands->len];
		cand->btf = targ_btf;
		cand->id = i;

		cands->cands = new_cands;
		cands->len++;
	}
	return 0;
}

static int load_module_btfs(struct bpf_object *obj)
{
	struct bpf_btf_info info;
	struct module_btf *mod_btf;
	struct btf *btf;
	char name[64];
	__u32 id = 0, len;
	int err, fd;

	if (obj->btf_modules_loaded)
		return 0;

	if (obj->gen_loader)
		return 0;

	/* don't do this again, even if we find no module BTFs */
	obj->btf_modules_loaded = true;

	/* kernel too old to support module BTFs */
	if (!kernel_supports(obj, FEAT_MODULE_BTF))
		return 0;

	while (true) {
		err = bpf_btf_get_next_id(id, &id);
		if (err && errno == ENOENT)
			return 0;
		if (err) {
			err = -errno;
			pr_warn("failed to iterate BTF objects: %d\n", err);
			return err;
		}

		fd = bpf_btf_get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT)
				continue; /* expected race: BTF was unloaded */
			err = -errno;
			pr_warn("failed to get BTF object #%d FD: %d\n", id, err);
			return err;
		}

		len = sizeof(info);
		memset(&info, 0, sizeof(info));
		info.name = ptr_to_u64(name);
		info.name_len = sizeof(name);

		err = bpf_btf_get_info_by_fd(fd, &info, &len);
		if (err) {
			err = -errno;
			pr_warn("failed to get BTF object #%d info: %d\n", id, err);
			goto err_out;
		}

		/* ignore non-module BTFs */
		if (!info.kernel_btf || strcmp(name, "vmlinux") == 0) {
			close(fd);
			continue;
		}

		btf = btf_get_from_fd(fd, obj->btf_vmlinux);
		err = libbpf_get_error(btf);
		if (err) {
			pr_warn("failed to load module [%s]'s BTF object #%d: %d\n",
				name, id, err);
			goto err_out;
		}

		err = libbpf_ensure_mem((void **)&obj->btf_modules, &obj->btf_module_cap,
					sizeof(*obj->btf_modules), obj->btf_module_cnt + 1);
		if (err)
			goto err_out;

		mod_btf = &obj->btf_modules[obj->btf_module_cnt++];

		mod_btf->btf = btf;
		mod_btf->id = id;
		mod_btf->fd = fd;
		mod_btf->name = strdup(name);
		if (!mod_btf->name) {
			err = -ENOMEM;
			goto err_out;
		}
		continue;

err_out:
		close(fd);
		return err;
	}

	return 0;
}

static struct bpf_core_cand_list *
bpf_core_find_cands(struct bpf_object *obj, const struct btf *local_btf, __u32 local_type_id)
{
	struct bpf_core_cand local_cand = {};
	struct bpf_core_cand_list *cands;
	const struct btf *main_btf;
	const struct btf_type *local_t;
	const char *local_name;
	size_t local_essent_len;
	int err, i;

	local_cand.btf = local_btf;
	local_cand.id = local_type_id;
	local_t = btf__type_by_id(local_btf, local_type_id);
	if (!local_t)
		return ERR_PTR(-EINVAL);

	local_name = btf__name_by_offset(local_btf, local_t->name_off);
	if (str_is_empty(local_name))
		return ERR_PTR(-EINVAL);
	local_essent_len = bpf_core_essential_name_len(local_name);

	cands = calloc(1, sizeof(*cands));
	if (!cands)
		return ERR_PTR(-ENOMEM);

	/* Attempt to find target candidates in vmlinux BTF first */
	main_btf = obj->btf_vmlinux_override ?: obj->btf_vmlinux;
	err = bpf_core_add_cands(&local_cand, local_essent_len, main_btf, "vmlinux", 1, cands);
	if (err)
		goto err_out;

	/* if vmlinux BTF has any candidate, don't got for module BTFs */
	if (cands->len)
		return cands;

	/* if vmlinux BTF was overridden, don't attempt to load module BTFs */
	if (obj->btf_vmlinux_override)
		return cands;

	/* now look through module BTFs, trying to still find candidates */
	err = load_module_btfs(obj);
	if (err)
		goto err_out;

	for (i = 0; i < obj->btf_module_cnt; i++) {
		err = bpf_core_add_cands(&local_cand, local_essent_len,
					 obj->btf_modules[i].btf,
					 obj->btf_modules[i].name,
					 btf__type_cnt(obj->btf_vmlinux),
					 cands);
		if (err)
			goto err_out;
	}

	return cands;
err_out:
	bpf_core_free_cands(cands);
	return ERR_PTR(err);
}

int bpf_core_types_are_compat(const struct btf *local_btf, __u32 local_id,
			      const struct btf *targ_btf, __u32 targ_id)
{
	return __bpf_core_types_are_compat(local_btf, local_id, targ_btf, targ_id, 32);
}

int bpf_core_types_match(const struct btf *local_btf, __u32 local_id,
			 const struct btf *targ_btf, __u32 targ_id)
{
	return __bpf_core_types_match(local_btf, local_id, targ_btf, targ_id, false, 32);
}

static size_t bpf_core_hash_fn(const long key, void *ctx)
{
	return key;
}

static bool bpf_core_equal_fn(const long k1, const long k2, void *ctx)
{
	return k1 == k2;
}

static int record_relo_core(struct bpf_program *prog,
			    const struct bpf_core_relo *core_relo, int insn_idx)
{
	struct reloc_desc *relos, *relo;

	relos = libbpf_reallocarray(prog->reloc_desc,
				    prog->nr_reloc + 1, sizeof(*relos));
	if (!relos)
		return -ENOMEM;
	relo = &relos[prog->nr_reloc];
	relo->type = RELO_CORE;
	relo->insn_idx = insn_idx;
	relo->core_relo = core_relo;
	prog->reloc_desc = relos;
	prog->nr_reloc++;
	return 0;
}

static const struct bpf_core_relo *find_relo_core(struct bpf_program *prog, int insn_idx)
{
	struct reloc_desc *relo;
	int i;

	for (i = 0; i < prog->nr_reloc; i++) {
		relo = &prog->reloc_desc[i];
		if (relo->type != RELO_CORE || relo->insn_idx != insn_idx)
			continue;

		return relo->core_relo;
	}

	return NULL;
}

static int bpf_core_resolve_relo(struct bpf_program *prog,
				 const struct bpf_core_relo *relo,
				 int relo_idx,
				 const struct btf *local_btf,
				 struct hashmap *cand_cache,
				 struct bpf_core_relo_res *targ_res)
{
	struct bpf_core_spec specs_scratch[3] = {};
	struct bpf_core_cand_list *cands = NULL;
	const char *prog_name = prog->name;
	const struct btf_type *local_type;
	const char *local_name;
	__u32 local_id = relo->type_id;
	int err;

	local_type = btf__type_by_id(local_btf, local_id);
	if (!local_type)
		return -EINVAL;

	local_name = btf__name_by_offset(local_btf, local_type->name_off);
	if (!local_name)
		return -EINVAL;

	if (relo->kind != BPF_CORE_TYPE_ID_LOCAL &&
	    !hashmap__find(cand_cache, local_id, &cands)) {
		cands = bpf_core_find_cands(prog->obj, local_btf, local_id);
		if (IS_ERR(cands)) {
			pr_warn("prog '%s': relo #%d: target candidate search failed for [%d] %s %s: %ld\n",
				prog_name, relo_idx, local_id, btf_kind_str(local_type),
				local_name, PTR_ERR(cands));
			return PTR_ERR(cands);
		}
		err = hashmap__set(cand_cache, local_id, cands, NULL, NULL);
		if (err) {
			bpf_core_free_cands(cands);
			return err;
		}
	}

	return bpf_core_calc_relo_insn(prog_name, relo, relo_idx, local_btf, cands, specs_scratch,
				       targ_res);
}

static int
bpf_object__relocate_core(struct bpf_object *obj, const char *targ_btf_path)
{
	const struct btf_ext_info_sec *sec;
	struct bpf_core_relo_res targ_res;
	const struct bpf_core_relo *rec;
	const struct btf_ext_info *seg;
	struct hashmap_entry *entry;
	struct hashmap *cand_cache = NULL;
	struct bpf_program *prog;
	struct bpf_insn *insn;
	const char *sec_name;
	int i, err = 0, insn_idx, sec_idx, sec_num;

	if (obj->btf_ext->core_relo_info.len == 0)
		return 0;

	if (targ_btf_path) {
		obj->btf_vmlinux_override = btf__parse(targ_btf_path, NULL);
		err = libbpf_get_error(obj->btf_vmlinux_override);
		if (err) {
			pr_warn("failed to parse target BTF: %d\n", err);
			return err;
		}
	}

	cand_cache = hashmap__new(bpf_core_hash_fn, bpf_core_equal_fn, NULL);
	if (IS_ERR(cand_cache)) {
		err = PTR_ERR(cand_cache);
		goto out;
	}

	seg = &obj->btf_ext->core_relo_info;
	sec_num = 0;
	for_each_btf_ext_sec(seg, sec) {
		sec_idx = seg->sec_idxs[sec_num];
		sec_num++;

		sec_name = btf__name_by_offset(obj->btf, sec->sec_name_off);
		if (str_is_empty(sec_name)) {
			err = -EINVAL;
			goto out;
		}

		pr_debug("sec '%s': found %d CO-RE relocations\n", sec_name, sec->num_info);

		for_each_btf_ext_rec(seg, sec, i, rec) {
			if (rec->insn_off % BPF_INSN_SZ)
				return -EINVAL;
			insn_idx = rec->insn_off / BPF_INSN_SZ;
			prog = find_prog_by_sec_insn(obj, sec_idx, insn_idx);
			if (!prog) {
				pr_debug("sec '%s': skipping CO-RE relocation #%d for insn #%d belonging to eliminated weak subprogram\n",
					 sec_name, i, insn_idx);
				continue;
			}
			/* no need to apply CO-RE relocation if the program is
			 * not going to be loaded
			 */
			if (!prog->autoload)
				continue;

			/* adjust insn_idx from section frame of reference to the local
			 * program's frame of reference; (sub-)program code is not yet
			 * relocated, so it's enough to just subtract in-section offset
			 */
			insn_idx = insn_idx - prog->sec_insn_off;
			if (insn_idx >= prog->insns_cnt)
				return -EINVAL;
			insn = &prog->insns[insn_idx];

			err = record_relo_core(prog, rec, insn_idx);
			if (err) {
				pr_warn("prog '%s': relo #%d: failed to record relocation: %d\n",
					prog->name, i, err);
				goto out;
			}

			if (prog->obj->gen_loader)
				continue;

			err = bpf_core_resolve_relo(prog, rec, i, obj->btf, cand_cache, &targ_res);
			if (err) {
				pr_warn("prog '%s': relo #%d: failed to relocate: %d\n",
					prog->name, i, err);
				goto out;
			}

			err = bpf_core_patch_insn(prog->name, insn, insn_idx, rec, i, &targ_res);
			if (err) {
				pr_warn("prog '%s': relo #%d: failed to patch insn #%u: %d\n",
					prog->name, i, insn_idx, err);
				goto out;
			}
		}
	}

out:
	/* obj->btf_vmlinux and module BTFs are freed after object load */
	btf__free(obj->btf_vmlinux_override);
	obj->btf_vmlinux_override = NULL;

	if (!IS_ERR_OR_NULL(cand_cache)) {
		hashmap__for_each_entry(cand_cache, entry, i) {
			bpf_core_free_cands(entry->pvalue);
		}
		hashmap__free(cand_cache);
	}
	return err;
}

/* base map load ldimm64 special constant, used also for log fixup logic */
#define POISON_LDIMM64_MAP_BASE 2001000000
#define POISON_LDIMM64_MAP_PFX "200100"

static void poison_map_ldimm64(struct bpf_program *prog, int relo_idx,
			       int insn_idx, struct bpf_insn *insn,
			       int map_idx, const struct bpf_map *map)
{
	int i;

	pr_debug("prog '%s': relo #%d: poisoning insn #%d that loads map #%d '%s'\n",
		 prog->name, relo_idx, insn_idx, map_idx, map->name);

	/* we turn single ldimm64 into two identical invalid calls */
	for (i = 0; i < 2; i++) {
		insn->code = BPF_JMP | BPF_CALL;
		insn->dst_reg = 0;
		insn->src_reg = 0;
		insn->off = 0;
		/* if this instruction is reachable (not a dead code),
		 * verifier will complain with something like:
		 * invalid func unknown#2001000123
		 * where lower 123 is map index into obj->maps[] array
		 */
		insn->imm = POISON_LDIMM64_MAP_BASE + map_idx;

		insn++;
	}
}

/* unresolved kfunc call special constant, used also for log fixup logic */
#define POISON_CALL_KFUNC_BASE 2002000000
#define POISON_CALL_KFUNC_PFX "2002"

static void poison_kfunc_call(struct bpf_program *prog, int relo_idx,
			      int insn_idx, struct bpf_insn *insn,
			      int ext_idx, const struct extern_desc *ext)
{
	pr_debug("prog '%s': relo #%d: poisoning insn #%d that calls kfunc '%s'\n",
		 prog->name, relo_idx, insn_idx, ext->name);

	/* we turn kfunc call into invalid helper call with identifiable constant */
	insn->code = BPF_JMP | BPF_CALL;
	insn->dst_reg = 0;
	insn->src_reg = 0;
	insn->off = 0;
	/* if this instruction is reachable (not a dead code),
	 * verifier will complain with something like:
	 * invalid func unknown#2001000123
	 * where lower 123 is extern index into obj->externs[] array
	 */
	insn->imm = POISON_CALL_KFUNC_BASE + ext_idx;
}

static int
bpf_object__relocate_data(struct bpf_object *obj, struct bpf_program *prog)
{
	int i;

	for (i = 0; i < prog->nr_reloc; i++) {
		struct reloc_desc *relo = &prog->reloc_desc[i];
		struct bpf_insn *insn = &prog->insns[relo->insn_idx];
		const struct bpf_map *map;
		struct extern_desc *ext;

		switch (relo->type) {
		case RELO_LD64:
			map = &obj->maps[relo->map_idx];
			if (obj->gen_loader) {
				insn[0].src_reg = BPF_PSEUDO_MAP_IDX;
				insn[0].imm = relo->map_idx;
			} else if (map->autocreate) {
				insn[0].src_reg = BPF_PSEUDO_MAP_FD;
				insn[0].imm = map->fd;
			} else {
				poison_map_ldimm64(prog, i, relo->insn_idx, insn,
						   relo->map_idx, map);
			}
			break;
		case RELO_DATA:
			map = &obj->maps[relo->map_idx];
			insn[1].imm = insn[0].imm + relo->sym_off;
			if (obj->gen_loader) {
				insn[0].src_reg = BPF_PSEUDO_MAP_IDX_VALUE;
				insn[0].imm = relo->map_idx;
			} else if (map->autocreate) {
				insn[0].src_reg = BPF_PSEUDO_MAP_VALUE;
				insn[0].imm = map->fd;
			} else {
				poison_map_ldimm64(prog, i, relo->insn_idx, insn,
						   relo->map_idx, map);
			}
			break;
		case RELO_EXTERN_LD64:
			ext = &obj->externs[relo->ext_idx];
			if (ext->type == EXT_KCFG) {
				if (obj->gen_loader) {
					insn[0].src_reg = BPF_PSEUDO_MAP_IDX_VALUE;
					insn[0].imm = obj->kconfig_map_idx;
				} else {
					insn[0].src_reg = BPF_PSEUDO_MAP_VALUE;
					insn[0].imm = obj->maps[obj->kconfig_map_idx].fd;
				}
				insn[1].imm = ext->kcfg.data_off;
			} else /* EXT_KSYM */ {
				if (ext->ksym.type_id && ext->is_set) { /* typed ksyms */
					insn[0].src_reg = BPF_PSEUDO_BTF_ID;
					insn[0].imm = ext->ksym.kernel_btf_id;
					insn[1].imm = ext->ksym.kernel_btf_obj_fd;
				} else { /* typeless ksyms or unresolved typed ksyms */
					insn[0].imm = (__u32)ext->ksym.addr;
					insn[1].imm = ext->ksym.addr >> 32;
				}
			}
			break;
		case RELO_EXTERN_CALL:
			ext = &obj->externs[relo->ext_idx];
			insn[0].src_reg = BPF_PSEUDO_KFUNC_CALL;
			if (ext->is_set) {
				insn[0].imm = ext->ksym.kernel_btf_id;
				insn[0].off = ext->ksym.btf_fd_idx;
			} else { /* unresolved weak kfunc call */
				poison_kfunc_call(prog, i, relo->insn_idx, insn,
						  relo->ext_idx, ext);
			}
			break;
		case RELO_SUBPROG_ADDR:
			if (insn[0].src_reg != BPF_PSEUDO_FUNC) {
				pr_warn("prog '%s': relo #%d: bad insn\n",
					prog->name, i);
				return -EINVAL;
			}
			/* handled already */
			break;
		case RELO_CALL:
			/* handled already */
			break;
		case RELO_CORE:
			/* will be handled by bpf_program_record_relos() */
			break;
		default:
			pr_warn("prog '%s': relo #%d: bad relo type %d\n",
				prog->name, i, relo->type);
			return -EINVAL;
		}
	}

	return 0;
}

static int adjust_prog_btf_ext_info(const struct bpf_object *obj,
				    const struct bpf_program *prog,
				    const struct btf_ext_info *ext_info,
				    void **prog_info, __u32 *prog_rec_cnt,
				    __u32 *prog_rec_sz)
{
	void *copy_start = NULL, *copy_end = NULL;
	void *rec, *rec_end, *new_prog_info;
	const struct btf_ext_info_sec *sec;
	size_t old_sz, new_sz;
	int i, sec_num, sec_idx, off_adj;

	sec_num = 0;
	for_each_btf_ext_sec(ext_info, sec) {
		sec_idx = ext_info->sec_idxs[sec_num];
		sec_num++;
		if (prog->sec_idx != sec_idx)
			continue;

		for_each_btf_ext_rec(ext_info, sec, i, rec) {
			__u32 insn_off = *(__u32 *)rec / BPF_INSN_SZ;

			if (insn_off < prog->sec_insn_off)
				continue;
			if (insn_off >= prog->sec_insn_off + prog->sec_insn_cnt)
				break;

			if (!copy_start)
				copy_start = rec;
			copy_end = rec + ext_info->rec_size;
		}

		if (!copy_start)
			return -ENOENT;

		/* append func/line info of a given (sub-)program to the main
		 * program func/line info
		 */
		old_sz = (size_t)(*prog_rec_cnt) * ext_info->rec_size;
		new_sz = old_sz + (copy_end - copy_start);
		new_prog_info = realloc(*prog_info, new_sz);
		if (!new_prog_info)
			return -ENOMEM;
		*prog_info = new_prog_info;
		*prog_rec_cnt = new_sz / ext_info->rec_size;
		memcpy(new_prog_info + old_sz, copy_start, copy_end - copy_start);

		/* Kernel instruction offsets are in units of 8-byte
		 * instructions, while .BTF.ext instruction offsets generated
		 * by Clang are in units of bytes. So convert Clang offsets
		 * into kernel offsets and adjust offset according to program
		 * relocated position.
		 */
		off_adj = prog->sub_insn_off - prog->sec_insn_off;
		rec = new_prog_info + old_sz;
		rec_end = new_prog_info + new_sz;
		for (; rec < rec_end; rec += ext_info->rec_size) {
			__u32 *insn_off = rec;

			*insn_off = *insn_off / BPF_INSN_SZ + off_adj;
		}
		*prog_rec_sz = ext_info->rec_size;
		return 0;
	}

	return -ENOENT;
}

static int
reloc_prog_func_and_line_info(const struct bpf_object *obj,
			      struct bpf_program *main_prog,
			      const struct bpf_program *prog)
{
	int err;

	/* no .BTF.ext relocation if .BTF.ext is missing or kernel doesn't
	 * supprot func/line info
	 */
	if (!obj->btf_ext || !kernel_supports(obj, FEAT_BTF_FUNC))
		return 0;

	/* only attempt func info relocation if main program's func_info
	 * relocation was successful
	 */
	if (main_prog != prog && !main_prog->func_info)
		goto line_info;

	err = adjust_prog_btf_ext_info(obj, prog, &obj->btf_ext->func_info,
				       &main_prog->func_info,
				       &main_prog->func_info_cnt,
				       &main_prog->func_info_rec_size);
	if (err) {
		if (err != -ENOENT) {
			pr_warn("prog '%s': error relocating .BTF.ext function info: %d\n",
				prog->name, err);
			return err;
		}
		if (main_prog->func_info) {
			/*
			 * Some info has already been found but has problem
			 * in the last btf_ext reloc. Must have to error out.
			 */
			pr_warn("prog '%s': missing .BTF.ext function info.\n", prog->name);
			return err;
		}
		/* Have problem loading the very first info. Ignore the rest. */
		pr_warn("prog '%s': missing .BTF.ext function info for the main program, skipping all of .BTF.ext func info.\n",
			prog->name);
	}

line_info:
	/* don't relocate line info if main program's relocation failed */
	if (main_prog != prog && !main_prog->line_info)
		return 0;

	err = adjust_prog_btf_ext_info(obj, prog, &obj->btf_ext->line_info,
				       &main_prog->line_info,
				       &main_prog->line_info_cnt,
				       &main_prog->line_info_rec_size);
	if (err) {
		if (err != -ENOENT) {
			pr_warn("prog '%s': error relocating .BTF.ext line info: %d\n",
				prog->name, err);
			return err;
		}
		if (main_prog->line_info) {
			/*
			 * Some info has already been found but has problem
			 * in the last btf_ext reloc. Must have to error out.
			 */
			pr_warn("prog '%s': missing .BTF.ext line info.\n", prog->name);
			return err;
		}
		/* Have problem loading the very first info. Ignore the rest. */
		pr_warn("prog '%s': missing .BTF.ext line info for the main program, skipping all of .BTF.ext line info.\n",
			prog->name);
	}
	return 0;
}

static int cmp_relo_by_insn_idx(const void *key, const void *elem)
{
	size_t insn_idx = *(const size_t *)key;
	const struct reloc_desc *relo = elem;

	if (insn_idx == relo->insn_idx)
		return 0;
	return insn_idx < relo->insn_idx ? -1 : 1;
}

static struct reloc_desc *find_prog_insn_relo(const struct bpf_program *prog, size_t insn_idx)
{
	if (!prog->nr_reloc)
		return NULL;
	return bsearch(&insn_idx, prog->reloc_desc, prog->nr_reloc,
		       sizeof(*prog->reloc_desc), cmp_relo_by_insn_idx);
}

static int append_subprog_relos(struct bpf_program *main_prog, struct bpf_program *subprog)
{
	int new_cnt = main_prog->nr_reloc + subprog->nr_reloc;
	struct reloc_desc *relos;
	int i;

	if (main_prog == subprog)
		return 0;
	relos = libbpf_reallocarray(main_prog->reloc_desc, new_cnt, sizeof(*relos));
	if (!relos)
		return -ENOMEM;
	if (subprog->nr_reloc)
		memcpy(relos + main_prog->nr_reloc, subprog->reloc_desc,
		       sizeof(*relos) * subprog->nr_reloc);

	for (i = main_prog->nr_reloc; i < new_cnt; i++)
		relos[i].insn_idx += subprog->sub_insn_off;
	/* After insn_idx adjustment the 'relos' array is still sorted
	 * by insn_idx and doesn't break bsearch.
	 */
	main_prog->reloc_desc = relos;
	main_prog->nr_reloc = new_cnt;
	return 0;
}

static int
bpf_object__reloc_code(struct bpf_object *obj, struct bpf_program *main_prog,
		       struct bpf_program *prog)
{
	size_t sub_insn_idx, insn_idx, new_cnt;
	struct bpf_program *subprog;
	struct bpf_insn *insns, *insn;
	struct reloc_desc *relo;
	int err;

	err = reloc_prog_func_and_line_info(obj, main_prog, prog);
	if (err)
		return err;

	for (insn_idx = 0; insn_idx < prog->sec_insn_cnt; insn_idx++) {
		insn = &main_prog->insns[prog->sub_insn_off + insn_idx];
		if (!insn_is_subprog_call(insn) && !insn_is_pseudo_func(insn))
			continue;

		relo = find_prog_insn_relo(prog, insn_idx);
		if (relo && relo->type == RELO_EXTERN_CALL)
			/* kfunc relocations will be handled later
			 * in bpf_object__relocate_data()
			 */
			continue;
		if (relo && relo->type != RELO_CALL && relo->type != RELO_SUBPROG_ADDR) {
			pr_warn("prog '%s': unexpected relo for insn #%zu, type %d\n",
				prog->name, insn_idx, relo->type);
			return -LIBBPF_ERRNO__RELOC;
		}
		if (relo) {
			if (relo->type == RELO_CALL)
				sub_insn_idx = relo->sym_off / BPF_INSN_SZ + insn->imm + 1;
			else
				sub_insn_idx = (relo->sym_off + insn->imm) / BPF_INSN_SZ;
		} else if (insn_is_pseudo_func(insn)) {
			/*
			 * RELO_SUBPROG_ADDR relo is always emitted even if both
			 * functions are in the same section, so it shouldn't reach here.
			 */
			pr_warn("prog '%s': missing subprog addr relo for insn #%zu\n",
				prog->name, insn_idx);
			return -LIBBPF_ERRNO__RELOC;
		} else {
			/* if subprogram call is to a static function within
			 * the same ELF section, there won't be any relocation
			 * emitted, but it also means there is no additional
			 * offset necessary, insns->imm is relative to
			 * instruction's original position within the section
			 */
			sub_insn_idx = prog->sec_insn_off + insn_idx + insn->imm + 1;
		}

		/* we enforce that sub-programs should be in .text section */
		subprog = find_prog_by_sec_insn(obj, obj->efile.text_shndx, sub_insn_idx);
		if (!subprog) {
			pr_warn("prog '%s': no .text section found yet sub-program call exists\n",
				prog->name);
			return -LIBBPF_ERRNO__RELOC;
		}

		if (subprog->sub_insn_off == 0) {
			subprog->sub_insn_off = main_prog->insns_cnt;

			new_cnt = main_prog->insns_cnt + subprog->insns_cnt;
			insns = libbpf_reallocarray(main_prog->insns, new_cnt, sizeof(*insns));
			if (!insns) {
				pr_warn("prog '%s': failed to realloc prog code\n", main_prog->name);
				return -ENOMEM;
			}
			main_prog->insns = insns;
			main_prog->insns_cnt = new_cnt;

			memcpy(main_prog->insns + subprog->sub_insn_off, subprog->insns,
			       subprog->insns_cnt * sizeof(*insns));

			pr_debug("prog '%s': added %zu insns from sub-prog '%s'\n",
				 main_prog->name, subprog->insns_cnt, subprog->name);

			/* The subprog insns are now appended. Append its relos too. */
			err = append_subprog_relos(main_prog, subprog);
			if (err)
				return err;
			err = bpf_object__reloc_code(obj, main_prog, subprog);
			if (err)
				return err;
		}

		/* main_prog->insns memory could have been re-allocated, so
		 * calculate pointer again
		 */
		insn = &main_prog->insns[prog->sub_insn_off + insn_idx];

		insn->imm = subprog->sub_insn_off - (prog->sub_insn_off + insn_idx) - 1;

		pr_debug("prog '%s': insn #%zu relocated, imm %d points to subprog '%s' (now at %zu offset)\n",
			 prog->name, insn_idx, insn->imm, subprog->name, subprog->sub_insn_off);
	}

	return 0;
}

static int
bpf_object__relocate_calls(struct bpf_object *obj, struct bpf_program *prog)
{
	struct bpf_program *subprog;
	int i, err;

	/* mark all subprogs as not relocated (yet) within the context of
	 * current main program
	 */
	for (i = 0; i < obj->nr_programs; i++) {
		subprog = &obj->programs[i];
		if (!prog_is_subprog(obj, subprog))
			continue;

		subprog->sub_insn_off = 0;
	}

	err = bpf_object__reloc_code(obj, prog, prog);
	if (err)
		return err;

	return 0;
}

static void
bpf_object__free_relocs(struct bpf_object *obj)
{
	struct bpf_program *prog;
	int i;

	/* free up relocation descriptors */
	for (i = 0; i < obj->nr_programs; i++) {
		prog = &obj->programs[i];
		zfree(&prog->reloc_desc);
		prog->nr_reloc = 0;
	}
}

static int cmp_relocs(const void *_a, const void *_b)
{
	const struct reloc_desc *a = _a;
	const struct reloc_desc *b = _b;

	if (a->insn_idx != b->insn_idx)
		return a->insn_idx < b->insn_idx ? -1 : 1;

	/* no two relocations should have the same insn_idx, but ... */
	if (a->type != b->type)
		return a->type < b->type ? -1 : 1;

	return 0;
}

static void bpf_object__sort_relos(struct bpf_object *obj)
{
	int i;

	for (i = 0; i < obj->nr_programs; i++) {
		struct bpf_program *p = &obj->programs[i];

		if (!p->nr_reloc)
			continue;

		qsort(p->reloc_desc, p->nr_reloc, sizeof(*p->reloc_desc), cmp_relocs);
	}
}

static int
bpf_object__relocate(struct bpf_object *obj, const char *targ_btf_path)
{
	struct bpf_program *prog;
	size_t i, j;
	int err;

	if (obj->btf_ext) {
		err = bpf_object__relocate_core(obj, targ_btf_path);
		if (err) {
			pr_warn("failed to perform CO-RE relocations: %d\n",
				err);
			return err;
		}
		bpf_object__sort_relos(obj);
	}

	for (i = 0; i < obj->nr_programs; i++) {
		prog = &obj->programs[i];
		for (j = 0; j < prog->nr_reloc; j++) {
			struct reloc_desc *relo = &prog->reloc_desc[j];
			struct bpf_insn *insn = &prog->insns[relo->insn_idx];

			/* mark the insn, so it's recognized by insn_is_pseudo_func() */
			if (relo->type == RELO_SUBPROG_ADDR)
				insn[0].src_reg = BPF_PSEUDO_FUNC;
		}
	}

	for (i = 0; i < obj->nr_programs; i++) {
		prog = &obj->programs[i];
		/* sub-program's sub-calls are relocated within the context of
		 * its main program only
		 */
		if (prog_is_subprog(obj, prog))
			continue;
		if (!prog->autoload)
			continue;

		err = bpf_object__relocate_calls(obj, prog);
		if (err) {
			pr_warn("prog '%s': failed to relocate calls: %d\n",
				prog->name, err);
			return err;
		}
	}
	/* Process data relos for main programs */
	for (i = 0; i < obj->nr_programs; i++) {
		prog = &obj->programs[i];
		if (prog_is_subprog(obj, prog))
			continue;
		if (!prog->autoload)
			continue;
		err = bpf_object__relocate_data(obj, prog);
		if (err) {
			pr_warn("prog '%s': failed to relocate data references: %d\n",
				prog->name, err);
			return err;
		}
	}

	return 0;
}

static int bpf_object__collect_st_ops_relos(struct bpf_object *obj,
					    Elf64_Shdr *shdr, Elf_Data *data);

static int bpf_object__collect_map_relos(struct bpf_object *obj,
					 Elf64_Shdr *shdr, Elf_Data *data)
{
	const int bpf_ptr_sz = 8, host_ptr_sz = sizeof(void *);
	int i, j, nrels, new_sz;
	const struct btf_var_secinfo *vi = NULL;
	const struct btf_type *sec, *var, *def;
	struct bpf_map *map = NULL, *targ_map = NULL;
	struct bpf_program *targ_prog = NULL;
	bool is_prog_array, is_map_in_map;
	const struct btf_member *member;
	const char *name, *mname, *type;
	unsigned int moff;
	Elf64_Sym *sym;
	Elf64_Rel *rel;
	void *tmp;

	if (!obj->efile.btf_maps_sec_btf_id || !obj->btf)
		return -EINVAL;
	sec = btf__type_by_id(obj->btf, obj->efile.btf_maps_sec_btf_id);
	if (!sec)
		return -EINVAL;

	nrels = shdr->sh_size / shdr->sh_entsize;
	for (i = 0; i < nrels; i++) {
		rel = elf_rel_by_idx(data, i);
		if (!rel) {
			pr_warn(".maps relo #%d: failed to get ELF relo\n", i);
			return -LIBBPF_ERRNO__FORMAT;
		}

		sym = elf_sym_by_idx(obj, ELF64_R_SYM(rel->r_info));
		if (!sym) {
			pr_warn(".maps relo #%d: symbol %zx not found\n",
				i, (size_t)ELF64_R_SYM(rel->r_info));
			return -LIBBPF_ERRNO__FORMAT;
		}
		name = elf_sym_str(obj, sym->st_name) ?: "<?>";

		pr_debug(".maps relo #%d: for %zd value %zd rel->r_offset %zu name %d ('%s')\n",
			 i, (ssize_t)(rel->r_info >> 32), (size_t)sym->st_value,
			 (size_t)rel->r_offset, sym->st_name, name);

		for (j = 0; j < obj->nr_maps; j++) {
			map = &obj->maps[j];
			if (map->sec_idx != obj->efile.btf_maps_shndx)
				continue;

			vi = btf_var_secinfos(sec) + map->btf_var_idx;
			if (vi->offset <= rel->r_offset &&
			    rel->r_offset + bpf_ptr_sz <= vi->offset + vi->size)
				break;
		}
		if (j == obj->nr_maps) {
			pr_warn(".maps relo #%d: cannot find map '%s' at rel->r_offset %zu\n",
				i, name, (size_t)rel->r_offset);
			return -EINVAL;
		}

		is_map_in_map = bpf_map_type__is_map_in_map(map->def.type);
		is_prog_array = map->def.type == BPF_MAP_TYPE_PROG_ARRAY;
		type = is_map_in_map ? "map" : "prog";
		if (is_map_in_map) {
			if (sym->st_shndx != obj->efile.btf_maps_shndx) {
				pr_warn(".maps relo #%d: '%s' isn't a BTF-defined map\n",
					i, name);
				return -LIBBPF_ERRNO__RELOC;
			}
			if (map->def.type == BPF_MAP_TYPE_HASH_OF_MAPS &&
			    map->def.key_size != sizeof(int)) {
				pr_warn(".maps relo #%d: hash-of-maps '%s' should have key size %zu.\n",
					i, map->name, sizeof(int));
				return -EINVAL;
			}
			targ_map = bpf_object__find_map_by_name(obj, name);
			if (!targ_map) {
				pr_warn(".maps relo #%d: '%s' isn't a valid map reference\n",
					i, name);
				return -ESRCH;
			}
		} else if (is_prog_array) {
			targ_prog = bpf_object__find_program_by_name(obj, name);
			if (!targ_prog) {
				pr_warn(".maps relo #%d: '%s' isn't a valid program reference\n",
					i, name);
				return -ESRCH;
			}
			if (targ_prog->sec_idx != sym->st_shndx ||
			    targ_prog->sec_insn_off * 8 != sym->st_value ||
			    prog_is_subprog(obj, targ_prog)) {
				pr_warn(".maps relo #%d: '%s' isn't an entry-point program\n",
					i, name);
				return -LIBBPF_ERRNO__RELOC;
			}
		} else {
			return -EINVAL;
		}

		var = btf__type_by_id(obj->btf, vi->type);
		def = skip_mods_and_typedefs(obj->btf, var->type, NULL);
		if (btf_vlen(def) == 0)
			return -EINVAL;
		member = btf_members(def) + btf_vlen(def) - 1;
		mname = btf__name_by_offset(obj->btf, member->name_off);
		if (strcmp(mname, "values"))
			return -EINVAL;

		moff = btf_member_bit_offset(def, btf_vlen(def) - 1) / 8;
		if (rel->r_offset - vi->offset < moff)
			return -EINVAL;

		moff = rel->r_offset - vi->offset - moff;
		/* here we use BPF pointer size, which is always 64 bit, as we
		 * are parsing ELF that was built for BPF target
		 */
		if (moff % bpf_ptr_sz)
			return -EINVAL;
		moff /= bpf_ptr_sz;
		if (moff >= map->init_slots_sz) {
			new_sz = moff + 1;
			tmp = libbpf_reallocarray(map->init_slots, new_sz, host_ptr_sz);
			if (!tmp)
				return -ENOMEM;
			map->init_slots = tmp;
			memset(map->init_slots + map->init_slots_sz, 0,
			       (new_sz - map->init_slots_sz) * host_ptr_sz);
			map->init_slots_sz = new_sz;
		}
		map->init_slots[moff] = is_map_in_map ? (void *)targ_map : (void *)targ_prog;

		pr_debug(".maps relo #%d: map '%s' slot [%d] points to %s '%s'\n",
			 i, map->name, moff, type, name);
	}

	return 0;
}

static int bpf_object__collect_relos(struct bpf_object *obj)
{
	int i, err;

	for (i = 0; i < obj->efile.sec_cnt; i++) {
		struct elf_sec_desc *sec_desc = &obj->efile.secs[i];
		Elf64_Shdr *shdr;
		Elf_Data *data;
		int idx;

		if (sec_desc->sec_type != SEC_RELO)
			continue;

		shdr = sec_desc->shdr;
		data = sec_desc->data;
		idx = shdr->sh_info;

		if (shdr->sh_type != SHT_REL) {
			pr_warn("internal error at %d\n", __LINE__);
			return -LIBBPF_ERRNO__INTERNAL;
		}

		if (idx == obj->efile.st_ops_shndx || idx == obj->efile.st_ops_link_shndx)
			err = bpf_object__collect_st_ops_relos(obj, shdr, data);
		else if (idx == obj->efile.btf_maps_shndx)
			err = bpf_object__collect_map_relos(obj, shdr, data);
		else
			err = bpf_object__collect_prog_relos(obj, shdr, data);
		if (err)
			return err;
	}

	bpf_object__sort_relos(obj);
	return 0;
}

static bool insn_is_helper_call(struct bpf_insn *insn, enum bpf_func_id *func_id)
{
	if (BPF_CLASS(insn->code) == BPF_JMP &&
	    BPF_OP(insn->code) == BPF_CALL &&
	    BPF_SRC(insn->code) == BPF_K &&
	    insn->src_reg == 0 &&
	    insn->dst_reg == 0) {
		    *func_id = insn->imm;
		    return true;
	}
	return false;
}

static int bpf_object__sanitize_prog(struct bpf_object *obj, struct bpf_program *prog)
{
	struct bpf_insn *insn = prog->insns;
	enum bpf_func_id func_id;
	int i;

	if (obj->gen_loader)
		return 0;

	for (i = 0; i < prog->insns_cnt; i++, insn++) {
		if (!insn_is_helper_call(insn, &func_id))
			continue;

		/* on kernels that don't yet support
		 * bpf_probe_read_{kernel,user}[_str] helpers, fall back
		 * to bpf_probe_read() which works well for old kernels
		 */
		switch (func_id) {
		case BPF_FUNC_probe_read_kernel:
		case BPF_FUNC_probe_read_user:
			if (!kernel_supports(obj, FEAT_PROBE_READ_KERN))
				insn->imm = BPF_FUNC_probe_read;
			break;
		case BPF_FUNC_probe_read_kernel_str:
		case BPF_FUNC_probe_read_user_str:
			if (!kernel_supports(obj, FEAT_PROBE_READ_KERN))
				insn->imm = BPF_FUNC_probe_read_str;
			break;
		default:
			break;
		}
	}
	return 0;
}

static int libbpf_find_attach_btf_id(struct bpf_program *prog, const char *attach_name,
				     int *btf_obj_fd, int *btf_type_id);

/* this is called as prog->sec_def->prog_prepare_load_fn for libbpf-supported sec_defs */
static int libbpf_prepare_prog_load(struct bpf_program *prog,
				    struct bpf_prog_load_opts *opts, long cookie)
{
	enum sec_def_flags def = cookie;

	/* old kernels might not support specifying expected_attach_type */
	if ((def & SEC_EXP_ATTACH_OPT) && !kernel_supports(prog->obj, FEAT_EXP_ATTACH_TYPE))
		opts->expected_attach_type = 0;

	if (def & SEC_SLEEPABLE)
		opts->prog_flags |= BPF_F_SLEEPABLE;

	if (prog->type == BPF_PROG_TYPE_XDP && (def & SEC_XDP_FRAGS))
		opts->prog_flags |= BPF_F_XDP_HAS_FRAGS;

	if ((def & SEC_ATTACH_BTF) && !prog->attach_btf_id) {
		int btf_obj_fd = 0, btf_type_id = 0, err;
		const char *attach_name;

		attach_name = strchr(prog->sec_name, '/');
		if (!attach_name) {
			pr_warn("prog '%s': no BTF-based attach target is specified, use bpf_program__set_attach_target()\n",
				prog->name);
			return -EINVAL;
		}
		attach_name++; /* skip over / */

		err = libbpf_find_attach_btf_id(prog, attach_name, &btf_obj_fd, &btf_type_id);
		if (err)
			return err;

		/* cache resolved BTF FD and BTF type ID in the prog */
		prog->attach_btf_obj_fd = btf_obj_fd;
		prog->attach_btf_id = btf_type_id;

		/* but by now libbpf common logic is not utilizing
		 * prog->atach_btf_obj_fd/prog->attach_btf_id anymore because
		 * this callback is called after opts were populated by
		 * libbpf, so this callback has to update opts explicitly here
		 */
		opts->attach_btf_obj_fd = btf_obj_fd;
		opts->attach_btf_id = btf_type_id;
	}
	return 0;
}

static void fixup_verifier_log(struct bpf_program *prog, char *buf, size_t buf_sz);

static int bpf_object_load_prog(struct bpf_object *obj, struct bpf_program *prog,
				struct bpf_insn *insns, int insns_cnt,
				const char *license, __u32 kern_version, int *prog_fd)
{
	LIBBPF_OPTS(bpf_prog_load_opts, load_attr);
	const char *prog_name = NULL;
	char *cp, errmsg[STRERR_BUFSIZE];
	size_t log_buf_size = 0;
	char *log_buf = NULL, *tmp;
	int btf_fd, ret, err;
	bool own_log_buf = true;
	__u32 log_level = prog->log_level;

	if (prog->type == BPF_PROG_TYPE_UNSPEC) {
		/*
		 * The program type must be set.  Most likely we couldn't find a proper
		 * section definition at load time, and thus we didn't infer the type.
		 */
		pr_warn("prog '%s': missing BPF prog type, check ELF section name '%s'\n",
			prog->name, prog->sec_name);
		return -EINVAL;
	}

	if (!insns || !insns_cnt)
		return -EINVAL;

	load_attr.expected_attach_type = prog->expected_attach_type;
	if (kernel_supports(obj, FEAT_PROG_NAME))
		prog_name = prog->name;
	load_attr.attach_prog_fd = prog->attach_prog_fd;
	load_attr.attach_btf_obj_fd = prog->attach_btf_obj_fd;
	load_attr.attach_btf_id = prog->attach_btf_id;
	load_attr.kern_version = kern_version;
	load_attr.prog_ifindex = prog->prog_ifindex;

	/* specify func_info/line_info only if kernel supports them */
	btf_fd = bpf_object__btf_fd(obj);
	if (btf_fd >= 0 && kernel_supports(obj, FEAT_BTF_FUNC)) {
		load_attr.prog_btf_fd = btf_fd;
		load_attr.func_info = prog->func_info;
		load_attr.func_info_rec_size = prog->func_info_rec_size;
		load_attr.func_info_cnt = prog->func_info_cnt;
		load_attr.line_info = prog->line_info;
		load_attr.line_info_rec_size = prog->line_info_rec_size;
		load_attr.line_info_cnt = prog->line_info_cnt;
	}
	load_attr.log_level = log_level;
	load_attr.prog_flags = prog->prog_flags;
	load_attr.fd_array = obj->fd_array;

	/* adjust load_attr if sec_def provides custom preload callback */
	if (prog->sec_def && prog->sec_def->prog_prepare_load_fn) {
		err = prog->sec_def->prog_prepare_load_fn(prog, &load_attr, prog->sec_def->cookie);
		if (err < 0) {
			pr_warn("prog '%s': failed to prepare load attributes: %d\n",
				prog->name, err);
			return err;
		}
		insns = prog->insns;
		insns_cnt = prog->insns_cnt;
	}

	if (obj->gen_loader) {
		bpf_gen__prog_load(obj->gen_loader, prog->type, prog->name,
				   license, insns, insns_cnt, &load_attr,
				   prog - obj->programs);
		*prog_fd = -1;
		return 0;
	}

retry_load:
	/* if log_level is zero, we don't request logs initially even if
	 * custom log_buf is specified; if the program load fails, then we'll
	 * bump log_level to 1 and use either custom log_buf or we'll allocate
	 * our own and retry the load to get details on what failed
	 */
	if (log_level) {
		if (prog->log_buf) {
			log_buf = prog->log_buf;
			log_buf_size = prog->log_size;
			own_log_buf = false;
		} else if (obj->log_buf) {
			log_buf = obj->log_buf;
			log_buf_size = obj->log_size;
			own_log_buf = false;
		} else {
			log_buf_size = max((size_t)BPF_LOG_BUF_SIZE, log_buf_size * 2);
			tmp = realloc(log_buf, log_buf_size);
			if (!tmp) {
				ret = -ENOMEM;
				goto out;
			}
			log_buf = tmp;
			log_buf[0] = '\0';
			own_log_buf = true;
		}
	}

	load_attr.log_buf = log_buf;
	load_attr.log_size = log_buf_size;
	load_attr.log_level = log_level;

	ret = bpf_prog_load(prog->type, prog_name, license, insns, insns_cnt, &load_attr);
	if (ret >= 0) {
		if (log_level && own_log_buf) {
			pr_debug("prog '%s': -- BEGIN PROG LOAD LOG --\n%s-- END PROG LOAD LOG --\n",
				 prog->name, log_buf);
		}

		if (obj->has_rodata && kernel_supports(obj, FEAT_PROG_BIND_MAP)) {
			struct bpf_map *map;
			int i;

			for (i = 0; i < obj->nr_maps; i++) {
				map = &prog->obj->maps[i];
				if (map->libbpf_type != LIBBPF_MAP_RODATA)
					continue;

				if (bpf_prog_bind_map(ret, bpf_map__fd(map), NULL)) {
					cp = libbpf_strerror_r(errno, errmsg, sizeof(errmsg));
					pr_warn("prog '%s': failed to bind map '%s': %s\n",
						prog->name, map->real_name, cp);
					/* Don't fail hard if can't bind rodata. */
				}
			}
		}

		*prog_fd = ret;
		ret = 0;
		goto out;
	}

	if (log_level == 0) {
		log_level = 1;
		goto retry_load;
	}
	/* On ENOSPC, increase log buffer size and retry, unless custom
	 * log_buf is specified.
	 * Be careful to not overflow u32, though. Kernel's log buf size limit
	 * isn't part of UAPI so it can always be bumped to full 4GB. So don't
	 * multiply by 2 unless we are sure we'll fit within 32 bits.
	 * Currently, we'll get -EINVAL when we reach (UINT_MAX >> 2).
	 */
	if (own_log_buf && errno == ENOSPC && log_buf_size <= UINT_MAX / 2)
		goto retry_load;

	ret = -errno;

	/* post-process verifier log to improve error descriptions */
	fixup_verifier_log(prog, log_buf, log_buf_size);

	cp = libbpf_strerror_r(errno, errmsg, sizeof(errmsg));
	pr_warn("prog '%s': BPF program load failed: %s\n", prog->name, cp);
	pr_perm_msg(ret);

	if (own_log_buf && log_buf && log_buf[0] != '\0') {
		pr_warn("prog '%s': -- BEGIN PROG LOAD LOG --\n%s-- END PROG LOAD LOG --\n",
			prog->name, log_buf);
	}

out:
	if (own_log_buf)
		free(log_buf);
	return ret;
}

static char *find_prev_line(char *buf, char *cur)
{
	char *p;

	if (cur == buf) /* end of a log buf */
		return NULL;

	p = cur - 1;
	while (p - 1 >= buf && *(p - 1) != '\n')
		p--;

	return p;
}

static void patch_log(char *buf, size_t buf_sz, size_t log_sz,
		      char *orig, size_t orig_sz, const char *patch)
{
	/* size of the remaining log content to the right from the to-be-replaced part */
	size_t rem_sz = (buf + log_sz) - (orig + orig_sz);
	size_t patch_sz = strlen(patch);

	if (patch_sz != orig_sz) {
		if (patch_sz > orig_sz) {
			if (orig + patch_sz >= buf + buf_sz) {
				/* patch is big enough to cover remaining space completely */
				patch_sz -= (orig + patch_sz) - (buf + buf_sz) + 1;
				rem_sz = 0;
			} else if (patch_sz - orig_sz > buf_sz - log_sz) {
				/* patch causes part of remaining log to be truncated */
				rem_sz -= (patch_sz - orig_sz) - (buf_sz - log_sz);
			}
		}
		/* shift remaining log to the right by calculated amount */
		memmove(orig + patch_sz, orig + orig_sz, rem_sz);
	}

	memcpy(orig, patch, patch_sz);
}

static void fixup_log_failed_core_relo(struct bpf_program *prog,
				       char *buf, size_t buf_sz, size_t log_sz,
				       char *line1, char *line2, char *line3)
{
	const struct bpf_core_relo *relo;
	struct bpf_core_spec spec;
	char patch[512], spec_buf[256];
	int insn_idx, err, spec_len;

	if (sscanf(line1, "%d: (%*d) call unknown#195896080\n", &insn_idx) != 1)
		return;

	relo = find_relo_core(prog, insn_idx);
	if (!relo)
		return;

	err = bpf_core_parse_spec(prog->name, prog->obj->btf, relo, &spec);
	if (err)
		return;

	spec_len = bpf_core_format_spec(spec_buf, sizeof(spec_buf), &spec);
	snprintf(patch, sizeof(patch),
		 "%d: <invalid CO-RE relocation>\n"
		 "failed to resolve CO-RE relocation %s%s\n",
		 insn_idx, spec_buf, spec_len >= sizeof(spec_buf) ? "..." : "");

	patch_log(buf, buf_sz, log_sz, line1, line3 - line1, patch);
}

static void fixup_log_missing_map_load(struct bpf_program *prog,
				       char *buf, size_t buf_sz, size_t log_sz,
				       char *line1, char *line2, char *line3)
{
	/* Expected log for failed and not properly guarded map reference:
	 * line1 -> 123: (85) call unknown#2001000345
	 * line2 -> invalid func unknown#2001000345
	 * line3 -> <anything else or end of buffer>
	 *
	 * "123" is the index of the instruction that was poisoned.
	 * "345" in "2001000345" is a map index in obj->maps to fetch map name.
	 */
	struct bpf_object *obj = prog->obj;
	const struct bpf_map *map;
	int insn_idx, map_idx;
	char patch[128];

	if (sscanf(line1, "%d: (%*d) call unknown#%d\n", &insn_idx, &map_idx) != 2)
		return;

	map_idx -= POISON_LDIMM64_MAP_BASE;
	if (map_idx < 0 || map_idx >= obj->nr_maps)
		return;
	map = &obj->maps[map_idx];

	snprintf(patch, sizeof(patch),
		 "%d: <invalid BPF map reference>\n"
		 "BPF map '%s' is referenced but wasn't created\n",
		 insn_idx, map->name);

	patch_log(buf, buf_sz, log_sz, line1, line3 - line1, patch);
}

static void fixup_log_missing_kfunc_call(struct bpf_program *prog,
					 char *buf, size_t buf_sz, size_t log_sz,
					 char *line1, char *line2, char *line3)
{
	struct bpf_object *obj = prog->obj;
	const struct extern_desc *ext;
	int insn_idx, ext_idx;
	char patch[128];

	if (sscanf(line1, "%d: (%*d) call unknown#%d\n", &insn_idx, &ext_idx) != 2)
		return;

	ext_idx -= POISON_CALL_KFUNC_BASE;
	if (ext_idx < 0 || ext_idx >= obj->nr_extern)
		return;
	ext = &obj->externs[ext_idx];

	snprintf(patch, sizeof(patch),
		 "%d: <invalid kfunc call>\n"
		 "kfunc '%s' is referenced but wasn't resolved\n",
		 insn_idx, ext->name);

	patch_log(buf, buf_sz, log_sz, line1, line3 - line1, patch);
}

static void fixup_verifier_log(struct bpf_program *prog, char *buf, size_t buf_sz)
{
	/* look for familiar error patterns in last N lines of the log */
	const size_t max_last_line_cnt = 10;
	char *prev_line, *cur_line, *next_line;
	size_t log_sz;
	int i;

	if (!buf)
		return;

	log_sz = strlen(buf) + 1;
	next_line = buf + log_sz - 1;

	for (i = 0; i < max_last_line_cnt; i++, next_line = cur_line) {
		cur_line = find_prev_line(buf, next_line);
		if (!cur_line)
			return;

		if (str_has_pfx(cur_line, "invalid func unknown#195896080\n")) {
			prev_line = find_prev_line(buf, cur_line);
			if (!prev_line)
				continue;

			/* failed CO-RE relocation case */
			fixup_log_failed_core_relo(prog, buf, buf_sz, log_sz,
						   prev_line, cur_line, next_line);
			return;
		} else if (str_has_pfx(cur_line, "invalid func unknown#"POISON_LDIMM64_MAP_PFX)) {
			prev_line = find_prev_line(buf, cur_line);
			if (!prev_line)
				continue;

			/* reference to uncreated BPF map */
			fixup_log_missing_map_load(prog, buf, buf_sz, log_sz,
						   prev_line, cur_line, next_line);
			return;
		} else if (str_has_pfx(cur_line, "invalid func unknown#"POISON_CALL_KFUNC_PFX)) {
			prev_line = find_prev_line(buf, cur_line);
			if (!prev_line)
				continue;

			/* reference to unresolved kfunc */
			fixup_log_missing_kfunc_call(prog, buf, buf_sz, log_sz,
						     prev_line, cur_line, next_line);
			return;
		}
	}
}

static int bpf_program_record_relos(struct bpf_program *prog)
{
	struct bpf_object *obj = prog->obj;
	int i;

	for (i = 0; i < prog->nr_reloc; i++) {
		struct reloc_desc *relo = &prog->reloc_desc[i];
		struct extern_desc *ext = &obj->externs[relo->ext_idx];
		int kind;

		switch (relo->type) {
		case RELO_EXTERN_LD64:
			if (ext->type != EXT_KSYM)
				continue;
			kind = btf_is_var(btf__type_by_id(obj->btf, ext->btf_id)) ?
				BTF_KIND_VAR : BTF_KIND_FUNC;
			bpf_gen__record_extern(obj->gen_loader, ext->name,
					       ext->is_weak, !ext->ksym.type_id,
					       true, kind, relo->insn_idx);
			break;
		case RELO_EXTERN_CALL:
			bpf_gen__record_extern(obj->gen_loader, ext->name,
					       ext->is_weak, false, false, BTF_KIND_FUNC,
					       relo->insn_idx);
			break;
		case RELO_CORE: {
			struct bpf_core_relo cr = {
				.insn_off = relo->insn_idx * 8,
				.type_id = relo->core_relo->type_id,
				.access_str_off = relo->core_relo->access_str_off,
				.kind = relo->core_relo->kind,
			};

			bpf_gen__record_relo_core(obj->gen_loader, &cr);
			break;
		}
		default:
			continue;
		}
	}
	return 0;
}

static int
bpf_object__load_progs(struct bpf_object *obj, int log_level)
{
	struct bpf_program *prog;
	size_t i;
	int err;

	for (i = 0; i < obj->nr_programs; i++) {
		prog = &obj->programs[i];
		err = bpf_object__sanitize_prog(obj, prog);
		if (err)
			return err;
	}

	for (i = 0; i < obj->nr_programs; i++) {
		prog = &obj->programs[i];
		if (prog_is_subprog(obj, prog))
			continue;
		if (!prog->autoload) {
			pr_debug("prog '%s': skipped loading\n", prog->name);
			continue;
		}
		prog->log_level |= log_level;

		if (obj->gen_loader)
			bpf_program_record_relos(prog);

		err = bpf_object_load_prog(obj, prog, prog->insns, prog->insns_cnt,
					   obj->license, obj->kern_version, &prog->fd);
		if (err) {
			pr_warn("prog '%s': failed to load: %d\n", prog->name, err);
			return err;
		}
	}

	bpf_object__free_relocs(obj);
	return 0;
}

static const struct bpf_sec_def *find_sec_def(const char *sec_name);

static int bpf_object_init_progs(struct bpf_object *obj, const struct bpf_object_open_opts *opts)
{
	struct bpf_program *prog;
	int err;

	bpf_object__for_each_program(prog, obj) {
		prog->sec_def = find_sec_def(prog->sec_name);
		if (!prog->sec_def) {
			/* couldn't guess, but user might manually specify */
			pr_debug("prog '%s': unrecognized ELF section name '%s'\n",
				prog->name, prog->sec_name);
			continue;
		}

		prog->type = prog->sec_def->prog_type;
		prog->expected_attach_type = prog->sec_def->expected_attach_type;

		/* sec_def can have custom callback which should be called
		 * after bpf_program is initialized to adjust its properties
		 */
		if (prog->sec_def->prog_setup_fn) {
			err = prog->sec_def->prog_setup_fn(prog, prog->sec_def->cookie);
			if (err < 0) {
				pr_warn("prog '%s': failed to initialize: %d\n",
					prog->name, err);
				return err;
			}
		}
	}

	return 0;
}

static struct bpf_object *bpf_object_open(const char *path, const void *obj_buf, size_t obj_buf_sz,
					  const struct bpf_object_open_opts *opts)
{
	const char *obj_name, *kconfig, *btf_tmp_path;
	struct bpf_object *obj;
	char tmp_name[64];
	int err;
	char *log_buf;
	size_t log_size;
	__u32 log_level;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		pr_warn("failed to init libelf for %s\n",
			path ? : "(mem buf)");
		return ERR_PTR(-LIBBPF_ERRNO__LIBELF);
	}

	if (!OPTS_VALID(opts, bpf_object_open_opts))
		return ERR_PTR(-EINVAL);

	obj_name = OPTS_GET(opts, object_name, NULL);
	if (obj_buf) {
		if (!obj_name) {
			snprintf(tmp_name, sizeof(tmp_name), "%lx-%lx",
				 (unsigned long)obj_buf,
				 (unsigned long)obj_buf_sz);
			obj_name = tmp_name;
		}
		path = obj_name;
		pr_debug("loading object '%s' from buffer\n", obj_name);
	}

	log_buf = OPTS_GET(opts, kernel_log_buf, NULL);
	log_size = OPTS_GET(opts, kernel_log_size, 0);
	log_level = OPTS_GET(opts, kernel_log_level, 0);
	if (log_size > UINT_MAX)
		return ERR_PTR(-EINVAL);
	if (log_size && !log_buf)
		return ERR_PTR(-EINVAL);

	obj = bpf_object__new(path, obj_buf, obj_buf_sz, obj_name);
	if (IS_ERR(obj))
		return obj;

	obj->log_buf = log_buf;
	obj->log_size = log_size;
	obj->log_level = log_level;

	btf_tmp_path = OPTS_GET(opts, btf_custom_path, NULL);
	if (btf_tmp_path) {
		if (strlen(btf_tmp_path) >= PATH_MAX) {
			err = -ENAMETOOLONG;
			goto out;
		}
		obj->btf_custom_path = strdup(btf_tmp_path);
		if (!obj->btf_custom_path) {
			err = -ENOMEM;
			goto out;
		}
	}

	kconfig = OPTS_GET(opts, kconfig, NULL);
	if (kconfig) {
		obj->kconfig = strdup(kconfig);
		if (!obj->kconfig) {
			err = -ENOMEM;
			goto out;
		}
	}

	err = bpf_object__elf_init(obj);
	err = err ? : bpf_object__check_endianness(obj);
	err = err ? : bpf_object__elf_collect(obj);
	err = err ? : bpf_object__collect_externs(obj);
	err = err ? : bpf_object_fixup_btf(obj);
	err = err ? : bpf_object__init_maps(obj, opts);
	err = err ? : bpf_object_init_progs(obj, opts);
	err = err ? : bpf_object__collect_relos(obj);
	if (err)
		goto out;

	bpf_object__elf_finish(obj);

	return obj;
out:
	bpf_object__close(obj);
	return ERR_PTR(err);
}

struct bpf_object *
bpf_object__open_file(const char *path, const struct bpf_object_open_opts *opts)
{
	if (!path)
		return libbpf_err_ptr(-EINVAL);

	pr_debug("loading %s\n", path);

	return libbpf_ptr(bpf_object_open(path, NULL, 0, opts));
}

struct bpf_object *bpf_object__open(const char *path)
{
	return bpf_object__open_file(path, NULL);
}

struct bpf_object *
bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
		     const struct bpf_object_open_opts *opts)
{
	if (!obj_buf || obj_buf_sz == 0)
		return libbpf_err_ptr(-EINVAL);

	return libbpf_ptr(bpf_object_open(NULL, obj_buf, obj_buf_sz, opts));
}

static int bpf_object_unload(struct bpf_object *obj)
{
	size_t i;

	if (!obj)
		return libbpf_err(-EINVAL);

	for (i = 0; i < obj->nr_maps; i++) {
		zclose(obj->maps[i].fd);
		if (obj->maps[i].st_ops)
			zfree(&obj->maps[i].st_ops->kern_vdata);
	}

	for (i = 0; i < obj->nr_programs; i++)
		bpf_program__unload(&obj->programs[i]);

	return 0;
}

static int bpf_object__sanitize_maps(struct bpf_object *obj)
{
	struct bpf_map *m;

	bpf_object__for_each_map(m, obj) {
		if (!bpf_map__is_internal(m))
			continue;
		if (!kernel_supports(obj, FEAT_ARRAY_MMAP))
			m->def.map_flags &= ~BPF_F_MMAPABLE;
	}

	return 0;
}

int libbpf_kallsyms_parse(kallsyms_cb_t cb, void *ctx)
{
	char sym_type, sym_name[500];
	unsigned long long sym_addr;
	int ret, err = 0;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		err = -errno;
		pr_warn("failed to open /proc/kallsyms: %d\n", err);
		return err;
	}

	while (true) {
		ret = fscanf(f, "%llx %c %499s%*[^\n]\n",
			     &sym_addr, &sym_type, sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 3) {
			pr_warn("failed to read kallsyms entry: %d\n", ret);
			err = -EINVAL;
			break;
		}

		err = cb(sym_addr, sym_type, sym_name, ctx);
		if (err)
			break;
	}

	fclose(f);
	return err;
}

static int kallsyms_cb(unsigned long long sym_addr, char sym_type,
		       const char *sym_name, void *ctx)
{
	struct bpf_object *obj = ctx;
	const struct btf_type *t;
	struct extern_desc *ext;

	ext = find_extern_by_name(obj, sym_name);
	if (!ext || ext->type != EXT_KSYM)
		return 0;

	t = btf__type_by_id(obj->btf, ext->btf_id);
	if (!btf_is_var(t))
		return 0;

	if (ext->is_set && ext->ksym.addr != sym_addr) {
		pr_warn("extern (ksym) '%s': resolution is ambiguous: 0x%llx or 0x%llx\n",
			sym_name, ext->ksym.addr, sym_addr);
		return -EINVAL;
	}
	if (!ext->is_set) {
		ext->is_set = true;
		ext->ksym.addr = sym_addr;
		pr_debug("extern (ksym) '%s': set to 0x%llx\n", sym_name, sym_addr);
	}
	return 0;
}

static int bpf_object__read_kallsyms_file(struct bpf_object *obj)
{
	return libbpf_kallsyms_parse(kallsyms_cb, obj);
}

static int find_ksym_btf_id(struct bpf_object *obj, const char *ksym_name,
			    __u16 kind, struct btf **res_btf,
			    struct module_btf **res_mod_btf)
{
	struct module_btf *mod_btf;
	struct btf *btf;
	int i, id, err;

	btf = obj->btf_vmlinux;
	mod_btf = NULL;
	id = btf__find_by_name_kind(btf, ksym_name, kind);

	if (id == -ENOENT) {
		err = load_module_btfs(obj);
		if (err)
			return err;

		for (i = 0; i < obj->btf_module_cnt; i++) {
			/* we assume module_btf's BTF FD is always >0 */
			mod_btf = &obj->btf_modules[i];
			btf = mod_btf->btf;
			id = btf__find_by_name_kind_own(btf, ksym_name, kind);
			if (id != -ENOENT)
				break;
		}
	}
	if (id <= 0)
		return -ESRCH;

	*res_btf = btf;
	*res_mod_btf = mod_btf;
	return id;
}

static int bpf_object__resolve_ksym_var_btf_id(struct bpf_object *obj,
					       struct extern_desc *ext)
{
	const struct btf_type *targ_var, *targ_type;
	__u32 targ_type_id, local_type_id;
	struct module_btf *mod_btf = NULL;
	const char *targ_var_name;
	struct btf *btf = NULL;
	int id, err;

	id = find_ksym_btf_id(obj, ext->name, BTF_KIND_VAR, &btf, &mod_btf);
	if (id < 0) {
		if (id == -ESRCH && ext->is_weak)
			return 0;
		pr_warn("extern (var ksym) '%s': not found in kernel BTF\n",
			ext->name);
		return id;
	}

	/* find local type_id */
	local_type_id = ext->ksym.type_id;

	/* find target type_id */
	targ_var = btf__type_by_id(btf, id);
	targ_var_name = btf__name_by_offset(btf, targ_var->name_off);
	targ_type = skip_mods_and_typedefs(btf, targ_var->type, &targ_type_id);

	err = bpf_core_types_are_compat(obj->btf, local_type_id,
					btf, targ_type_id);
	if (err <= 0) {
		const struct btf_type *local_type;
		const char *targ_name, *local_name;

		local_type = btf__type_by_id(obj->btf, local_type_id);
		local_name = btf__name_by_offset(obj->btf, local_type->name_off);
		targ_name = btf__name_by_offset(btf, targ_type->name_off);

		pr_warn("extern (var ksym) '%s': incompatible types, expected [%d] %s %s, but kernel has [%d] %s %s\n",
			ext->name, local_type_id,
			btf_kind_str(local_type), local_name, targ_type_id,
			btf_kind_str(targ_type), targ_name);
		return -EINVAL;
	}

	ext->is_set = true;
	ext->ksym.kernel_btf_obj_fd = mod_btf ? mod_btf->fd : 0;
	ext->ksym.kernel_btf_id = id;
	pr_debug("extern (var ksym) '%s': resolved to [%d] %s %s\n",
		 ext->name, id, btf_kind_str(targ_var), targ_var_name);

	return 0;
}

static int bpf_object__resolve_ksym_func_btf_id(struct bpf_object *obj,
						struct extern_desc *ext)
{
	int local_func_proto_id, kfunc_proto_id, kfunc_id;
	struct module_btf *mod_btf = NULL;
	const struct btf_type *kern_func;
	struct btf *kern_btf = NULL;
	int ret;

	local_func_proto_id = ext->ksym.type_id;

	kfunc_id = find_ksym_btf_id(obj, ext->name, BTF_KIND_FUNC, &kern_btf, &mod_btf);
	if (kfunc_id < 0) {
		if (kfunc_id == -ESRCH && ext->is_weak)
			return 0;
		pr_warn("extern (func ksym) '%s': not found in kernel or module BTFs\n",
			ext->name);
		return kfunc_id;
	}

	kern_func = btf__type_by_id(kern_btf, kfunc_id);
	kfunc_proto_id = kern_func->type;

	ret = bpf_core_types_are_compat(obj->btf, local_func_proto_id,
					kern_btf, kfunc_proto_id);
	if (ret <= 0) {
		pr_warn("extern (func ksym) '%s': func_proto [%d] incompatible with %s [%d]\n",
			ext->name, local_func_proto_id,
			mod_btf ? mod_btf->name : "vmlinux", kfunc_proto_id);
		return -EINVAL;
	}

	/* set index for module BTF fd in fd_array, if unset */
	if (mod_btf && !mod_btf->fd_array_idx) {
		/* insn->off is s16 */
		if (obj->fd_array_cnt == INT16_MAX) {
			pr_warn("extern (func ksym) '%s': module BTF fd index %d too big to fit in bpf_insn offset\n",
				ext->name, mod_btf->fd_array_idx);
			return -E2BIG;
		}
		/* Cannot use index 0 for module BTF fd */
		if (!obj->fd_array_cnt)
			obj->fd_array_cnt = 1;

		ret = libbpf_ensure_mem((void **)&obj->fd_array, &obj->fd_array_cap, sizeof(int),
					obj->fd_array_cnt + 1);
		if (ret)
			return ret;
		mod_btf->fd_array_idx = obj->fd_array_cnt;
		/* we assume module BTF FD is always >0 */
		obj->fd_array[obj->fd_array_cnt++] = mod_btf->fd;
	}

	ext->is_set = true;
	ext->ksym.kernel_btf_id = kfunc_id;
	ext->ksym.btf_fd_idx = mod_btf ? mod_btf->fd_array_idx : 0;
	/* Also set kernel_btf_obj_fd to make sure that bpf_object__relocate_data()
	 * populates FD into ld_imm64 insn when it's used to point to kfunc.
	 * {kernel_btf_id, btf_fd_idx} -> fixup bpf_call.
	 * {kernel_btf_id, kernel_btf_obj_fd} -> fixup ld_imm64.
	 */
	ext->ksym.kernel_btf_obj_fd = mod_btf ? mod_btf->fd : 0;
	pr_debug("extern (func ksym) '%s': resolved to %s [%d]\n",
		 ext->name, mod_btf ? mod_btf->name : "vmlinux", kfunc_id);

	return 0;
}

static int bpf_object__resolve_ksyms_btf_id(struct bpf_object *obj)
{
	const struct btf_type *t;
	struct extern_desc *ext;
	int i, err;

	for (i = 0; i < obj->nr_extern; i++) {
		ext = &obj->externs[i];
		if (ext->type != EXT_KSYM || !ext->ksym.type_id)
			continue;

		if (obj->gen_loader) {
			ext->is_set = true;
			ext->ksym.kernel_btf_obj_fd = 0;
			ext->ksym.kernel_btf_id = 0;
			continue;
		}
		t = btf__type_by_id(obj->btf, ext->btf_id);
		if (btf_is_var(t))
			err = bpf_object__resolve_ksym_var_btf_id(obj, ext);
		else
			err = bpf_object__resolve_ksym_func_btf_id(obj, ext);
		if (err)
			return err;
	}
	return 0;
}

static int bpf_object__resolve_externs(struct bpf_object *obj,
				       const char *extra_kconfig)
{
	bool need_config = false, need_kallsyms = false;
	bool need_vmlinux_btf = false;
	struct extern_desc *ext;
	void *kcfg_data = NULL;
	int err, i;

	if (obj->nr_extern == 0)
		return 0;

	if (obj->kconfig_map_idx >= 0)
		kcfg_data = obj->maps[obj->kconfig_map_idx].mmaped;

	for (i = 0; i < obj->nr_extern; i++) {
		ext = &obj->externs[i];

		if (ext->type == EXT_KSYM) {
			if (ext->ksym.type_id)
				need_vmlinux_btf = true;
			else
				need_kallsyms = true;
			continue;
		} else if (ext->type == EXT_KCFG) {
			void *ext_ptr = kcfg_data + ext->kcfg.data_off;
			__u64 value = 0;

			/* Kconfig externs need actual /proc/config.gz */
			if (str_has_pfx(ext->name, "CONFIG_")) {
				need_config = true;
				continue;
			}

			/* Virtual kcfg externs are customly handled by libbpf */
			if (strcmp(ext->name, "LINUX_KERNEL_VERSION") == 0) {
				value = get_kernel_version();
				if (!value) {
					pr_warn("extern (kcfg) '%s': failed to get kernel version\n", ext->name);
					return -EINVAL;
				}
			} else if (strcmp(ext->name, "LINUX_HAS_BPF_COOKIE") == 0) {
				value = kernel_supports(obj, FEAT_BPF_COOKIE);
			} else if (strcmp(ext->name, "LINUX_HAS_SYSCALL_WRAPPER") == 0) {
				value = kernel_supports(obj, FEAT_SYSCALL_WRAPPER);
			} else if (!str_has_pfx(ext->name, "LINUX_") || !ext->is_weak) {
				/* Currently libbpf supports only CONFIG_ and LINUX_ prefixed
				 * __kconfig externs, where LINUX_ ones are virtual and filled out
				 * customly by libbpf (their values don't come from Kconfig).
				 * If LINUX_xxx variable is not recognized by libbpf, but is marked
				 * __weak, it defaults to zero value, just like for CONFIG_xxx
				 * externs.
				 */
				pr_warn("extern (kcfg) '%s': unrecognized virtual extern\n", ext->name);
				return -EINVAL;
			}

			err = set_kcfg_value_num(ext, ext_ptr, value);
			if (err)
				return err;
			pr_debug("extern (kcfg) '%s': set to 0x%llx\n",
				 ext->name, (long long)value);
		} else {
			pr_warn("extern '%s': unrecognized extern kind\n", ext->name);
			return -EINVAL;
		}
	}
	if (need_config && extra_kconfig) {
		err = bpf_object__read_kconfig_mem(obj, extra_kconfig, kcfg_data);
		if (err)
			return -EINVAL;
		need_config = false;
		for (i = 0; i < obj->nr_extern; i++) {
			ext = &obj->externs[i];
			if (ext->type == EXT_KCFG && !ext->is_set) {
				need_config = true;
				break;
			}
		}
	}
	if (need_config) {
		err = bpf_object__read_kconfig_file(obj, kcfg_data);
		if (err)
			return -EINVAL;
	}
	if (need_kallsyms) {
		err = bpf_object__read_kallsyms_file(obj);
		if (err)
			return -EINVAL;
	}
	if (need_vmlinux_btf) {
		err = bpf_object__resolve_ksyms_btf_id(obj);
		if (err)
			return -EINVAL;
	}
	for (i = 0; i < obj->nr_extern; i++) {
		ext = &obj->externs[i];

		if (!ext->is_set && !ext->is_weak) {
			pr_warn("extern '%s' (strong): not resolved\n", ext->name);
			return -ESRCH;
		} else if (!ext->is_set) {
			pr_debug("extern '%s' (weak): not resolved, defaulting to zero\n",
				 ext->name);
		}
	}

	return 0;
}

static void bpf_map_prepare_vdata(const struct bpf_map *map)
{
	struct bpf_struct_ops *st_ops;
	__u32 i;

	st_ops = map->st_ops;
	for (i = 0; i < btf_vlen(st_ops->type); i++) {
		struct bpf_program *prog = st_ops->progs[i];
		void *kern_data;
		int prog_fd;

		if (!prog)
			continue;

		prog_fd = bpf_program__fd(prog);
		kern_data = st_ops->kern_vdata + st_ops->kern_func_off[i];
		*(unsigned long *)kern_data = prog_fd;
	}
}

static int bpf_object_prepare_struct_ops(struct bpf_object *obj)
{
	int i;

	for (i = 0; i < obj->nr_maps; i++)
		if (bpf_map__is_struct_ops(&obj->maps[i]))
			bpf_map_prepare_vdata(&obj->maps[i]);

	return 0;
}

static int bpf_object_load(struct bpf_object *obj, int extra_log_level, const char *target_btf_path)
{
	int err, i;

	if (!obj)
		return libbpf_err(-EINVAL);

	if (obj->loaded) {
		pr_warn("object '%s': load can't be attempted twice\n", obj->name);
		return libbpf_err(-EINVAL);
	}

	if (obj->gen_loader)
		bpf_gen__init(obj->gen_loader, extra_log_level, obj->nr_programs, obj->nr_maps);

	err = bpf_object__probe_loading(obj);
	err = err ? : bpf_object__load_vmlinux_btf(obj, false);
	err = err ? : bpf_object__resolve_externs(obj, obj->kconfig);
	err = err ? : bpf_object__sanitize_and_load_btf(obj);
	err = err ? : bpf_object__sanitize_maps(obj);
	err = err ? : bpf_object__init_kern_struct_ops_maps(obj);
	err = err ? : bpf_object__create_maps(obj);
	err = err ? : bpf_object__relocate(obj, obj->btf_custom_path ? : target_btf_path);
	err = err ? : bpf_object__load_progs(obj, extra_log_level);
	err = err ? : bpf_object_init_prog_arrays(obj);
	err = err ? : bpf_object_prepare_struct_ops(obj);

	if (obj->gen_loader) {
		/* reset FDs */
		if (obj->btf)
			btf__set_fd(obj->btf, -1);
		for (i = 0; i < obj->nr_maps; i++)
			obj->maps[i].fd = -1;
		if (!err)
			err = bpf_gen__finish(obj->gen_loader, obj->nr_programs, obj->nr_maps);
	}

	/* clean up fd_array */
	zfree(&obj->fd_array);

	/* clean up module BTFs */
	for (i = 0; i < obj->btf_module_cnt; i++) {
		close(obj->btf_modules[i].fd);
		btf__free(obj->btf_modules[i].btf);
		free(obj->btf_modules[i].name);
	}
	free(obj->btf_modules);

	/* clean up vmlinux BTF */
	btf__free(obj->btf_vmlinux);
	obj->btf_vmlinux = NULL;

	obj->loaded = true; /* doesn't matter if successfully or not */

	if (err)
		goto out;

	return 0;
out:
	/* unpin any maps that were auto-pinned during load */
	for (i = 0; i < obj->nr_maps; i++)
		if (obj->maps[i].pinned && !obj->maps[i].reused)
			bpf_map__unpin(&obj->maps[i], NULL);

	bpf_object_unload(obj);
	pr_warn("failed to load object '%s'\n", obj->path);
	return libbpf_err(err);
}

int bpf_object__load(struct bpf_object *obj)
{
	return bpf_object_load(obj, 0, NULL);
}

static int make_parent_dir(const char *path)
{
	char *cp, errmsg[STRERR_BUFSIZE];
	char *dname, *dir;
	int err = 0;

	dname = strdup(path);
	if (dname == NULL)
		return -ENOMEM;

	dir = dirname(dname);
	if (mkdir(dir, 0700) && errno != EEXIST)
		err = -errno;

	free(dname);
	if (err) {
		cp = libbpf_strerror_r(-err, errmsg, sizeof(errmsg));
		pr_warn("failed to mkdir %s: %s\n", path, cp);
	}
	return err;
}

static int check_path(const char *path)
{
	char *cp, errmsg[STRERR_BUFSIZE];
	struct statfs st_fs;
	char *dname, *dir;
	int err = 0;

	if (path == NULL)
		return -EINVAL;

	dname = strdup(path);
	if (dname == NULL)
		return -ENOMEM;

	dir = dirname(dname);
	if (statfs(dir, &st_fs)) {
		cp = libbpf_strerror_r(errno, errmsg, sizeof(errmsg));
		pr_warn("failed to statfs %s: %s\n", dir, cp);
		err = -errno;
	}
	free(dname);

	if (!err && st_fs.f_type != BPF_FS_MAGIC) {
		pr_warn("specified path %s is not on BPF FS\n", path);
		err = -EINVAL;
	}

	return err;
}

int bpf_program__pin(struct bpf_program *prog, const char *path)
{
	char *cp, errmsg[STRERR_BUFSIZE];
	int err;

	if (prog->fd < 0) {
		pr_warn("prog '%s': can't pin program that wasn't loaded\n", prog->name);
		return libbpf_err(-EINVAL);
	}

	err = make_parent_dir(path);
	if (err)
		return libbpf_err(err);

	err = check_path(path);
	if (err)
		return libbpf_err(err);

	if (bpf_obj_pin(prog->fd, path)) {
		err = -errno;
		cp = libbpf_strerror_r(err, errmsg, sizeof(errmsg));
		pr_warn("prog '%s': failed to pin at '%s': %s\n", prog->name, path, cp);
		return libbpf_err(err);
	}

	pr_debug("prog '%s': pinned at '%s'\n", prog->name, path);
	return 0;
}

int bpf_program__unpin(struct bpf_program *prog, const char *path)
{
	int err;

	if (prog->fd < 0) {
		pr_warn("prog '%s': can't unpin program that wasn't loaded\n", prog->name);
		return libbpf_err(-EINVAL);
	}

	err = check_path(path);
	if (err)
		return libbpf_err(err);

	err = unlink(path);
	if (err)
		return libbpf_err(-errno);

	pr_debug("prog '%s': unpinned from '%s'\n", prog->name, path);
	return 0;
}

int bpf_map__pin(struct bpf_map *map, const char *path)
{
	char *cp, errmsg[STRERR_BUFSIZE];
	int err;

	if (map == NULL) {
		pr_warn("invalid map pointer\n");
		return libbpf_err(-EINVAL);
	}

	if (map->pin_path) {
		if (path && strcmp(path, map->pin_path)) {
			pr_warn("map '%s' already has pin path '%s' different from '%s'\n",
				bpf_map__name(map), map->pin_path, path);
			return libbpf_err(-EINVAL);
		} else if (map->pinned) {
			pr_debug("map '%s' already pinned at '%s'; not re-pinning\n",
				 bpf_map__name(map), map->pin_path);
			return 0;
		}
	} else {
		if (!path) {
			pr_warn("missing a path to pin map '%s' at\n",
				bpf_map__name(map));
			return libbpf_err(-EINVAL);
		} else if (map->pinned) {
			pr_warn("map '%s' already pinned\n", bpf_map__name(map));
			return libbpf_err(-EEXIST);
		}

		map->pin_path = strdup(path);
		if (!map->pin_path) {
			err = -errno;
			goto out_err;
		}
	}

	err = make_parent_dir(map->pin_path);
	if (err)
		return libbpf_err(err);

	err = check_path(map->pin_path);
	if (err)
		return libbpf_err(err);

	if (bpf_obj_pin(map->fd, map->pin_path)) {
		err = -errno;
		goto out_err;
	}

	map->pinned = true;
	pr_debug("pinned map '%s'\n", map->pin_path);

	return 0;

out_err:
	cp = libbpf_strerror_r(-err, errmsg, sizeof(errmsg));
	pr_warn("failed to pin map: %s\n", cp);
	return libbpf_err(err);
}

int bpf_map__unpin(struct bpf_map *map, const char *path)
{
	int err;

	if (map == NULL) {
		pr_warn("invalid map pointer\n");
		return libbpf_err(-EINVAL);
	}

	if (map->pin_path) {
		if (path && strcmp(path, map->pin_path)) {
			pr_warn("map '%s' already has pin path '%s' different from '%s'\n",
				bpf_map__name(map), map->pin_path, path);
			return libbpf_err(-EINVAL);
		}
		path = map->pin_path;
	} else if (!path) {
		pr_warn("no path to unpin map '%s' from\n",
			bpf_map__name(map));
		return libbpf_err(-EINVAL);
	}

	err = check_path(path);
	if (err)
		return libbpf_err(err);

	err = unlink(path);
	if (err != 0)
		return libbpf_err(-errno);

	map->pinned = false;
	pr_debug("unpinned map '%s' from '%s'\n", bpf_map__name(map), path);

	return 0;
}

int bpf_map__set_pin_path(struct bpf_map *map, const char *path)
{
	char *new = NULL;

	if (path) {
		new = strdup(path);
		if (!new)
			return libbpf_err(-errno);
	}

	free(map->pin_path);
	map->pin_path = new;
	return 0;
}

__alias(bpf_map__pin_path)
const char *bpf_map__get_pin_path(const struct bpf_map *map);

const char *bpf_map__pin_path(const struct bpf_map *map)
{
	return map->pin_path;
}

bool bpf_map__is_pinned(const struct bpf_map *map)
{
	return map->pinned;
}

static void sanitize_pin_path(char *s)
{
	/* bpffs disallows periods in path names */
	while (*s) {
		if (*s == '.')
			*s = '_';
		s++;
	}
}

int bpf_object__pin_maps(struct bpf_object *obj, const char *path)
{
	struct bpf_map *map;
	int err;

	if (!obj)
		return libbpf_err(-ENOENT);

	if (!obj->loaded) {
		pr_warn("object not yet loaded; load it first\n");
		return libbpf_err(-ENOENT);
	}

	bpf_object__for_each_map(map, obj) {
		char *pin_path = NULL;
		char buf[PATH_MAX];

		if (!map->autocreate)
			continue;

		if (path) {
			err = pathname_concat(buf, sizeof(buf), path, bpf_map__name(map));
			if (err)
				goto err_unpin_maps;
			sanitize_pin_path(buf);
			pin_path = buf;
		} else if (!map->pin_path) {
			continue;
		}

		err = bpf_map__pin(map, pin_path);
		if (err)
			goto err_unpin_maps;
	}

	return 0;

err_unpin_maps:
	while ((map = bpf_object__prev_map(obj, map))) {
		if (!map->pin_path)
			continue;

		bpf_map__unpin(map, NULL);
	}

	return libbpf_err(err);
}
