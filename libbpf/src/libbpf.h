#ifndef __LIBBPF_LIBBPF_H
#define __LIBBPF_LIBBPF_H

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h> // for size_t
#include <linux/bpf.h>

#include "libbpf_common.h"
#include "libbpf_legacy.h"

#ifdef __cplusplus
extern "C"
{
#endif

    LIBBPF_API __u32 libbpf_major_version(void);
    LIBBPF_API __u32 libbpf_minor_version(void);
    LIBBPF_API const char *libbpf_version_string(void);
    enum libbpf_errno
    {
        __LIBBPF_ERRNO__START = 4000,

        /* Something wrong in libelf */
        LIBBPF_ERRNO__LIBELF = __LIBBPF_ERRNO__START,
        LIBBPF_ERRNO__FORMAT,   /* BPF object format invalid */
        LIBBPF_ERRNO__KVERSION, /* Incorrect or no 'version' section */
        LIBBPF_ERRNO__ENDIAN,   /* Endian mismatch */
        LIBBPF_ERRNO__INTERNAL, /* Internal error in libbpf */
        LIBBPF_ERRNO__RELOC,    /* Relocation failed */
        LIBBPF_ERRNO__LOAD,     /* Load program failure for unknown reason */
        LIBBPF_ERRNO__VERIFY,   /* Kernel verifier blocks program loading */
        LIBBPF_ERRNO__PROG2BIG, /* Program too big */
        LIBBPF_ERRNO__KVER,     /* Incorrect kernel version */
        LIBBPF_ERRNO__PROGTYPE, /* Kernel doesn't support this program type */
        LIBBPF_ERRNO__WRNGPID,  /* Wrong pid in netlink message */
        LIBBPF_ERRNO__INVSEQ,   /* Invalid netlink sequence */
        LIBBPF_ERRNO__NLPARSE,  /* netlink parsing error */
        __LIBBPF_ERRNO__END,
    };

    LIBBPF_API int libbpf_strerror(int err, char *buf, size_t size);
    LIBBPF_API const char *libbpf_bpf_attach_type_str(enum bpf_attach_type t);

    LIBBPF_API const char *libbpf_bpf_link_type_str(enum bpf_link_type t);

    LIBBPF_API const char *libbpf_bpf_map_type_str(enum bpf_map_type t);

    LIBBPF_API const char *libbpf_bpf_prog_type_str(enum bpf_prog_type t);
    enum libbpf_print_level
    {
        LIBBPF_WARN,
        LIBBPF_INFO,
        LIBBPF_DEBUG,
    };

    typedef int (*libbpf_print_fn_t)(enum libbpf_print_level level,
                                     const char *, va_list ap);
    LIBBPF_API libbpf_print_fn_t libbpf_set_print(libbpf_print_fn_t fn);
    struct bpf_object;
    struct bpf_object_open_opts
    {
        /* size of this struct, for forward/backward compatibility */
        size_t sz;

        const char *object_name;
        /* parse map definitions non-strictly, allowing extra attributes/data */
        bool relaxed_maps;

        const char *pin_root_path;

        __u32 : 32;
        const char *kconfig;

        const char *btf_custom_path;

        char *kernel_log_buf;
        size_t kernel_log_size;

        __u32 kernel_log_level;

        size_t : 0;
    };
#define bpf_object_open_opts__last_field kernel_log_level
    LIBBPF_API struct bpf_object *bpf_object__open(const char *path);
    LIBBPF_API struct bpf_object *
    bpf_object__open_file(const char *path, const struct bpf_object_open_opts *opts);

    LIBBPF_API struct bpf_object *
    bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
                         const struct bpf_object_open_opts *opts);
    LIBBPF_API int bpf_object__load(struct bpf_object *obj);
    LIBBPF_API void bpf_object__close(struct bpf_object *obj);
    LIBBPF_API int bpf_object__pin_maps(struct bpf_object *obj, const char *path);

    LIBBPF_API int bpf_object__unpin_maps(struct bpf_object *obj,
                                          const char *path);
    LIBBPF_API int bpf_object__pin_programs(struct bpf_object *obj,
                                            const char *path);
    LIBBPF_API int bpf_object__unpin_programs(struct bpf_object *obj,
                                              const char *path);
    LIBBPF_API int bpf_object__pin(struct bpf_object *object, const char *path);

    LIBBPF_API const char *bpf_object__name(const struct bpf_object *obj);
    LIBBPF_API unsigned int bpf_object__kversion(const struct bpf_object *obj);
    LIBBPF_API int bpf_object__set_kversion(struct bpf_object *obj, __u32 kern_version);

    struct btf;
    LIBBPF_API struct btf *bpf_object__btf(const struct bpf_object *obj);
    LIBBPF_API int bpf_object__btf_fd(const struct bpf_object *obj);

    LIBBPF_API struct bpf_program *
    bpf_object__find_program_by_name(const struct bpf_object *obj,
                                     const char *name);

    LIBBPF_API int
    libbpf_prog_type_by_name(const char *name, enum bpf_prog_type *prog_type,
                             enum bpf_attach_type *expected_attach_type);
    LIBBPF_API int libbpf_attach_type_by_name(const char *name,
                                              enum bpf_attach_type *attach_type);
    LIBBPF_API int libbpf_find_vmlinux_btf_id(const char *name,
                                              enum bpf_attach_type attach_type);

    /* Accessors of bpf_program */
    struct bpf_program;
    LIBBPF_API struct bpf_program *
    bpf_object__next_program(const struct bpf_object *obj, struct bpf_program *prog);

#define bpf_object__for_each_program(pos, obj)          \
    for ((pos) = bpf_object__next_program((obj), NULL); \
         (pos) != NULL;                                 \
         (pos) = bpf_object__next_program((obj), (pos)))

    LIBBPF_API struct bpf_program *
    bpf_object__prev_program(const struct bpf_object *obj, struct bpf_program *prog);

    LIBBPF_API void bpf_program__set_ifindex(struct bpf_program *prog,
                                             __u32 ifindex);

    LIBBPF_API const char *bpf_program__name(const struct bpf_program *prog);
    LIBBPF_API const char *bpf_program__section_name(const struct bpf_program *prog);
    LIBBPF_API bool bpf_program__autoload(const struct bpf_program *prog);
    LIBBPF_API int bpf_program__set_autoload(struct bpf_program *prog, bool autoload);
    LIBBPF_API bool bpf_program__autoattach(const struct bpf_program *prog);
    LIBBPF_API void bpf_program__set_autoattach(struct bpf_program *prog, bool autoattach);

    struct bpf_insn;

    LIBBPF_API const struct bpf_insn *bpf_program__insns(const struct bpf_program *prog);

    LIBBPF_API int bpf_program__set_insns(struct bpf_program *prog,
                                          struct bpf_insn *new_insns, size_t new_insn_cnt);

    LIBBPF_API size_t bpf_program__insn_cnt(const struct bpf_program *prog);

    LIBBPF_API int bpf_program__fd(const struct bpf_program *prog);
    LIBBPF_API int bpf_program__pin(struct bpf_program *prog, const char *path);

    LIBBPF_API int bpf_program__unpin(struct bpf_program *prog, const char *path);
    LIBBPF_API void bpf_program__unload(struct bpf_program *prog);

    struct bpf_link;

    LIBBPF_API struct bpf_link *bpf_link__open(const char *path);
    LIBBPF_API int bpf_link__fd(const struct bpf_link *link);
    LIBBPF_API const char *bpf_link__pin_path(const struct bpf_link *link);
    LIBBPF_API int bpf_link__pin(struct bpf_link *link, const char *path);
    LIBBPF_API int bpf_link__unpin(struct bpf_link *link);
    LIBBPF_API int bpf_link__update_program(struct bpf_link *link,
                                            struct bpf_program *prog);
    LIBBPF_API void bpf_link__disconnect(struct bpf_link *link);
    LIBBPF_API int bpf_link__detach(struct bpf_link *link);
    LIBBPF_API int bpf_link__destroy(struct bpf_link *link);

    LIBBPF_API struct bpf_link *
    bpf_program__attach(const struct bpf_program *prog);

    struct bpf_perf_event_opts
    {
        /* size of this struct, for forward/backward compatibility */
        size_t sz;
        /* custom user-provided value fetchable through bpf_get_attach_cookie() */
        __u64 bpf_cookie;
        /* don't use BPF link when attach BPF program */
        bool force_ioctl_attach;
        size_t : 0;
    };
#define bpf_perf_event_opts__last_field force_ioctl_attach

    LIBBPF_API struct bpf_link *
    bpf_program__attach_perf_event(const struct bpf_program *prog, int pfd);

    LIBBPF_API struct bpf_link *
    bpf_program__attach_perf_event_opts(const struct bpf_program *prog, int pfd,
                                        const struct bpf_perf_event_opts *opts);

    enum probe_attach_mode
    {
        /* attach probe in latest supported mode by kernel */
        PROBE_ATTACH_MODE_DEFAULT = 0,
        /* attach probe in legacy mode, using debugfs/tracefs */
        PROBE_ATTACH_MODE_LEGACY,
        /* create perf event with perf_event_open() syscall */
        PROBE_ATTACH_MODE_PERF,
        /* attach probe with BPF link */
        PROBE_ATTACH_MODE_LINK,
    };

    struct bpf_kprobe_opts
    {
        /* size of this struct, for forward/backward compatibility */
        size_t sz;
        /* custom user-provided value fetchable through bpf_get_attach_cookie() */
        __u64 bpf_cookie;
        /* function's offset to install kprobe to */
        size_t offset;
        /* kprobe is return probe */
        bool retprobe;
        /* kprobe attach mode */
        enum probe_attach_mode attach_mode;
        size_t : 0;
    };
#define bpf_kprobe_opts__last_field attach_mode

    LIBBPF_API struct bpf_link *
    bpf_program__attach_kprobe(const struct bpf_program *prog, bool retprobe,
                               const char *func_name);
    LIBBPF_API struct bpf_link *
    bpf_program__attach_kprobe_opts(const struct bpf_program *prog,
                                    const char *func_name,
                                    const struct bpf_kprobe_opts *opts);

    struct bpf_kprobe_multi_opts
    {
        /* size of this struct, for forward/backward compatibility */
        size_t sz;
        /* array of function symbols to attach */
        const char **syms;
        /* array of function addresses to attach */
        const unsigned long *addrs;
        /* array of user-provided values fetchable through bpf_get_attach_cookie */
        const __u64 *cookies;
        /* number of elements in syms/addrs/cookies arrays */
        size_t cnt;
        /* create return kprobes */
        bool retprobe;
        size_t : 0;
    };

#define bpf_kprobe_multi_opts__last_field retprobe

    LIBBPF_API struct bpf_link *
    bpf_program__attach_kprobe_multi_opts(const struct bpf_program *prog,
                                          const char *pattern,
                                          struct bpf_kprobe_multi_opts *opts);

    struct bpf_ksyscall_opts
    {
        /* size of this struct, for forward/backward compatibility */
        size_t sz;
        /* custom user-provided value fetchable through bpf_get_attach_cookie() */
        __u64 bpf_cookie;
        /* attach as return probe? */
        bool retprobe;
        size_t : 0;
    };
#define bpf_ksyscall_opts__last_field retprobe

    LIBBPF_API struct bpf_link *
    bpf_program__attach_ksyscall(const struct bpf_program *prog,
                                 const char *syscall_name,
                                 const struct bpf_ksyscall_opts *opts);

    struct bpf_uprobe_opts
    {
        size_t sz;
        size_t ref_ctr_offset;
        __u64 bpf_cookie;
        bool retprobe;
        const char *func_name;
        enum probe_attach_mode attach_mode;
        size_t : 0;
    };
#define bpf_uprobe_opts__last_field attach_mode

    LIBBPF_API struct bpf_link *
    bpf_program__attach_uprobe(const struct bpf_program *prog, bool retprobe,
                               pid_t pid, const char *binary_path,
                               size_t func_offset);

    LIBBPF_API struct bpf_link *
    bpf_program__attach_uprobe_opts(const struct bpf_program *prog, pid_t pid,
                                    const char *binary_path, size_t func_offset,
                                    const struct bpf_uprobe_opts *opts);

    struct bpf_usdt_opts
    {
        size_t sz;
        __u64 usdt_cookie;
        size_t : 0;
    };
#define bpf_usdt_opts__last_field usdt_cookie

    LIBBPF_API struct bpf_link *
    bpf_program__attach_usdt(const struct bpf_program *prog,
                             pid_t pid, const char *binary_path,
                             const char *usdt_provider, const char *usdt_name,
                             const struct bpf_usdt_opts *opts);

    struct bpf_tracepoint_opts
    {
        size_t sz;
        __u64 bpf_cookie;
    };
#define bpf_tracepoint_opts__last_field bpf_cookie

    LIBBPF_API struct bpf_link *
    bpf_program__attach_tracepoint(const struct bpf_program *prog,
                                   const char *tp_category,
                                   const char *tp_name);
    LIBBPF_API struct bpf_link *
    bpf_program__attach_tracepoint_opts(const struct bpf_program *prog,
                                        const char *tp_category,
                                        const char *tp_name,
                                        const struct bpf_tracepoint_opts *opts);

    LIBBPF_API struct bpf_link *
    bpf_program__attach_raw_tracepoint(const struct bpf_program *prog,
                                       const char *tp_name);

    struct bpf_trace_opts
    {
        size_t sz;
        __u64 cookie;
    };
#define bpf_trace_opts__last_field cookie

    LIBBPF_API struct bpf_link *
    bpf_program__attach_trace(const struct bpf_program *prog);
    LIBBPF_API struct bpf_link *
    bpf_program__attach_trace_opts(const struct bpf_program *prog, const struct bpf_trace_opts *opts);

    LIBBPF_API struct bpf_link *
    bpf_program__attach_lsm(const struct bpf_program *prog);
    LIBBPF_API struct bpf_link *
    bpf_program__attach_cgroup(const struct bpf_program *prog, int cgroup_fd);
    LIBBPF_API struct bpf_link *
    bpf_program__attach_netns(const struct bpf_program *prog, int netns_fd);
    LIBBPF_API struct bpf_link *
    bpf_program__attach_xdp(const struct bpf_program *prog, int ifindex);
    LIBBPF_API struct bpf_link *
    bpf_program__attach_freplace(const struct bpf_program *prog,
                                 int target_fd, const char *attach_func_name);

    struct bpf_map;

    LIBBPF_API struct bpf_link *bpf_map__attach_struct_ops(const struct bpf_map *map);
    LIBBPF_API int bpf_link__update_map(struct bpf_link *link, const struct bpf_map *map);

    struct bpf_iter_attach_opts
    {
        size_t sz; /* size of this struct for forward/backward compatibility */
        union bpf_iter_link_info *link_info;
        __u32 link_info_len;
    };
#define bpf_iter_attach_opts__last_field link_info_len

    LIBBPF_API struct bpf_link *
    bpf_program__attach_iter(const struct bpf_program *prog,
                             const struct bpf_iter_attach_opts *opts);

    LIBBPF_API enum bpf_prog_type bpf_program__type(const struct bpf_program *prog);

    LIBBPF_API int bpf_program__set_type(struct bpf_program *prog,
                                         enum bpf_prog_type type);

    LIBBPF_API enum bpf_attach_type
    bpf_program__expected_attach_type(const struct bpf_program *prog);

    LIBBPF_API int
    bpf_program__set_expected_attach_type(struct bpf_program *prog,
                                          enum bpf_attach_type type);

    LIBBPF_API __u32 bpf_program__flags(const struct bpf_program *prog);
    LIBBPF_API int bpf_program__set_flags(struct bpf_program *prog, __u32 flags);

    LIBBPF_API __u32 bpf_program__log_level(const struct bpf_program *prog);
    LIBBPF_API int bpf_program__set_log_level(struct bpf_program *prog, __u32 log_level);
    LIBBPF_API const char *bpf_program__log_buf(const struct bpf_program *prog, size_t *log_size);
    LIBBPF_API int bpf_program__set_log_buf(struct bpf_program *prog, char *log_buf, size_t log_size);

    LIBBPF_API int
    bpf_program__set_attach_target(struct bpf_program *prog, int attach_prog_fd,
                                   const char *attach_func_name);
    LIBBPF_API struct bpf_map *
    bpf_object__find_map_by_name(const struct bpf_object *obj, const char *name);

    LIBBPF_API int
    bpf_object__find_map_fd_by_name(const struct bpf_object *obj, const char *name);

    LIBBPF_API struct bpf_map *
    bpf_object__next_map(const struct bpf_object *obj, const struct bpf_map *map);

#define bpf_object__for_each_map(pos, obj)          \
    for ((pos) = bpf_object__next_map((obj), NULL); \
         (pos) != NULL;                             \
         (pos) = bpf_object__next_map((obj), (pos)))
#define bpf_map__for_each bpf_object__for_each_map

    LIBBPF_API struct bpf_map *
    bpf_object__prev_map(const struct bpf_object *obj, const struct bpf_map *map);

    LIBBPF_API int bpf_map__set_autocreate(struct bpf_map *map, bool autocreate);
    LIBBPF_API bool bpf_map__autocreate(const struct bpf_map *map);

    LIBBPF_API int bpf_map__fd(const struct bpf_map *map);
    LIBBPF_API int bpf_map__reuse_fd(struct bpf_map *map, int fd);
    LIBBPF_API const char *bpf_map__name(const struct bpf_map *map);
    /* get/set map type */
    LIBBPF_API enum bpf_map_type bpf_map__type(const struct bpf_map *map);
    LIBBPF_API int bpf_map__set_type(struct bpf_map *map, enum bpf_map_type type);
    /* get/set map size (max_entries) */
    LIBBPF_API __u32 bpf_map__max_entries(const struct bpf_map *map);
    LIBBPF_API int bpf_map__set_max_entries(struct bpf_map *map, __u32 max_entries);
    /* get/set map flags */
    LIBBPF_API __u32 bpf_map__map_flags(const struct bpf_map *map);
    LIBBPF_API int bpf_map__set_map_flags(struct bpf_map *map, __u32 flags);
    /* get/set map NUMA node */
    LIBBPF_API __u32 bpf_map__numa_node(const struct bpf_map *map);
    LIBBPF_API int bpf_map__set_numa_node(struct bpf_map *map, __u32 numa_node);
    /* get/set map key size */
    LIBBPF_API __u32 bpf_map__key_size(const struct bpf_map *map);
    LIBBPF_API int bpf_map__set_key_size(struct bpf_map *map, __u32 size);
    /* get/set map value size */
    LIBBPF_API __u32 bpf_map__value_size(const struct bpf_map *map);
    LIBBPF_API int bpf_map__set_value_size(struct bpf_map *map, __u32 size);
    /* get map key/value BTF type IDs */
    LIBBPF_API __u32 bpf_map__btf_key_type_id(const struct bpf_map *map);
    LIBBPF_API __u32 bpf_map__btf_value_type_id(const struct bpf_map *map);
    /* get/set map if_index */
    LIBBPF_API __u32 bpf_map__ifindex(const struct bpf_map *map);
    LIBBPF_API int bpf_map__set_ifindex(struct bpf_map *map, __u32 ifindex);
    /* get/set map map_extra flags */
    LIBBPF_API __u64 bpf_map__map_extra(const struct bpf_map *map);
    LIBBPF_API int bpf_map__set_map_extra(struct bpf_map *map, __u64 map_extra);

    LIBBPF_API int bpf_map__set_initial_value(struct bpf_map *map,
                                              const void *data, size_t size);
    LIBBPF_API const void *bpf_map__initial_value(struct bpf_map *map, size_t *psize);
    LIBBPF_API bool bpf_map__is_internal(const struct bpf_map *map);

    LIBBPF_API int bpf_map__set_pin_path(struct bpf_map *map, const char *path);

    LIBBPF_API const char *bpf_map__pin_path(const struct bpf_map *map);

    LIBBPF_API bool bpf_map__is_pinned(const struct bpf_map *map);

    LIBBPF_API int bpf_map__pin(struct bpf_map *map, const char *path);

    LIBBPF_API int bpf_map__unpin(struct bpf_map *map, const char *path);

    LIBBPF_API int bpf_map__set_inner_map_fd(struct bpf_map *map, int fd);
    LIBBPF_API struct bpf_map *bpf_map__inner_map(struct bpf_map *map);

    LIBBPF_API int bpf_map__lookup_elem(const struct bpf_map *map,
                                        const void *key, size_t key_sz,
                                        void *value, size_t value_sz, __u64 flags);

    LIBBPF_API int bpf_map__update_elem(const struct bpf_map *map,
                                        const void *key, size_t key_sz,
                                        const void *value, size_t value_sz, __u64 flags);

    LIBBPF_API int bpf_map__delete_elem(const struct bpf_map *map,
                                        const void *key, size_t key_sz, __u64 flags);
    LIBBPF_API int bpf_map__lookup_and_delete_elem(const struct bpf_map *map,
                                                   const void *key, size_t key_sz,
                                                   void *value, size_t value_sz, __u64 flags);
    LIBBPF_API int bpf_map__get_next_key(const struct bpf_map *map,
                                         const void *cur_key, void *next_key, size_t key_sz);

    struct bpf_xdp_set_link_opts
    {
        size_t sz;
        int old_fd;
        size_t : 0;
    };
#define bpf_xdp_set_link_opts__last_field old_fd

    struct bpf_xdp_attach_opts
    {
        size_t sz;
        int old_prog_fd;
        size_t : 0;
    };
#define bpf_xdp_attach_opts__last_field old_prog_fd

    struct bpf_xdp_query_opts
    {
        size_t sz;
        __u32 prog_id;       /* output */
        __u32 drv_prog_id;   /* output */
        __u32 hw_prog_id;    /* output */
        __u32 skb_prog_id;   /* output */
        __u8 attach_mode;    /* output */
        __u64 feature_flags; /* output */
        size_t : 0;
    };
#define bpf_xdp_query_opts__last_field feature_flags

    LIBBPF_API int bpf_xdp_attach(int ifindex, int prog_fd, __u32 flags,
                                  const struct bpf_xdp_attach_opts *opts);
    LIBBPF_API int bpf_xdp_detach(int ifindex, __u32 flags,
                                  const struct bpf_xdp_attach_opts *opts);
    LIBBPF_API int bpf_xdp_query(int ifindex, int flags, struct bpf_xdp_query_opts *opts);
    LIBBPF_API int bpf_xdp_query_id(int ifindex, int flags, __u32 *prog_id);

    enum bpf_tc_attach_point
    {
        BPF_TC_INGRESS = 1 << 0,
        BPF_TC_EGRESS = 1 << 1,
        BPF_TC_CUSTOM = 1 << 2,
    };

#define BPF_TC_PARENT(a, b) \
    ((((a) << 16) & 0xFFFF0000U) | ((b) & 0x0000FFFFU))

    enum bpf_tc_flags
    {
        BPF_TC_F_REPLACE = 1 << 0,
    };

    struct bpf_tc_hook
    {
        size_t sz;
        int ifindex;
        enum bpf_tc_attach_point attach_point;
        __u32 parent;
        size_t : 0;
    };
#define bpf_tc_hook__last_field parent

    struct bpf_tc_opts
    {
        size_t sz;
        int prog_fd;
        __u32 flags;
        __u32 prog_id;
        __u32 handle;
        __u32 priority;
        size_t : 0;
    };
#define bpf_tc_opts__last_field priority

    LIBBPF_API int bpf_tc_hook_create(struct bpf_tc_hook *hook);
    LIBBPF_API int bpf_tc_hook_destroy(struct bpf_tc_hook *hook);
    LIBBPF_API int bpf_tc_attach(const struct bpf_tc_hook *hook,
                                 struct bpf_tc_opts *opts);
    LIBBPF_API int bpf_tc_detach(const struct bpf_tc_hook *hook,
                                 const struct bpf_tc_opts *opts);
    LIBBPF_API int bpf_tc_query(const struct bpf_tc_hook *hook,
                                struct bpf_tc_opts *opts);

    /* Ring buffer APIs */
    struct ring_buffer;
    struct user_ring_buffer;

    typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);

    struct ring_buffer_opts
    {
        size_t sz; /* size of this struct, for forward/backward compatibility */
    };
#define ring_buffer_opts__last_field sz

    LIBBPF_API struct ring_buffer *
    ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx,
                     const struct ring_buffer_opts *opts);
    LIBBPF_API void ring_buffer__free(struct ring_buffer *rb);
    LIBBPF_API int ring_buffer__add(struct ring_buffer *rb, int map_fd,
                                    ring_buffer_sample_fn sample_cb, void *ctx);
    LIBBPF_API int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms);
    LIBBPF_API int ring_buffer__consume(struct ring_buffer *rb);
    LIBBPF_API int ring_buffer__epoll_fd(const struct ring_buffer *rb);

    struct user_ring_buffer_opts
    {
        size_t sz; /* size of this struct, for forward/backward compatibility */
    };

#define user_ring_buffer_opts__last_field sz

    LIBBPF_API struct user_ring_buffer *
    user_ring_buffer__new(int map_fd, const struct user_ring_buffer_opts *opts);

    LIBBPF_API void *user_ring_buffer__reserve(struct user_ring_buffer *rb, __u32 size);

    LIBBPF_API void *user_ring_buffer__reserve_blocking(struct user_ring_buffer *rb,
                                                        __u32 size,
                                                        int timeout_ms);
    LIBBPF_API void user_ring_buffer__submit(struct user_ring_buffer *rb, void *sample);
    LIBBPF_API void user_ring_buffer__discard(struct user_ring_buffer *rb, void *sample);

    LIBBPF_API void user_ring_buffer__free(struct user_ring_buffer *rb);

    struct perf_buffer;

    typedef void (*perf_buffer_sample_fn)(void *ctx, int cpu,
                                          void *data, __u32 size);
    typedef void (*perf_buffer_lost_fn)(void *ctx, int cpu, __u64 cnt);

    /* common use perf buffer options */
    struct perf_buffer_opts
    {
        size_t sz;
        __u32 sample_period;
        size_t : 0;
    };
#define perf_buffer_opts__last_field sample_period

    LIBBPF_API struct perf_buffer *
    perf_buffer__new(int map_fd, size_t page_cnt,
                     perf_buffer_sample_fn sample_cb, perf_buffer_lost_fn lost_cb, void *ctx,
                     const struct perf_buffer_opts *opts);

    enum bpf_perf_event_ret
    {
        LIBBPF_PERF_EVENT_DONE = 0,
        LIBBPF_PERF_EVENT_ERROR = -1,
        LIBBPF_PERF_EVENT_CONT = -2,
    };

    struct perf_event_header;

    typedef enum bpf_perf_event_ret (*perf_buffer_event_fn)(void *ctx, int cpu, struct perf_event_header *event);

    struct perf_buffer_raw_opts
    {
        size_t sz;
        long : 0;
        long : 0;

        int cpu_cnt;
        int *cpus;
        int *map_keys;
    };
#define perf_buffer_raw_opts__last_field map_keys

    struct perf_event_attr;

    LIBBPF_API struct perf_buffer *
    perf_buffer__new_raw(int map_fd, size_t page_cnt, struct perf_event_attr *attr,
                         perf_buffer_event_fn event_cb, void *ctx,
                         const struct perf_buffer_raw_opts *opts);

    LIBBPF_API void perf_buffer__free(struct perf_buffer *pb);
    LIBBPF_API int perf_buffer__epoll_fd(const struct perf_buffer *pb);
    LIBBPF_API int perf_buffer__poll(struct perf_buffer *pb, int timeout_ms);
    LIBBPF_API int perf_buffer__consume(struct perf_buffer *pb);
    LIBBPF_API int perf_buffer__consume_buffer(struct perf_buffer *pb, size_t buf_idx);
    LIBBPF_API size_t perf_buffer__buffer_cnt(const struct perf_buffer *pb);
    LIBBPF_API int perf_buffer__buffer_fd(const struct perf_buffer *pb, size_t buf_idx);
    LIBBPF_API int perf_buffer__buffer(struct perf_buffer *pb, int buf_idx, void **buf,
                                       size_t *buf_size);

    struct bpf_prog_linfo;
    struct bpf_prog_info;

    LIBBPF_API void bpf_prog_linfo__free(struct bpf_prog_linfo *prog_linfo);
    LIBBPF_API struct bpf_prog_linfo *
    bpf_prog_linfo__new(const struct bpf_prog_info *info);
    LIBBPF_API const struct bpf_line_info *
    bpf_prog_linfo__lfind_addr_func(const struct bpf_prog_linfo *prog_linfo,
                                    __u64 addr, __u32 func_idx, __u32 nr_skip);
    LIBBPF_API const struct bpf_line_info *
    bpf_prog_linfo__lfind(const struct bpf_prog_linfo *prog_linfo,
                          __u32 insn_off, __u32 nr_skip);

    LIBBPF_API int libbpf_probe_bpf_prog_type(enum bpf_prog_type prog_type, const void *opts);
    LIBBPF_API int libbpf_probe_bpf_map_type(enum bpf_map_type map_type, const void *opts);

    LIBBPF_API int libbpf_probe_bpf_helper(enum bpf_prog_type prog_type,
                                           enum bpf_func_id helper_id, const void *opts);
    LIBBPF_API int libbpf_num_possible_cpus(void);

    struct bpf_map_skeleton
    {
        const char *name;
        struct bpf_map **map;
        void **mmaped;
    };

    struct bpf_prog_skeleton
    {
        const char *name;
        struct bpf_program **prog;
        struct bpf_link **link;
    };

    struct bpf_object_skeleton
    {
        size_t sz; /* size of this struct, for forward/backward compatibility */

        const char *name;
        const void *data;
        size_t data_sz;

        struct bpf_object **obj;

        int map_cnt;
        int map_skel_sz; /* sizeof(struct bpf_map_skeleton) */
        struct bpf_map_skeleton *maps;

        int prog_cnt;
        int prog_skel_sz; /* sizeof(struct bpf_prog_skeleton) */
        struct bpf_prog_skeleton *progs;
    };
    LIBBPF_API int
    bpf_object__open_skeleton(struct bpf_object_skeleton *s,
                              const struct bpf_object_open_opts *opts);
    LIBBPF_API int bpf_object__load_skeleton(struct bpf_object_skeleton *s);
    LIBBPF_API int bpf_object__attach_skeleton(struct bpf_object_skeleton *s);
    LIBBPF_API void bpf_object__detach_skeleton(struct bpf_object_skeleton *s);
    LIBBPF_API void bpf_object__destroy_skeleton(struct bpf_object_skeleton *s);

    struct bpf_var_skeleton
    {
        const char *name;
        struct bpf_map **map;
        void **addr;
    };
