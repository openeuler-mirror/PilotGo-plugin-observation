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
