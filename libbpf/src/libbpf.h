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