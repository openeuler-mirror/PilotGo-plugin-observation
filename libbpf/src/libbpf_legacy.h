/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __LIBBPF_LEGACY_BPF_H
#define __LIBBPF_LEGACY_BPF_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "libbpf_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

    enum libbpf_strict_mode
    {

        LIBBPF_STRICT_ALL = 0xffffffff,

        LIBBPF_STRICT_NONE = 0x00,

        LIBBPF_STRICT_CLEAN_PTRS = 0x01,

        LIBBPF_STRICT_DIRECT_ERRS = 0x02,

        LIBBPF_STRICT_SEC_NAME = 0x04,

        LIBBPF_STRICT_NO_OBJECT_LIST = 0x08,

        LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK = 0x10,

        LIBBPF_STRICT_MAP_DEFINITIONS = 0x20,

        __LIBBPF_STRICT_LAST,
    };

    LIBBPF_API int libbpf_set_strict_mode(enum libbpf_strict_mode mode);

    LIBBPF_API long libbpf_get_error(const void *ptr);

#define DECLARE_LIBBPF_OPTS LIBBPF_OPTS

    struct bpf_program;
    struct bpf_map;
    struct btf;
    struct btf_ext;

    LIBBPF_API struct btf *libbpf_find_kernel_btf(void);

    LIBBPF_API enum bpf_prog_type bpf_program__get_type(const struct bpf_program *prog);
    LIBBPF_API enum bpf_attach_type bpf_program__get_expected_attach_type(const struct bpf_program *prog);
    LIBBPF_API const char *bpf_map__get_pin_path(const struct bpf_map *map);
    LIBBPF_API const void *btf__get_raw_data(const struct btf *btf, __u32 *size);
    LIBBPF_API const void *btf_ext__get_raw_data(const struct btf_ext *btf_ext, __u32 *size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __LIBBPF_LEGACY_BPF_H */
