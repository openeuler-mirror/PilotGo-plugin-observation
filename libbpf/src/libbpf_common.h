/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __LIBBPF_LIBBPF_COMMON_H
#define __LIBBPF_LIBBPF_COMMON_H

#include <string.h>
#include "libbpf_version.h"

#ifndef LIBBPF_API
#define LIBBPF_API __attribute__((visibility("default")))
#endif

#define LIBBPF_DEPRECATED(msg) __attribute__((deprecated(msg)))

/* Mark a symbol as deprecated when libbpf version is >= {major}.{minor} */
#define LIBBPF_DEPRECATED_SINCE(major, minor, msg) \
    __LIBBPF_MARK_DEPRECATED_##major##_##minor(LIBBPF_DEPRECATED("libbpf v" #major "." #minor "+: " msg))

#define __LIBBPF_CURRENT_VERSION_GEQ(major, minor) \
    (LIBBPF_MAJOR_VERSION > (major) ||             \
     (LIBBPF_MAJOR_VERSION == (major) && LIBBPF_MINOR_VERSION >= (minor)))

#if __LIBBPF_CURRENT_VERSION_GEQ(1, 0)
#define __LIBBPF_MARK_DEPRECATED_1_0(X) X
#else
#define __LIBBPF_MARK_DEPRECATED_1_0(X)
#endif

#define ___libbpf_cat(A, B) A##B
#define ___libbpf_select(NAME, NUM) ___libbpf_cat(NAME, NUM)
#define ___libbpf_nth(_1, _2, _3, _4, _5, _6, N, ...) N
#define ___libbpf_cnt(...) ___libbpf_nth(__VA_ARGS__, 6, 5, 4, 3, 2, 1)
#define ___libbpf_overload(NAME, ...) ___libbpf_select(NAME, ___libbpf_cnt(__VA_ARGS__))(__VA_ARGS__)

#define LIBBPF_OPTS(TYPE, NAME, ...)               \
    struct TYPE NAME = (                           \
        {                                          \
            memset(&NAME, 0, sizeof(struct TYPE)); \
            (struct TYPE){                         \
                .sz = sizeof(struct TYPE),         \
                __VA_ARGS__};                      \
        })

#endif /* __LIBBPF_LIBBPF_COMMON_H */
