/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __LIBBPF_LIBBPF_INTERNAL_H
#define __LIBBPF_LIBBPF_INTERNAL_H

#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <linux/err.h>
#include <fcntl.h>
#include <unistd.h>
#include "relo_core.h"

/* make sure libbpf doesn't use kernel-only integer typedefs */
#pragma GCC poison u8 u16 u32 u64 s8 s16 s32 s64

/* prevent accidental re-addition of reallocarray() */
#pragma GCC poison reallocarray

#include "libbpf.h"
#include "btf.h"

#ifndef EM_BPF
#define EM_BPF 247
#endif

#ifndef R_BPF_64_64
#define R_BPF_64_64 1
#endif
#ifndef R_BPF_64_ABS64
#define R_BPF_64_ABS64 2
#endif
#ifndef R_BPF_64_ABS32
#define R_BPF_64_ABS32 3
#endif
#ifndef R_BPF_64_32
#define R_BPF_64_32 10
#endif

#ifndef SHT_LLVM_ADDRSIG
#define SHT_LLVM_ADDRSIG 0x6FFF4C03
#endif

/* if libelf is old and doesn't support mmap(), fall back to read() */
#ifndef ELF_C_READ_MMAP
#define ELF_C_READ_MMAP ELF_C_READ
#endif

/* Older libelf all end up in this expression, for both 32 and 64 bit */
#ifndef ELF64_ST_VISIBILITY
#define ELF64_ST_VISIBILITY(o) ((o)&0x03)
#endif

#define BTF_INFO_ENC(kind, kind_flag, vlen) \
    ((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen)&BTF_MAX_VLEN))
#define BTF_TYPE_ENC(name, info, size_or_type) (name), (info), (size_or_type)
#define BTF_INT_ENC(encoding, bits_offset, nr_bits) \
    ((encoding) << 24 | (bits_offset) << 16 | (nr_bits))
#define BTF_TYPE_INT_ENC(name, encoding, bits_offset, bits, sz) \
    BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_INT, 0, 0), sz),   \
        BTF_INT_ENC(encoding, bits_offset, bits)
#define BTF_MEMBER_ENC(name, type, bits_offset) (name), (type), (bits_offset)
#define BTF_PARAM_ENC(name, type) (name), (type)
#define BTF_VAR_SECINFO_ENC(type, offset, size) (type), (offset), (size)
#define BTF_TYPE_FLOAT_ENC(name, sz) \
    BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_FLOAT, 0, 0), sz)
#define BTF_TYPE_DECL_TAG_ENC(value, type, component_idx) \
    BTF_TYPE_ENC(value, BTF_INFO_ENC(BTF_KIND_DECL_TAG, 0, 0), type), (component_idx)
#define BTF_TYPE_TYPE_TAG_ENC(value, type) \
    BTF_TYPE_ENC(value, BTF_INFO_ENC(BTF_KIND_TYPE_TAG, 0, 0), type)

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef max
#define max(x, y) ((x) < (y) ? (y) : (x))
#endif
#ifndef offsetofend
#define offsetofend(TYPE, FIELD) \
    (offsetof(TYPE, FIELD) + sizeof(((TYPE *)0)->FIELD))
#endif
#ifndef __alias
#define __alias(symbol) __attribute__((alias(#symbol)))
#endif

#define str_has_pfx(str, pfx) \
    (strncmp(str, pfx, __builtin_constant_p(pfx) ? sizeof(pfx) - 1 : strlen(pfx)) == 0)

/* suffix check */
static inline bool str_has_sfx(const char *str, const char *sfx)
{
    size_t str_len = strlen(str);
    size_t sfx_len = strlen(sfx);

    if (sfx_len > str_len)
        return false;
    return strcmp(str + str_len - sfx_len, sfx) == 0;
}

#if defined(SHARED) && defined(__GNUC__) && __GNUC__ >= 10

#define DEFAULT_VERSION(internal_name, api_name, version) \
    __attribute__((symver(#api_name "@@" #version)))
#define COMPAT_VERSION(internal_name, api_name, version) \
    __attribute__((symver(#api_name "@" #version)))

#elif defined(SHARED)

#define COMPAT_VERSION(internal_name, api_name, version) \
    asm(".symver " #internal_name "," #api_name "@" #version);
#define DEFAULT_VERSION(internal_name, api_name, version) \
    asm(".symver " #internal_name "," #api_name "@@" #version);

#else /* !SHARED */

#define COMPAT_VERSION(internal_name, api_name, version)
#define DEFAULT_VERSION(internal_name, api_name, version) \
    extern typeof(internal_name) api_name                 \
        __attribute__((alias(#internal_name)));

#endif

extern void libbpf_print(enum libbpf_print_level level,
                         const char *format, ...)
    __attribute__((format(printf, 2, 3)));

#define __pr(level, fmt, ...)                               \
    do                                                      \
    {                                                       \
        libbpf_print(level, "libbpf: " fmt, ##__VA_ARGS__); \
    } while (0)

#define pr_warn(fmt, ...) __pr(LIBBPF_WARN, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) __pr(LIBBPF_INFO, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) __pr(LIBBPF_DEBUG, fmt, ##__VA_ARGS__)

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

struct bpf_link
{
    int (*detach)(struct bpf_link *link);
    void (*dealloc)(struct bpf_link *link);
    char *pin_path; /* NULL, if not pinned */
    int fd;         /* hook FD, -1 if not applicable */
    bool disconnected;
};

static inline void *libbpf_reallocarray(void *ptr, size_t nmemb, size_t size)
{
    size_t total;

#if __has_builtin(__builtin_mul_overflow)
    if (unlikely(__builtin_mul_overflow(nmemb, size, &total)))
        return NULL;
#else
    if (size == 0 || nmemb > ULONG_MAX / size)
        return NULL;
    total = nmemb * size;
#endif
    return realloc(ptr, total);
}

static inline void libbpf_strlcpy(char *dst, const char *src, size_t sz)
{
    size_t i;

    if (sz == 0)
        return;

    sz--;
    for (i = 0; i < sz && src[i]; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

__u32 get_kernel_version(void);

struct btf;
struct btf_type;

struct btf_type *btf_type_by_id(const struct btf *btf, __u32 type_id);
const char *btf_kind_str(const struct btf_type *t);
const struct btf_type *skip_mods_and_typedefs(const struct btf *btf, __u32 id, __u32 *res_id);

static inline enum btf_func_linkage btf_func_linkage(const struct btf_type *t)
{
    return (enum btf_func_linkage)(int)btf_vlen(t);
}

static inline __u32 btf_type_info(int kind, int vlen, int kflag)
{
    return (kflag << 31) | (kind << 24) | vlen;
}

enum map_def_parts
{
    MAP_DEF_MAP_TYPE = 0x001,
    MAP_DEF_KEY_TYPE = 0x002,
    MAP_DEF_KEY_SIZE = 0x004,
    MAP_DEF_VALUE_TYPE = 0x008,
    MAP_DEF_VALUE_SIZE = 0x010,
    MAP_DEF_MAX_ENTRIES = 0x020,
    MAP_DEF_MAP_FLAGS = 0x040,
    MAP_DEF_NUMA_NODE = 0x080,
    MAP_DEF_PINNING = 0x100,
    MAP_DEF_INNER_MAP = 0x200,
    MAP_DEF_MAP_EXTRA = 0x400,

    MAP_DEF_ALL = 0x7ff, /* combination of all above */
};

struct btf_map_def
{
    enum map_def_parts parts;
    __u32 map_type;
    __u32 key_type_id;
    __u32 key_size;
    __u32 value_type_id;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    __u32 numa_node;
    __u32 pinning;
    __u64 map_extra;
};

int parse_btf_map_def(const char *map_name, struct btf *btf,
                      const struct btf_type *def_t, bool strict,
                      struct btf_map_def *map_def, struct btf_map_def *inner_def);

void *libbpf_add_mem(void **data, size_t *cap_cnt, size_t elem_sz,
                     size_t cur_cnt, size_t max_cnt, size_t add_cnt);
int libbpf_ensure_mem(void **data, size_t *cap_cnt, size_t elem_sz, size_t need_cnt);

static inline bool libbpf_is_mem_zeroed(const char *p, ssize_t len)
{
    while (len > 0)
    {
        if (*p)
            return false;
        p++;
        len--;
    }
    return true;
}

static inline bool libbpf_validate_opts(const char *opts,
                                        size_t opts_sz, size_t user_sz,
                                        const char *type_name)
{
    if (user_sz < sizeof(size_t))
    {
        pr_warn("%s size (%zu) is too small\n", type_name, user_sz);
        return false;
    }
    if (!libbpf_is_mem_zeroed(opts + opts_sz, (ssize_t)user_sz - opts_sz))
    {
        pr_warn("%s has non-zero extra bytes\n", type_name);
        return false;
    }
    return true;
}

#define OPTS_VALID(opts, type)                                        \
    (!(opts) || libbpf_validate_opts((const char *)opts,              \
                                     offsetofend(struct type,         \
                                                 type##__last_field), \
                                     (opts)->sz, #type))
#define OPTS_HAS(opts, field) \
    ((opts) && opts->sz >= offsetofend(typeof(*(opts)), field))
#define OPTS_GET(opts, field, fallback_value) \
    (OPTS_HAS(opts, field) ? (opts)->field : fallback_value)
#define OPTS_SET(opts, field, value) \
    do                               \
    {                                \
        if (OPTS_HAS(opts, field))   \
            (opts)->field = value;   \
    } while (0)

#define OPTS_ZEROED(opts, last_nonzero_field)                             \
    ({                                                                    \
        ssize_t __off = offsetofend(typeof(*(opts)), last_nonzero_field); \
        !(opts) || libbpf_is_mem_zeroed((const void *)opts + __off,       \
                                        (opts)->sz - __off);              \
    })
