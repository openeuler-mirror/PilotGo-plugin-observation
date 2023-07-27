/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __LIBBPF_HASHMAP_H
#define __LIBBPF_HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <limits.h>

static inline size_t hash_bits(size_t h, int bits)
{
    /* shuffle bits and return requested number of upper bits */
    if (bits == 0)
        return 0;

#if (__SIZEOF_SIZE_T__ == __SIZEOF_LONG_LONG__)
    /* LP64 case */
    return (h * 11400714819323198485llu) >> (__SIZEOF_LONG_LONG__ * 8 - bits);
#elif (__SIZEOF_SIZE_T__ <= __SIZEOF_LONG__)
    return (h * 2654435769lu) >> (__SIZEOF_LONG__ * 8 - bits);
#else
#error "Unsupported size_t size"
#endif
}

/* generic C-string hashing function */
static inline size_t str_hash(const char *s)
{
    size_t h = 0;

    while (*s)
    {
        h = h * 31 + *s;
        s++;
    }
    return h;
}

typedef size_t (*hashmap_hash_fn)(long key, void *ctx);
typedef bool (*hashmap_equal_fn)(long key1, long key2, void *ctx);

struct hashmap_entry
{
    union
    {
        long key;
        const void *pkey;
    };
    union
    {
        long value;
        void *pvalue;
    };
    struct hashmap_entry *next;
};

struct hashmap
{
    hashmap_hash_fn hash_fn;
    hashmap_equal_fn equal_fn;
    void *ctx;

    struct hashmap_entry **buckets;
    size_t cap;
    size_t cap_bits;
    size_t sz;
};

#define HASHMAP_INIT(hash_fn, equal_fn, ctx) \
    {                                        \
        .hash_fn = (hash_fn),                \
        .equal_fn = (equal_fn),              \
        .ctx = (ctx),                        \
        .buckets = NULL,                     \
        .cap = 0,                            \
        .cap_bits = 0,                       \
        .sz = 0,                             \
    }

void hashmap__init(struct hashmap *map, hashmap_hash_fn hash_fn,
                   hashmap_equal_fn equal_fn, void *ctx);
struct hashmap *hashmap__new(hashmap_hash_fn hash_fn,
                             hashmap_equal_fn equal_fn,
                             void *ctx);
void hashmap__clear(struct hashmap *map);
void hashmap__free(struct hashmap *map);

size_t hashmap__size(const struct hashmap *map);
size_t hashmap__capacity(const struct hashmap *map);

enum hashmap_insert_strategy
{
    HASHMAP_ADD,
    HASHMAP_SET,
    HASHMAP_UPDATE,
    HASHMAP_APPEND,
};
