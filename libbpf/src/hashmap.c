#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <linux/err.h>
#include "hashmap.h"

/* make sure libbpf doesn't use kernel-only integer typedefs */
#pragma GCC poison u8 u16 u32 u64 s8 s16 s32 s64

/* prevent accidental re-addition of reallocarray() */
#pragma GCC poison reallocarray

/* start with 4 buckets */
#define HASHMAP_MIN_CAP_BITS 2

static void hashmap_add_entry(struct hashmap_entry **pprev,
                              struct hashmap_entry *entry)
{
    entry->next = *pprev;
    *pprev = entry;
}

static void hashmap_del_entry(struct hashmap_entry **pprev,
                              struct hashmap_entry *entry)
{
    *pprev = entry->next;
    entry->next = NULL;
}

void hashmap__init(struct hashmap *map, hashmap_hash_fn hash_fn,
                   hashmap_equal_fn equal_fn, void *ctx)
{
    map->hash_fn = hash_fn;
    map->equal_fn = equal_fn;
    map->ctx = ctx;

    map->buckets = NULL;
    map->cap = 0;
    map->cap_bits = 0;
    map->sz = 0;
}

struct hashmap *hashmap__new(hashmap_hash_fn hash_fn,
                             hashmap_equal_fn equal_fn,
                             void *ctx)
{
    struct hashmap *map = malloc(sizeof(struct hashmap));

    if (!map)
        return ERR_PTR(-ENOMEM);
    hashmap__init(map, hash_fn, equal_fn, ctx);
    return map;
}

void hashmap__clear(struct hashmap *map)
{
    struct hashmap_entry *cur, *tmp;
    size_t bkt;

    hashmap__for_each_entry_safe(map, cur, tmp, bkt)
    {
        free(cur);
    }
    free(map->buckets);
    map->buckets = NULL;
    map->cap = map->cap_bits = map->sz = 0;
}

void hashmap__free(struct hashmap *map)
{
    if (IS_ERR_OR_NULL(map))
        return;

    hashmap__clear(map);
    free(map);
}

size_t hashmap__size(const struct hashmap *map)
{
    return map->sz;
}

size_t hashmap__capacity(const struct hashmap *map)
{
    return map->cap;
}

static bool hashmap_needs_to_grow(struct hashmap *map)
{
    /* grow if empty or more than 75% filled */
    return (map->cap == 0) || ((map->sz + 1) * 4 / 3 > map->cap);
}
