// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * BTF-to-C type converter.
 *
 * Copyright (c) 2019 Facebook
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <linux/err.h>
#include <linux/btf.h>
#include <linux/kernel.h>
#include "btf.h"
#include "hashmap.h"
#include "libbpf.h"
#include "libbpf_internal.h"

static const char PREFIXES[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t";
static const size_t PREFIX_CNT = sizeof(PREFIXES) - 1;

static const char *pfx(int lvl)
{
	return lvl >= PREFIX_CNT ? PREFIXES : &PREFIXES[PREFIX_CNT - lvl];
}

enum btf_dump_type_order_state {
	NOT_ORDERED,
	ORDERING,
	ORDERED,
};

enum btf_dump_type_emit_state {
	NOT_EMITTED,
	EMITTING,
	EMITTED,
};

/* per-type auxiliary state */
struct btf_dump_type_aux_state {
	/* topological sorting state */
	enum btf_dump_type_order_state order_state: 2;
	/* emitting state used to determine the need for forward declaration */
	enum btf_dump_type_emit_state emit_state: 2;
	/* whether forward declaration was already emitted */
	__u8 fwd_emitted: 1;
	/* whether unique non-duplicate name was already assigned */
	__u8 name_resolved: 1;
	/* whether type is referenced from any other type */
	__u8 referenced: 1;
};

/* indent string length; one indent string is added for each indent level */
#define BTF_DATA_INDENT_STR_LEN			32

/*
 * Common internal data for BTF type data dump operations.
 */
struct btf_dump_data {
	const void *data_end;		/* end of valid data to show */
	bool compact;
	bool skip_names;
	bool emit_zeroes;
	__u8 indent_lvl;	/* base indent level */
	char indent_str[BTF_DATA_INDENT_STR_LEN];
	/* below are used during iteration */
	int depth;
	bool is_array_member;
	bool is_array_terminated;
	bool is_array_char;
};

struct btf_dump {
	const struct btf *btf;
	btf_dump_printf_fn_t printf_fn;
	void *cb_ctx;
	int ptr_sz;
	bool strip_mods;
	bool skip_anon_defs;
	int last_id;

	/* per-type auxiliary state */
	struct btf_dump_type_aux_state *type_states;
	size_t type_states_cap;
	/* per-type optional cached unique name, must be freed, if present */
	const char **cached_names;
	size_t cached_names_cap;

	/* topo-sorted list of dependent type definitions */
	__u32 *emit_queue;
	int emit_queue_cap;
	int emit_queue_cnt;

	/*
	 * stack of type declarations (e.g., chain of modifiers, arrays,
	 * funcs, etc)
	 */
	__u32 *decl_stack;
	int decl_stack_cap;
	int decl_stack_cnt;

	/* maps struct/union/enum name to a number of name occurrences */
	struct hashmap *type_names;
	/*
	 * maps typedef identifiers and enum value names to a number of such
	 * name occurrences
	 */
	struct hashmap *ident_names;
	/*
	 * data for typed display; allocated if needed.
	 */
	struct btf_dump_data *typed_dump;
};

static size_t str_hash_fn(long key, void *ctx)
{
	return str_hash((void *)key);
}

static bool str_equal_fn(long a, long b, void *ctx)
{
	return strcmp((void *)a, (void *)b) == 0;
}

static const char *btf_name_of(const struct btf_dump *d, __u32 name_off)
{
	return btf__name_by_offset(d->btf, name_off);
}

static void btf_dump_printf(const struct btf_dump *d, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	d->printf_fn(d->cb_ctx, fmt, args);
	va_end(args);
}

static int btf_dump_mark_referenced(struct btf_dump *d);
static int btf_dump_resize(struct btf_dump *d);

struct btf_dump *btf_dump__new(const struct btf *btf,
			       btf_dump_printf_fn_t printf_fn,
			       void *ctx,
			       const struct btf_dump_opts *opts)
{
	struct btf_dump *d;
	int err;

	if (!OPTS_VALID(opts, btf_dump_opts))
		return libbpf_err_ptr(-EINVAL);

	if (!printf_fn)
		return libbpf_err_ptr(-EINVAL);

	d = calloc(1, sizeof(struct btf_dump));
	if (!d)
		return libbpf_err_ptr(-ENOMEM);

	d->btf = btf;
	d->printf_fn = printf_fn;
	d->cb_ctx = ctx;
	d->ptr_sz = btf__pointer_size(btf) ? : sizeof(void *);

	d->type_names = hashmap__new(str_hash_fn, str_equal_fn, NULL);
	if (IS_ERR(d->type_names)) {
		err = PTR_ERR(d->type_names);
		d->type_names = NULL;
		goto err;
	}
	d->ident_names = hashmap__new(str_hash_fn, str_equal_fn, NULL);
	if (IS_ERR(d->ident_names)) {
		err = PTR_ERR(d->ident_names);
		d->ident_names = NULL;
		goto err;
	}

	err = btf_dump_resize(d);
	if (err)
		goto err;

	return d;
err:
	btf_dump__free(d);
	return libbpf_err_ptr(err);
}

static int btf_dump_resize(struct btf_dump *d)
{
	int err, last_id = btf__type_cnt(d->btf) - 1;

	if (last_id <= d->last_id)
		return 0;

	if (libbpf_ensure_mem((void **)&d->type_states, &d->type_states_cap,
			      sizeof(*d->type_states), last_id + 1))
		return -ENOMEM;
	if (libbpf_ensure_mem((void **)&d->cached_names, &d->cached_names_cap,
			      sizeof(*d->cached_names), last_id + 1))
		return -ENOMEM;

	if (d->last_id == 0) {
		/* VOID is special */
		d->type_states[0].order_state = ORDERED;
		d->type_states[0].emit_state = EMITTED;
	}

	/* eagerly determine referenced types for anon enums */
	err = btf_dump_mark_referenced(d);
	if (err)
		return err;

	d->last_id = last_id;
	return 0;
}

static void btf_dump_free_names(struct hashmap *map)
{
	size_t bkt;
	struct hashmap_entry *cur;

	hashmap__for_each_entry(map, cur, bkt)
		free((void *)cur->pkey);

	hashmap__free(map);
}

void btf_dump__free(struct btf_dump *d)
{
	int i;

	if (IS_ERR_OR_NULL(d))
		return;

	free(d->type_states);
	if (d->cached_names) {
		/* any set cached name is owned by us and should be freed */
		for (i = 0; i <= d->last_id; i++) {
			if (d->cached_names[i])
				free((void *)d->cached_names[i]);
		}
	}
	free(d->cached_names);
	free(d->emit_queue);
	free(d->decl_stack);
	btf_dump_free_names(d->type_names);
	btf_dump_free_names(d->ident_names);

	free(d);
}

static int btf_dump_order_type(struct btf_dump *d, __u32 id, bool through_ptr);
static void btf_dump_emit_type(struct btf_dump *d, __u32 id, __u32 cont_id);

int btf_dump__dump_type(struct btf_dump *d, __u32 id)
{
	int err, i;

	if (id >= btf__type_cnt(d->btf))
		return libbpf_err(-EINVAL);

	err = btf_dump_resize(d);
	if (err)
		return libbpf_err(err);

	d->emit_queue_cnt = 0;
	err = btf_dump_order_type(d, id, false);
	if (err < 0)
		return libbpf_err(err);

	for (i = 0; i < d->emit_queue_cnt; i++)
		btf_dump_emit_type(d, d->emit_queue[i], 0 /*top-level*/);

	return 0;
}

static int btf_dump_mark_referenced(struct btf_dump *d)
{
	int i, j, n = btf__type_cnt(d->btf);
	const struct btf_type *t;
	__u16 vlen;

	for (i = d->last_id + 1; i < n; i++) {
		t = btf__type_by_id(d->btf, i);
		vlen = btf_vlen(t);

		switch (btf_kind(t)) {
		case BTF_KIND_INT:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
		case BTF_KIND_FWD:
		case BTF_KIND_FLOAT:
			break;

		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_PTR:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_FUNC:
		case BTF_KIND_VAR:
		case BTF_KIND_DECL_TAG:
		case BTF_KIND_TYPE_TAG:
			d->type_states[t->type].referenced = 1;
			break;

		case BTF_KIND_ARRAY: {
			const struct btf_array *a = btf_array(t);

			d->type_states[a->index_type].referenced = 1;
			d->type_states[a->type].referenced = 1;
			break;
		}
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION: {
			const struct btf_member *m = btf_members(t);

			for (j = 0; j < vlen; j++, m++)
				d->type_states[m->type].referenced = 1;
			break;
		}
		case BTF_KIND_FUNC_PROTO: {
			const struct btf_param *p = btf_params(t);

			for (j = 0; j < vlen; j++, p++)
				d->type_states[p->type].referenced = 1;
			break;
		}
		case BTF_KIND_DATASEC: {
			const struct btf_var_secinfo *v = btf_var_secinfos(t);

			for (j = 0; j < vlen; j++, v++)
				d->type_states[v->type].referenced = 1;
			break;
		}
		default:
			return -EINVAL;
		}
	}
	return 0;
}
