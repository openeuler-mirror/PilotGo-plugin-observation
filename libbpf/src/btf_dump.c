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

static int btf_dump_add_emit_queue_id(struct btf_dump *d, __u32 id)
{
	__u32 *new_queue;
	size_t new_cap;

	if (d->emit_queue_cnt >= d->emit_queue_cap) {
		new_cap = max(16, d->emit_queue_cap * 3 / 2);
		new_queue = libbpf_reallocarray(d->emit_queue, new_cap, sizeof(new_queue[0]));
		if (!new_queue)
			return -ENOMEM;
		d->emit_queue = new_queue;
		d->emit_queue_cap = new_cap;
	}

	d->emit_queue[d->emit_queue_cnt++] = id;
	return 0;
}


static int btf_dump_order_type(struct btf_dump *d, __u32 id, bool through_ptr)
{
	struct btf_dump_type_aux_state *tstate = &d->type_states[id];
	const struct btf_type *t;
	__u16 vlen;
	int err, i;

	/* return true, letting typedefs know that it's ok to be emitted */
	if (tstate->order_state == ORDERED)
		return 1;

	t = btf__type_by_id(d->btf, id);

	if (tstate->order_state == ORDERING) {
		/* type loop, but resolvable through fwd declaration */
		if (btf_is_composite(t) && through_ptr && t->name_off != 0)
			return 0;
		pr_warn("unsatisfiable type cycle, id:[%u]\n", id);
		return -ELOOP;
	}

	switch (btf_kind(t)) {
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
		tstate->order_state = ORDERED;
		return 0;

	case BTF_KIND_PTR:
		err = btf_dump_order_type(d, t->type, true);
		tstate->order_state = ORDERED;
		return err;

	case BTF_KIND_ARRAY:
		return btf_dump_order_type(d, btf_array(t)->type, false);

	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		const struct btf_member *m = btf_members(t);
		/*
		 * struct/union is part of strong link, only if it's embedded
		 * (so no ptr in a path) or it's anonymous (so has to be
		 * defined inline, even if declared through ptr)
		 */
		if (through_ptr && t->name_off != 0)
			return 0;

		tstate->order_state = ORDERING;

		vlen = btf_vlen(t);
		for (i = 0; i < vlen; i++, m++) {
			err = btf_dump_order_type(d, m->type, false);
			if (err < 0)
				return err;
		}

		if (t->name_off != 0) {
			err = btf_dump_add_emit_queue_id(d, id);
			if (err < 0)
				return err;
		}

		tstate->order_state = ORDERED;
		return 1;
	}
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
	case BTF_KIND_FWD:
		/*
		 * non-anonymous or non-referenced enums are top-level
		 * declarations and should be emitted. Same logic can be
		 * applied to FWDs, it won't hurt anyways.
		 */
		if (t->name_off != 0 || !tstate->referenced) {
			err = btf_dump_add_emit_queue_id(d, id);
			if (err)
				return err;
		}
		tstate->order_state = ORDERED;
		return 1;

	case BTF_KIND_TYPEDEF: {
		int is_strong;

		is_strong = btf_dump_order_type(d, t->type, through_ptr);
		if (is_strong < 0)
			return is_strong;

		/* typedef is similar to struct/union w.r.t. fwd-decls */
		if (through_ptr && !is_strong)
			return 0;

		/* typedef is always a named definition */
		err = btf_dump_add_emit_queue_id(d, id);
		if (err)
			return err;

		d->type_states[id].order_state = ORDERED;
		return 1;
	}
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPE_TAG:
		return btf_dump_order_type(d, t->type, through_ptr);

	case BTF_KIND_FUNC_PROTO: {
		const struct btf_param *p = btf_params(t);
		bool is_strong;

		err = btf_dump_order_type(d, t->type, through_ptr);
		if (err < 0)
			return err;
		is_strong = err > 0;

		vlen = btf_vlen(t);
		for (i = 0; i < vlen; i++, p++) {
			err = btf_dump_order_type(d, p->type, through_ptr);
			if (err < 0)
				return err;
			if (err > 0)
				is_strong = true;
		}
		return is_strong;
	}
	case BTF_KIND_FUNC:
	case BTF_KIND_VAR:
	case BTF_KIND_DATASEC:
	case BTF_KIND_DECL_TAG:
		d->type_states[id].order_state = ORDERED;
		return 0;

	default:
		return -EINVAL;
	}
}

static void btf_dump_emit_missing_aliases(struct btf_dump *d, __u32 id,
					  const struct btf_type *t);

static void btf_dump_emit_struct_fwd(struct btf_dump *d, __u32 id,
				     const struct btf_type *t);
static void btf_dump_emit_struct_def(struct btf_dump *d, __u32 id,
				     const struct btf_type *t, int lvl);

static void btf_dump_emit_enum_fwd(struct btf_dump *d, __u32 id,
				   const struct btf_type *t);
static void btf_dump_emit_enum_def(struct btf_dump *d, __u32 id,
				   const struct btf_type *t, int lvl);

static void btf_dump_emit_fwd_def(struct btf_dump *d, __u32 id,
				  const struct btf_type *t);

static void btf_dump_emit_typedef_def(struct btf_dump *d, __u32 id,
				      const struct btf_type *t, int lvl);

/* a local view into a shared stack */
struct id_stack {
	const __u32 *ids;
	int cnt;
};

static void btf_dump_emit_type_decl(struct btf_dump *d, __u32 id,
				    const char *fname, int lvl);
static void btf_dump_emit_type_chain(struct btf_dump *d,
				     struct id_stack *decl_stack,
				     const char *fname, int lvl);

static const char *btf_dump_type_name(struct btf_dump *d, __u32 id);
static const char *btf_dump_ident_name(struct btf_dump *d, __u32 id);
static size_t btf_dump_name_dups(struct btf_dump *d, struct hashmap *name_map,
				 const char *orig_name);

static bool btf_dump_is_blacklisted(struct btf_dump *d, __u32 id)
{
	const struct btf_type *t = btf__type_by_id(d->btf, id);

	/* __builtin_va_list is a compiler built-in, which causes compilation
	 * errors, when compiling w/ different compiler, then used to compile
	 * original code (e.g., GCC to compile kernel, Clang to use generated
	 * C header from BTF). As it is built-in, it should be already defined
	 * properly internally in compiler.
	 */
	if (t->name_off == 0)
		return false;
	return strcmp(btf_name_of(d, t->name_off), "__builtin_va_list") == 0;
}

static void btf_dump_emit_type(struct btf_dump *d, __u32 id, __u32 cont_id)
{
	struct btf_dump_type_aux_state *tstate = &d->type_states[id];
	bool top_level_def = cont_id == 0;
	const struct btf_type *t;
	__u16 kind;

	if (tstate->emit_state == EMITTED)
		return;

	t = btf__type_by_id(d->btf, id);
	kind = btf_kind(t);

	if (tstate->emit_state == EMITTING) {
		if (tstate->fwd_emitted)
			return;

		switch (kind) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			/*
			 * if we are referencing a struct/union that we are
			 * part of - then no need for fwd declaration
			 */
			if (id == cont_id)
				return;
			if (t->name_off == 0) {
				pr_warn("anonymous struct/union loop, id:[%u]\n",
					id);
				return;
			}
			btf_dump_emit_struct_fwd(d, id, t);
			btf_dump_printf(d, ";\n\n");
			tstate->fwd_emitted = 1;
			break;
		case BTF_KIND_TYPEDEF:
			/*
			 * for typedef fwd_emitted means typedef definition
			 * was emitted, but it can be used only for "weak"
			 * references through pointer only, not for embedding
			 */
			if (!btf_dump_is_blacklisted(d, id)) {
				btf_dump_emit_typedef_def(d, id, t, 0);
				btf_dump_printf(d, ";\n\n");
			}
			tstate->fwd_emitted = 1;
			break;
		default:
			break;
		}

		return;
	}

	switch (kind) {
	case BTF_KIND_INT:
		/* Emit type alias definitions if necessary */
		btf_dump_emit_missing_aliases(d, id, t);

		tstate->emit_state = EMITTED;
		break;
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		if (top_level_def) {
			btf_dump_emit_enum_def(d, id, t, 0);
			btf_dump_printf(d, ";\n\n");
		}
		tstate->emit_state = EMITTED;
		break;
	case BTF_KIND_PTR:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPE_TAG:
		btf_dump_emit_type(d, t->type, cont_id);
		break;
	case BTF_KIND_ARRAY:
		btf_dump_emit_type(d, btf_array(t)->type, cont_id);
		break;
	case BTF_KIND_FWD:
		btf_dump_emit_fwd_def(d, id, t);
		btf_dump_printf(d, ";\n\n");
		tstate->emit_state = EMITTED;
		break;
	case BTF_KIND_TYPEDEF:
		tstate->emit_state = EMITTING;
		btf_dump_emit_type(d, t->type, id);
		/*
		 * typedef can server as both definition and forward
		 * declaration; at this stage someone depends on
		 * typedef as a forward declaration (refers to it
		 * through pointer), so unless we already did it,
		 * emit typedef as a forward declaration
		 */
		if (!tstate->fwd_emitted && !btf_dump_is_blacklisted(d, id)) {
			btf_dump_emit_typedef_def(d, id, t, 0);
			btf_dump_printf(d, ";\n\n");
		}
		tstate->emit_state = EMITTED;
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		tstate->emit_state = EMITTING;
		/* if it's a top-level struct/union definition or struct/union
		 * is anonymous, then in C we'll be emitting all fields and
		 * their types (as opposed to just `struct X`), so we need to
		 * make sure that all types, referenced from struct/union
		 * members have necessary forward-declarations, where
		 * applicable
		 */
		if (top_level_def || t->name_off == 0) {
			const struct btf_member *m = btf_members(t);
			__u16 vlen = btf_vlen(t);
			int i, new_cont_id;

			new_cont_id = t->name_off == 0 ? cont_id : id;
			for (i = 0; i < vlen; i++, m++)
				btf_dump_emit_type(d, m->type, new_cont_id);
		} else if (!tstate->fwd_emitted && id != cont_id) {
			btf_dump_emit_struct_fwd(d, id, t);
			btf_dump_printf(d, ";\n\n");
			tstate->fwd_emitted = 1;
		}

		if (top_level_def) {
			btf_dump_emit_struct_def(d, id, t, 0);
			btf_dump_printf(d, ";\n\n");
			tstate->emit_state = EMITTED;
		} else {
			tstate->emit_state = NOT_EMITTED;
		}
		break;
	case BTF_KIND_FUNC_PROTO: {
		const struct btf_param *p = btf_params(t);
		__u16 n = btf_vlen(t);
		int i;

		btf_dump_emit_type(d, t->type, cont_id);
		for (i = 0; i < n; i++, p++)
			btf_dump_emit_type(d, p->type, cont_id);

		break;
	}
	default:
		break;
	}
}

static bool btf_is_struct_packed(const struct btf *btf, __u32 id,
				 const struct btf_type *t)
{
	const struct btf_member *m;
	int max_align = 1, align, i, bit_sz;
	__u16 vlen;

	m = btf_members(t);
	vlen = btf_vlen(t);
	/* all non-bitfield fields have to be naturally aligned */
	for (i = 0; i < vlen; i++, m++) {
		align = btf__align_of(btf, m->type);
		bit_sz = btf_member_bitfield_size(t, i);
		if (align && bit_sz == 0 && m->offset % (8 * align) != 0)
			return true;
		max_align = max(align, max_align);
	}
	/* size of a non-packed struct has to be a multiple of its alignment */
	if (t->size % max_align != 0)
		return true;
	/*
	 * if original struct was marked as packed, but its layout is
	 * naturally aligned, we'll detect that it's not packed
	 */
	return false;
}

static void btf_dump_emit_bit_padding(const struct btf_dump *d,
				      int cur_off, int next_off, int next_align,
				      bool in_bitfield, int lvl)
{
	const struct {
		const char *name;
		int bits;
	} pads[] = {
		{"long", d->ptr_sz * 8}, {"int", 32}, {"short", 16}, {"char", 8}
	};
	int new_off, pad_bits, bits, i;
	const char *pad_type;

	if (cur_off >= next_off)
		return; /* no gap */
	for (i = 0; i < ARRAY_SIZE(pads); i++) {
		pad_bits = pads[i].bits;
		pad_type = pads[i].name;

		new_off = roundup(cur_off, pad_bits);
		if (new_off <= next_off)
			break;
	}

	if (new_off > cur_off && new_off <= next_off) {
		if (in_bitfield ||
		    (new_off == next_off && roundup(cur_off, next_align * 8) != new_off) ||
		    (new_off != next_off && next_off - new_off <= new_off - cur_off))
			/* but for bitfields we'll emit explicit bit count */
			btf_dump_printf(d, "\n%s%s: %d;", pfx(lvl), pad_type,
					in_bitfield ? new_off - cur_off : 0);
		cur_off = new_off;
	}

	/* Now we know we start at naturally aligned offset for a chosen
	 * padding type (long, int, short, or char), and so the rest is just
	 * a straightforward filling of remaining padding gap with full
	 * `<type>: sizeof(<type>);` markers, except for the last one, which
	 * might need smaller than sizeof(<type>) padding.
	 */
	while (cur_off != next_off) {
		bits = min(next_off - cur_off, pad_bits);
		if (bits == pad_bits) {
			btf_dump_printf(d, "\n%s%s: %d;", pfx(lvl), pad_type, pad_bits);
			cur_off += bits;
			continue;
		}
		/* For the remainder padding that doesn't cover entire
		 * pad_type bit length, we pick the smallest necessary type.
		 * This is pure aesthetics, we could have just used `long`,
		 * but having smallest necessary one communicates better the
		 * scale of the padding gap.
		 */
		for (i = ARRAY_SIZE(pads) - 1; i >= 0; i--) {
			pad_type = pads[i].name;
			pad_bits = pads[i].bits;
			if (pad_bits < bits)
				continue;

			btf_dump_printf(d, "\n%s%s: %d;", pfx(lvl), pad_type, bits);
			cur_off += bits;
			break;
		}
	}
}

static const char *missing_base_types[][2] = {
	/*
	 * GCC emits typedefs to its internal __PolyX_t types when compiling Arm
	 * SIMD intrinsics. Alias them to standard base types.
	 */
	{ "__Poly8_t",		"unsigned char" },
	{ "__Poly16_t",		"unsigned short" },
	{ "__Poly64_t",		"unsigned long long" },
	{ "__Poly128_t",	"unsigned __int128" },
};

static void btf_dump_emit_missing_aliases(struct btf_dump *d, __u32 id,
					  const struct btf_type *t)
{
	const char *name = btf_dump_type_name(d, id);
	int i;

	for (i = 0; i < ARRAY_SIZE(missing_base_types); i++) {
		if (strcmp(name, missing_base_types[i][0]) == 0) {
			btf_dump_printf(d, "typedef %s %s;\n\n",
					missing_base_types[i][1], name);
			break;
		}
	}
}

static void btf_dump_emit_enum_fwd(struct btf_dump *d, __u32 id,
				   const struct btf_type *t)
{
	btf_dump_printf(d, "enum %s", btf_dump_type_name(d, id));
}

static void btf_dump_emit_enum32_val(struct btf_dump *d,
				     const struct btf_type *t,
				     int lvl, __u16 vlen)
{
	const struct btf_enum *v = btf_enum(t);
	bool is_signed = btf_kflag(t);
	const char *fmt_str;
	const char *name;
	size_t dup_cnt;
	int i;

	for (i = 0; i < vlen; i++, v++) {
		name = btf_name_of(d, v->name_off);
		/* enumerators share namespace with typedef idents */
		dup_cnt = btf_dump_name_dups(d, d->ident_names, name);
		if (dup_cnt > 1) {
			fmt_str = is_signed ? "\n%s%s___%zd = %d," : "\n%s%s___%zd = %u,";
			btf_dump_printf(d, fmt_str, pfx(lvl + 1), name, dup_cnt, v->val);
		} else {
			fmt_str = is_signed ? "\n%s%s = %d," : "\n%s%s = %u,";
			btf_dump_printf(d, fmt_str, pfx(lvl + 1), name, v->val);
		}
	}
}

static void btf_dump_emit_enum64_val(struct btf_dump *d,
				     const struct btf_type *t,
				     int lvl, __u16 vlen)
{
	const struct btf_enum64 *v = btf_enum64(t);
	bool is_signed = btf_kflag(t);
	const char *fmt_str;
	const char *name;
	size_t dup_cnt;
	__u64 val;
	int i;

	for (i = 0; i < vlen; i++, v++) {
		name = btf_name_of(d, v->name_off);
		dup_cnt = btf_dump_name_dups(d, d->ident_names, name);
		val = btf_enum64_value(v);
		if (dup_cnt > 1) {
			fmt_str = is_signed ? "\n%s%s___%zd = %lldLL,"
					    : "\n%s%s___%zd = %lluULL,";
			btf_dump_printf(d, fmt_str,
					pfx(lvl + 1), name, dup_cnt,
					(unsigned long long)val);
		} else {
			fmt_str = is_signed ? "\n%s%s = %lldLL,"
					    : "\n%s%s = %lluULL,";
			btf_dump_printf(d, fmt_str,
					pfx(lvl + 1), name,
					(unsigned long long)val);
		}
	}
}

static void btf_dump_emit_enum_def(struct btf_dump *d, __u32 id,
				   const struct btf_type *t,
				   int lvl)
{
	__u16 vlen = btf_vlen(t);

	btf_dump_printf(d, "enum%s%s",
			t->name_off ? " " : "",
			btf_dump_type_name(d, id));

	if (!vlen)
		return;

	btf_dump_printf(d, " {");
	if (btf_is_enum(t))
		btf_dump_emit_enum32_val(d, t, lvl, vlen);
	else
		btf_dump_emit_enum64_val(d, t, lvl, vlen);
	btf_dump_printf(d, "\n%s}", pfx(lvl));

	/* special case enums with special sizes */
	if (t->size == 1) {
		/* one-byte enums can be forced with mode(byte) attribute */
		btf_dump_printf(d, " __attribute__((mode(byte)))");
	} else if (t->size == 8 && d->ptr_sz == 8) {

		bool needs_word_mode;

		if (btf_is_enum(t)) {
			/* enum can't represent 64-bit values, so we need word mode */
			needs_word_mode = true;
		} else {

			int i;

			needs_word_mode = true;
			for (i = 0; i < vlen; i++) {
				if (btf_enum64(t)[i].val_hi32 != 0) {
					needs_word_mode = false;
					break;
				}
			}
		}
		if (needs_word_mode)
			btf_dump_printf(d, " __attribute__((mode(word)))");
	}

}

static void btf_dump_emit_fwd_def(struct btf_dump *d, __u32 id,
				  const struct btf_type *t)
{
	const char *name = btf_dump_type_name(d, id);

	if (btf_kflag(t))
		btf_dump_printf(d, "union %s", name);
	else
		btf_dump_printf(d, "struct %s", name);
}

static void btf_dump_emit_typedef_def(struct btf_dump *d, __u32 id,
				     const struct btf_type *t, int lvl)
{
	const char *name = btf_dump_ident_name(d, id);

	/*
	 * Old GCC versions are emitting invalid typedef for __gnuc_va_list
	 * pointing to VOID. This generates warnings from btf_dump() and
	 * results in uncompilable header file, so we are fixing it up here
	 * with valid typedef into __builtin_va_list.
	 */
	if (t->type == 0 && strcmp(name, "__gnuc_va_list") == 0) {
		btf_dump_printf(d, "typedef __builtin_va_list __gnuc_va_list");
		return;
	}

	btf_dump_printf(d, "typedef ");
	btf_dump_emit_type_decl(d, t->type, name, lvl);
}

static int btf_dump_push_decl_stack_id(struct btf_dump *d, __u32 id)
{
	__u32 *new_stack;
	size_t new_cap;

	if (d->decl_stack_cnt >= d->decl_stack_cap) {
		new_cap = max(16, d->decl_stack_cap * 3 / 2);
		new_stack = libbpf_reallocarray(d->decl_stack, new_cap, sizeof(new_stack[0]));
		if (!new_stack)
			return -ENOMEM;
		d->decl_stack = new_stack;
		d->decl_stack_cap = new_cap;
	}

	d->decl_stack[d->decl_stack_cnt++] = id;

	return 0;
}

int btf_dump__emit_type_decl(struct btf_dump *d, __u32 id,
			     const struct btf_dump_emit_type_decl_opts *opts)
{
	const char *fname;
	int lvl, err;

	if (!OPTS_VALID(opts, btf_dump_emit_type_decl_opts))
		return libbpf_err(-EINVAL);

	err = btf_dump_resize(d);
	if (err)
		return libbpf_err(err);

	fname = OPTS_GET(opts, field_name, "");
	lvl = OPTS_GET(opts, indent_level, 0);
	d->strip_mods = OPTS_GET(opts, strip_mods, false);
	btf_dump_emit_type_decl(d, id, fname, lvl);
	d->strip_mods = false;
	return 0;
}

static void btf_dump_emit_type_decl(struct btf_dump *d, __u32 id,
				    const char *fname, int lvl)
{
	struct id_stack decl_stack;
	const struct btf_type *t;
	int err, stack_start;

	stack_start = d->decl_stack_cnt;
	for (;;) {
		t = btf__type_by_id(d->btf, id);
		if (d->strip_mods && btf_is_mod(t))
			goto skip_mod;

		err = btf_dump_push_decl_stack_id(d, id);
		if (err < 0) {
			/*
			 * if we don't have enough memory for entire type decl
			 * chain, restore stack, emit warning, and try to
			 * proceed nevertheless
			 */
			pr_warn("not enough memory for decl stack:%d", err);
			d->decl_stack_cnt = stack_start;
			return;
		}
skip_mod:
		/* VOID */
		if (id == 0)
			break;

		switch (btf_kind(t)) {
		case BTF_KIND_PTR:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_FUNC_PROTO:
		case BTF_KIND_TYPE_TAG:
			id = t->type;
			break;
		case BTF_KIND_ARRAY:
			id = btf_array(t)->type;
			break;
		case BTF_KIND_INT:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
		case BTF_KIND_FWD:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_FLOAT:
			goto done;
		default:
			pr_warn("unexpected type in decl chain, kind:%u, id:[%u]\n",
				btf_kind(t), id);
			goto done;
		}
	}
done:
	decl_stack.ids = d->decl_stack + stack_start;
	decl_stack.cnt = d->decl_stack_cnt - stack_start;
	btf_dump_emit_type_chain(d, &decl_stack, fname, lvl);
	d->decl_stack_cnt = stack_start;
}

static void btf_dump_emit_mods(struct btf_dump *d, struct id_stack *decl_stack)
{
	const struct btf_type *t;
	__u32 id;

	while (decl_stack->cnt) {
		id = decl_stack->ids[decl_stack->cnt - 1];
		t = btf__type_by_id(d->btf, id);

		switch (btf_kind(t)) {
		case BTF_KIND_VOLATILE:
			btf_dump_printf(d, "volatile ");
			break;
		case BTF_KIND_CONST:
			btf_dump_printf(d, "const ");
			break;
		case BTF_KIND_RESTRICT:
			btf_dump_printf(d, "restrict ");
			break;
		default:
			return;
		}
		decl_stack->cnt--;
	}
}

static void btf_dump_drop_mods(struct btf_dump *d, struct id_stack *decl_stack)
{
	const struct btf_type *t;
	__u32 id;

	while (decl_stack->cnt) {
		id = decl_stack->ids[decl_stack->cnt - 1];
		t = btf__type_by_id(d->btf, id);
		if (!btf_is_mod(t))
			return;
		decl_stack->cnt--;
	}
}
