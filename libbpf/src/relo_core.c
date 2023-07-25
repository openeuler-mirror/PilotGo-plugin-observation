// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2019 Facebook */

#ifdef __KERNEL__
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/string.h>
#include <linux/bpf_verifier.h>
#include "relo_core.h"

static const char *btf_kind_str(const struct btf_type *t)
{
	return btf_type_str(t);
}

static bool is_ldimm64_insn(struct bpf_insn *insn)
{
	return insn->code == (BPF_LD | BPF_IMM | BPF_DW);
}

static const struct btf_type *
skip_mods_and_typedefs(const struct btf *btf, u32 id, u32 *res_id)
{
	return btf_type_skip_modifiers(btf, id, res_id);
}

static const char *btf__name_by_offset(const struct btf *btf, u32 offset)
{
	return btf_name_by_offset(btf, offset);
}

static s64 btf__resolve_size(const struct btf *btf, u32 type_id)
{
	const struct btf_type *t;
	int size;

	t = btf_type_by_id(btf, type_id);
	t = btf_resolve_size(btf, t, &size);
	if (IS_ERR(t))
		return PTR_ERR(t);
	return size;
}

enum libbpf_print_level {
	LIBBPF_WARN,
	LIBBPF_INFO,
	LIBBPF_DEBUG,
};

#undef pr_warn
#undef pr_info
#undef pr_debug
#define pr_warn(fmt, log, ...)	bpf_log((void *)log, fmt, "", ##__VA_ARGS__)
#define pr_info(fmt, log, ...)	bpf_log((void *)log, fmt, "", ##__VA_ARGS__)
#define pr_debug(fmt, log, ...)	bpf_log((void *)log, fmt, "", ##__VA_ARGS__)
#define libbpf_print(level, fmt, ...)	bpf_log((void *)prog_name, fmt, ##__VA_ARGS__)
#else
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <linux/err.h>

#include "libbpf.h"
#include "bpf.h"
#include "btf.h"
#include "str_error.h"
#include "libbpf_internal.h"
#endif

static bool is_flex_arr(const struct btf *btf,
			const struct bpf_core_accessor *acc,
			const struct btf_array *arr)
{
	const struct btf_type *t;

	/* not a flexible array, if not inside a struct or has non-zero size */
	if (!acc->name || arr->nelems > 0)
		return false;

	/* has to be the last member of enclosing struct */
	t = btf_type_by_id(btf, acc->type_id);
	return acc->idx == btf_vlen(t) - 1;
}

static const char *core_relo_kind_str(enum bpf_core_relo_kind kind)
{
	switch (kind) {
	case BPF_CORE_FIELD_BYTE_OFFSET: return "byte_off";
	case BPF_CORE_FIELD_BYTE_SIZE: return "byte_sz";
	case BPF_CORE_FIELD_EXISTS: return "field_exists";
	case BPF_CORE_FIELD_SIGNED: return "signed";
	case BPF_CORE_FIELD_LSHIFT_U64: return "lshift_u64";
	case BPF_CORE_FIELD_RSHIFT_U64: return "rshift_u64";
	case BPF_CORE_TYPE_ID_LOCAL: return "local_type_id";
	case BPF_CORE_TYPE_ID_TARGET: return "target_type_id";
	case BPF_CORE_TYPE_EXISTS: return "type_exists";
	case BPF_CORE_TYPE_MATCHES: return "type_matches";
	case BPF_CORE_TYPE_SIZE: return "type_size";
	case BPF_CORE_ENUMVAL_EXISTS: return "enumval_exists";
	case BPF_CORE_ENUMVAL_VALUE: return "enumval_value";
	default: return "unknown";
	}
}

static bool core_relo_is_field_based(enum bpf_core_relo_kind kind)
{
	switch (kind) {
	case BPF_CORE_FIELD_BYTE_OFFSET:
	case BPF_CORE_FIELD_BYTE_SIZE:
	case BPF_CORE_FIELD_EXISTS:
	case BPF_CORE_FIELD_SIGNED:
	case BPF_CORE_FIELD_LSHIFT_U64:
	case BPF_CORE_FIELD_RSHIFT_U64:
		return true;
	default:
		return false;
	}
}

static bool core_relo_is_type_based(enum bpf_core_relo_kind kind)
{
	switch (kind) {
	case BPF_CORE_TYPE_ID_LOCAL:
	case BPF_CORE_TYPE_ID_TARGET:
	case BPF_CORE_TYPE_EXISTS:
	case BPF_CORE_TYPE_MATCHES:
	case BPF_CORE_TYPE_SIZE:
		return true;
	default:
		return false;
	}
}

static bool core_relo_is_enumval_based(enum bpf_core_relo_kind kind)
{
	switch (kind) {
	case BPF_CORE_ENUMVAL_EXISTS:
	case BPF_CORE_ENUMVAL_VALUE:
		return true;
	default:
		return false;
	}
}

int __bpf_core_types_are_compat(const struct btf *local_btf, __u32 local_id,
				const struct btf *targ_btf, __u32 targ_id, int level)
{
	const struct btf_type *local_type, *targ_type;
	int depth = 32; /* max recursion depth */

	/* caller made sure that names match (ignoring flavor suffix) */
	local_type = btf_type_by_id(local_btf, local_id);
	targ_type = btf_type_by_id(targ_btf, targ_id);
	if (!btf_kind_core_compat(local_type, targ_type))
		return 0;

recur:
	depth--;
	if (depth < 0)
		return -EINVAL;

	local_type = skip_mods_and_typedefs(local_btf, local_id, &local_id);
	targ_type = skip_mods_and_typedefs(targ_btf, targ_id, &targ_id);
	if (!local_type || !targ_type)
		return -EINVAL;

	if (!btf_kind_core_compat(local_type, targ_type))
		return 0;

	switch (btf_kind(local_type)) {
	case BTF_KIND_UNKN:
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
	case BTF_KIND_ENUM:
	case BTF_KIND_FWD:
	case BTF_KIND_ENUM64:
		return 1;
	case BTF_KIND_INT:
		/* just reject deprecated bitfield-like integers; all other
		 * integers are by default compatible between each other
		 */
		return btf_int_offset(local_type) == 0 && btf_int_offset(targ_type) == 0;
	case BTF_KIND_PTR:
		local_id = local_type->type;
		targ_id = targ_type->type;
		goto recur;
	case BTF_KIND_ARRAY:
		local_id = btf_array(local_type)->type;
		targ_id = btf_array(targ_type)->type;
		goto recur;
	case BTF_KIND_FUNC_PROTO: {
		struct btf_param *local_p = btf_params(local_type);
		struct btf_param *targ_p = btf_params(targ_type);
		__u16 local_vlen = btf_vlen(local_type);
		__u16 targ_vlen = btf_vlen(targ_type);
		int i, err;

		if (local_vlen != targ_vlen)
			return 0;

		for (i = 0; i < local_vlen; i++, local_p++, targ_p++) {
			if (level <= 0)
				return -EINVAL;

			skip_mods_and_typedefs(local_btf, local_p->type, &local_id);
			skip_mods_and_typedefs(targ_btf, targ_p->type, &targ_id);
			err = __bpf_core_types_are_compat(local_btf, local_id, targ_btf, targ_id,
							  level - 1);
			if (err <= 0)
				return err;
		}

		/* tail recurse for return type check */
		skip_mods_and_typedefs(local_btf, local_type->type, &local_id);
		skip_mods_and_typedefs(targ_btf, targ_type->type, &targ_id);
		goto recur;
	}
	default:
		pr_warn("unexpected kind %s relocated, local [%d], target [%d]\n",
			btf_kind_str(local_type), local_id, targ_id);
		return 0;
	}
}

int bpf_core_parse_spec(const char *prog_name, const struct btf *btf,
			const struct bpf_core_relo *relo,
			struct bpf_core_spec *spec)
{
	int access_idx, parsed_len, i;
	struct bpf_core_accessor *acc;
	const struct btf_type *t;
	const char *name, *spec_str;
	__u32 id, name_off;
	__s64 sz;

	spec_str = btf__name_by_offset(btf, relo->access_str_off);
	if (str_is_empty(spec_str) || *spec_str == ':')
		return -EINVAL;

	memset(spec, 0, sizeof(*spec));
	spec->btf = btf;
	spec->root_type_id = relo->type_id;
	spec->relo_kind = relo->kind;

	/* type-based relocations don't have a field access string */
	if (core_relo_is_type_based(relo->kind)) {
		if (strcmp(spec_str, "0"))
			return -EINVAL;
		return 0;
	}

	/* parse spec_str="0:1:2:3:4" into array raw_spec=[0, 1, 2, 3, 4] */
	while (*spec_str) {
		if (*spec_str == ':')
			++spec_str;
		if (sscanf(spec_str, "%d%n", &access_idx, &parsed_len) != 1)
			return -EINVAL;
		if (spec->raw_len == BPF_CORE_SPEC_MAX_LEN)
			return -E2BIG;
		spec_str += parsed_len;
		spec->raw_spec[spec->raw_len++] = access_idx;
	}

	if (spec->raw_len == 0)
		return -EINVAL;

	t = skip_mods_and_typedefs(btf, relo->type_id, &id);
	if (!t)
		return -EINVAL;

	access_idx = spec->raw_spec[0];
	acc = &spec->spec[0];
	acc->type_id = id;
	acc->idx = access_idx;
	spec->len++;

	if (core_relo_is_enumval_based(relo->kind)) {
		if (!btf_is_any_enum(t) || spec->raw_len > 1 || access_idx >= btf_vlen(t))
			return -EINVAL;

		/* record enumerator name in a first accessor */
		name_off = btf_is_enum(t) ? btf_enum(t)[access_idx].name_off
					  : btf_enum64(t)[access_idx].name_off;
		acc->name = btf__name_by_offset(btf, name_off);
		return 0;
	}

	if (!core_relo_is_field_based(relo->kind))
		return -EINVAL;

	sz = btf__resolve_size(btf, id);
	if (sz < 0)
		return sz;
	spec->bit_offset = access_idx * sz * 8;

	for (i = 1; i < spec->raw_len; i++) {
		t = skip_mods_and_typedefs(btf, id, &id);
		if (!t)
			return -EINVAL;

		access_idx = spec->raw_spec[i];
		acc = &spec->spec[spec->len];

		if (btf_is_composite(t)) {
			const struct btf_member *m;
			__u32 bit_offset;

			if (access_idx >= btf_vlen(t))
				return -EINVAL;

			bit_offset = btf_member_bit_offset(t, access_idx);
			spec->bit_offset += bit_offset;

			m = btf_members(t) + access_idx;
			if (m->name_off) {
				name = btf__name_by_offset(btf, m->name_off);
				if (str_is_empty(name))
					return -EINVAL;

				acc->type_id = id;
				acc->idx = access_idx;
				acc->name = name;
				spec->len++;
			}

			id = m->type;
		} else if (btf_is_array(t)) {
			const struct btf_array *a = btf_array(t);
			bool flex;

			t = skip_mods_and_typedefs(btf, a->type, &id);
			if (!t)
				return -EINVAL;

			flex = is_flex_arr(btf, acc - 1, a);
			if (!flex && access_idx >= a->nelems)
				return -EINVAL;

			spec->spec[spec->len].type_id = id;
			spec->spec[spec->len].idx = access_idx;
			spec->len++;

			sz = btf__resolve_size(btf, id);
			if (sz < 0)
				return sz;
			spec->bit_offset += access_idx * sz * 8;
		} else {
			pr_warn("prog '%s': relo for [%u] %s (at idx %d) captures type [%d] of unexpected kind %s\n",
				prog_name, relo->type_id, spec_str, i, id, btf_kind_str(t));
			return -EINVAL;
		}
	}

	return 0;
}

static int bpf_core_fields_are_compat(const struct btf *local_btf,
				      __u32 local_id,
				      const struct btf *targ_btf,
				      __u32 targ_id)
{
	const struct btf_type *local_type, *targ_type;

recur:
	local_type = skip_mods_and_typedefs(local_btf, local_id, &local_id);
	targ_type = skip_mods_and_typedefs(targ_btf, targ_id, &targ_id);
	if (!local_type || !targ_type)
		return -EINVAL;

	if (btf_is_composite(local_type) && btf_is_composite(targ_type))
		return 1;
	if (!btf_kind_core_compat(local_type, targ_type))
		return 0;

	switch (btf_kind(local_type)) {
	case BTF_KIND_PTR:
	case BTF_KIND_FLOAT:
		return 1;
	case BTF_KIND_FWD:
	case BTF_KIND_ENUM64:
	case BTF_KIND_ENUM: {
		const char *local_name, *targ_name;
		size_t local_len, targ_len;

		local_name = btf__name_by_offset(local_btf,
						 local_type->name_off);
		targ_name = btf__name_by_offset(targ_btf, targ_type->name_off);
		local_len = bpf_core_essential_name_len(local_name);
		targ_len = bpf_core_essential_name_len(targ_name);
		/* one of them is anonymous or both w/ same flavor-less names */
		return local_len == 0 || targ_len == 0 ||
		       (local_len == targ_len &&
			strncmp(local_name, targ_name, local_len) == 0);
	}
	case BTF_KIND_INT:
		/* just reject deprecated bitfield-like integers; all other
		 * integers are by default compatible between each other
		 */
		return btf_int_offset(local_type) == 0 &&
		       btf_int_offset(targ_type) == 0;
	case BTF_KIND_ARRAY:
		local_id = btf_array(local_type)->type;
		targ_id = btf_array(targ_type)->type;
		goto recur;
	default:
		return 0;
	}
}

static int bpf_core_match_member(const struct btf *local_btf,
				 const struct bpf_core_accessor *local_acc,
				 const struct btf *targ_btf,
				 __u32 targ_id,
				 struct bpf_core_spec *spec,
				 __u32 *next_targ_id)
{
	const struct btf_type *local_type, *targ_type;
	const struct btf_member *local_member, *m;
	const char *local_name, *targ_name;
	__u32 local_id;
	int i, n, found;

	targ_type = skip_mods_and_typedefs(targ_btf, targ_id, &targ_id);
	if (!targ_type)
		return -EINVAL;
	if (!btf_is_composite(targ_type))
		return 0;

	local_id = local_acc->type_id;
	local_type = btf_type_by_id(local_btf, local_id);
	local_member = btf_members(local_type) + local_acc->idx;
	local_name = btf__name_by_offset(local_btf, local_member->name_off);

	n = btf_vlen(targ_type);
	m = btf_members(targ_type);
	for (i = 0; i < n; i++, m++) {
		__u32 bit_offset;

		bit_offset = btf_member_bit_offset(targ_type, i);

		/* too deep struct/union/array nesting */
		if (spec->raw_len == BPF_CORE_SPEC_MAX_LEN)
			return -E2BIG;

		/* speculate this member will be the good one */
		spec->bit_offset += bit_offset;
		spec->raw_spec[spec->raw_len++] = i;

		targ_name = btf__name_by_offset(targ_btf, m->name_off);
		if (str_is_empty(targ_name)) {
			/* embedded struct/union, we need to go deeper */
			found = bpf_core_match_member(local_btf, local_acc,
						      targ_btf, m->type,
						      spec, next_targ_id);
			if (found) /* either found or error */
				return found;
		} else if (strcmp(local_name, targ_name) == 0) {
			/* matching named field */
			struct bpf_core_accessor *targ_acc;

			targ_acc = &spec->spec[spec->len++];
			targ_acc->type_id = targ_id;
			targ_acc->idx = i;
			targ_acc->name = targ_name;

			*next_targ_id = m->type;
			found = bpf_core_fields_are_compat(local_btf,
							   local_member->type,
							   targ_btf, m->type);
			if (!found)
				spec->len--; /* pop accessor */
			return found;
		}
		/* member turned out not to be what we looked for */
		spec->bit_offset -= bit_offset;
		spec->raw_len--;
	}

	return 0;
}
