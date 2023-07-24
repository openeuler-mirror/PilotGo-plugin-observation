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
