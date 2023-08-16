// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2018 Facebook */

#include <byteswap.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/btf.h>
#include <gelf.h>
#include "btf.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"
#include "hashmap.h"
#include "strset.h"

#define BTF_MAX_NR_TYPES 0x7fffffffU
#define BTF_MAX_STR_OFFSET 0x7fffffffU

static struct btf_type btf_void;

struct btf {
	/* raw BTF data in native endianness */
	void *raw_data;
	/* raw BTF data in non-native endianness */
	void *raw_data_swapped;
	__u32 raw_size;
	/* whether target endianness differs from the native one */
	bool swapped_endian;

	struct btf_header *hdr;

	void *types_data;
	size_t types_data_cap; /* used size stored in hdr->type_len */

	__u32 *type_offs;
	size_t type_offs_cap;
	__u32 nr_types;
	struct btf *base_btf;
	int start_id;
	int start_str_off;

	void *strs_data;
	/* a set of unique strings */
	struct strset *strs_set;
	/* whether strings are already deduplicated */
	bool strs_deduped;

	/* BTF object FD, if loaded into kernel */
	int fd;

	/* Pointer size (in bytes) for a target architecture of this BTF */
	int ptr_sz;
};

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

void *libbpf_add_mem(void **data, size_t *cap_cnt, size_t elem_sz,
		     size_t cur_cnt, size_t max_cnt, size_t add_cnt)
{
	size_t new_cnt;
	void *new_data;

	if (cur_cnt + add_cnt <= *cap_cnt)
		return *data + cur_cnt * elem_sz;

	/* requested more than the set limit */
	if (cur_cnt + add_cnt > max_cnt)
		return NULL;

	new_cnt = *cap_cnt;
	new_cnt += new_cnt / 4;		  /* expand by 25% */
	if (new_cnt < 16)		  /* but at least 16 elements */
		new_cnt = 16;
	if (new_cnt > max_cnt)		  /* but not exceeding a set limit */
		new_cnt = max_cnt;
	if (new_cnt < cur_cnt + add_cnt)  /* also ensure we have enough memory */
		new_cnt = cur_cnt + add_cnt;

	new_data = libbpf_reallocarray(*data, new_cnt, elem_sz);
	if (!new_data)
		return NULL;

	/* zero out newly allocated portion of memory */
	memset(new_data + (*cap_cnt) * elem_sz, 0, (new_cnt - *cap_cnt) * elem_sz);

	*data = new_data;
	*cap_cnt = new_cnt;
	return new_data + cur_cnt * elem_sz;
}

int libbpf_ensure_mem(void **data, size_t *cap_cnt, size_t elem_sz, size_t need_cnt)
{
	void *p;

	if (need_cnt <= *cap_cnt)
		return 0;

	p = libbpf_add_mem(data, cap_cnt, elem_sz, *cap_cnt, SIZE_MAX, need_cnt - *cap_cnt);
	if (!p)
		return -ENOMEM;

	return 0;
}

static void *btf_add_type_offs_mem(struct btf *btf, size_t add_cnt)
{
	return libbpf_add_mem((void **)&btf->type_offs, &btf->type_offs_cap, sizeof(__u32),
			      btf->nr_types, BTF_MAX_NR_TYPES, add_cnt);
}

static int btf_add_type_idx_entry(struct btf *btf, __u32 type_off)
{
	__u32 *p;

	p = btf_add_type_offs_mem(btf, 1);
	if (!p)
		return -ENOMEM;

	*p = type_off;
	return 0;
}

static void btf_bswap_hdr(struct btf_header *h)
{
	h->magic = bswap_16(h->magic);
	h->hdr_len = bswap_32(h->hdr_len);
	h->type_off = bswap_32(h->type_off);
	h->type_len = bswap_32(h->type_len);
	h->str_off = bswap_32(h->str_off);
	h->str_len = bswap_32(h->str_len);
}

static int btf_parse_hdr(struct btf *btf)
{
	struct btf_header *hdr = btf->hdr;
	__u32 meta_left;

	if (btf->raw_size < sizeof(struct btf_header)) {
		pr_debug("BTF header not found\n");
		return -EINVAL;
	}

	if (hdr->magic == bswap_16(BTF_MAGIC)) {
		btf->swapped_endian = true;
		if (bswap_32(hdr->hdr_len) != sizeof(struct btf_header)) {
			pr_warn("Can't load BTF with non-native endianness due to unsupported header length %u\n",
				bswap_32(hdr->hdr_len));
			return -ENOTSUP;
		}
		btf_bswap_hdr(hdr);
	} else if (hdr->magic != BTF_MAGIC) {
		pr_debug("Invalid BTF magic: %x\n", hdr->magic);
		return -EINVAL;
	}

	if (btf->raw_size < hdr->hdr_len) {
		pr_debug("BTF header len %u larger than data size %u\n",
			 hdr->hdr_len, btf->raw_size);
		return -EINVAL;
	}

	meta_left = btf->raw_size - hdr->hdr_len;
	if (meta_left < (long long)hdr->str_off + hdr->str_len) {
		pr_debug("Invalid BTF total size: %u\n", btf->raw_size);
		return -EINVAL;
	}

	if ((long long)hdr->type_off + hdr->type_len > hdr->str_off) {
		pr_debug("Invalid BTF data sections layout: type data at %u + %u, strings data at %u + %u\n",
			 hdr->type_off, hdr->type_len, hdr->str_off, hdr->str_len);
		return -EINVAL;
	}

	if (hdr->type_off % 4) {
		pr_debug("BTF type section is not aligned to 4 bytes\n");
		return -EINVAL;
	}

	return 0;
}

static int btf_parse_str_sec(struct btf *btf)
{
	const struct btf_header *hdr = btf->hdr;
	const char *start = btf->strs_data;
	const char *end = start + btf->hdr->str_len;

	if (btf->base_btf && hdr->str_len == 0)
		return 0;
	if (!hdr->str_len || hdr->str_len - 1 > BTF_MAX_STR_OFFSET || end[-1]) {
		pr_debug("Invalid BTF string section\n");
		return -EINVAL;
	}
	if (!btf->base_btf && start[0]) {
		pr_debug("Invalid BTF string section\n");
		return -EINVAL;
	}
	return 0;
}

static int btf_type_size(const struct btf_type *t)
{
	const int base_size = sizeof(struct btf_type);
	__u16 vlen = btf_vlen(t);

	switch (btf_kind(t)) {
	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		return base_size;
	case BTF_KIND_INT:
		return base_size + sizeof(__u32);
	case BTF_KIND_ENUM:
		return base_size + vlen * sizeof(struct btf_enum);
	case BTF_KIND_ENUM64:
		return base_size + vlen * sizeof(struct btf_enum64);
	case BTF_KIND_ARRAY:
		return base_size + sizeof(struct btf_array);
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return base_size + vlen * sizeof(struct btf_member);
	case BTF_KIND_FUNC_PROTO:
		return base_size + vlen * sizeof(struct btf_param);
	case BTF_KIND_VAR:
		return base_size + sizeof(struct btf_var);
	case BTF_KIND_DATASEC:
		return base_size + vlen * sizeof(struct btf_var_secinfo);
	case BTF_KIND_DECL_TAG:
		return base_size + sizeof(struct btf_decl_tag);
	default:
		pr_debug("Unsupported BTF_KIND:%u\n", btf_kind(t));
		return -EINVAL;
	}
}

static void btf_bswap_type_base(struct btf_type *t)
{
	t->name_off = bswap_32(t->name_off);
	t->info = bswap_32(t->info);
	t->type = bswap_32(t->type);
}

static int btf_bswap_type_rest(struct btf_type *t)
{
	struct btf_var_secinfo *v;
	struct btf_enum64 *e64;
	struct btf_member *m;
	struct btf_array *a;
	struct btf_param *p;
	struct btf_enum *e;
	__u16 vlen = btf_vlen(t);
	int i;

	switch (btf_kind(t)) {
	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		return 0;
	case BTF_KIND_INT:
		*(__u32 *)(t + 1) = bswap_32(*(__u32 *)(t + 1));
		return 0;
	case BTF_KIND_ENUM:
		for (i = 0, e = btf_enum(t); i < vlen; i++, e++) {
			e->name_off = bswap_32(e->name_off);
			e->val = bswap_32(e->val);
		}
		return 0;
	case BTF_KIND_ENUM64:
		for (i = 0, e64 = btf_enum64(t); i < vlen; i++, e64++) {
			e64->name_off = bswap_32(e64->name_off);
			e64->val_lo32 = bswap_32(e64->val_lo32);
			e64->val_hi32 = bswap_32(e64->val_hi32);
		}
		return 0;
	case BTF_KIND_ARRAY:
		a = btf_array(t);
		a->type = bswap_32(a->type);
		a->index_type = bswap_32(a->index_type);
		a->nelems = bswap_32(a->nelems);
		return 0;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		for (i = 0, m = btf_members(t); i < vlen; i++, m++) {
			m->name_off = bswap_32(m->name_off);
			m->type = bswap_32(m->type);
			m->offset = bswap_32(m->offset);
		}
		return 0;
	case BTF_KIND_FUNC_PROTO:
		for (i = 0, p = btf_params(t); i < vlen; i++, p++) {
			p->name_off = bswap_32(p->name_off);
			p->type = bswap_32(p->type);
		}
		return 0;
	case BTF_KIND_VAR:
		btf_var(t)->linkage = bswap_32(btf_var(t)->linkage);
		return 0;
	case BTF_KIND_DATASEC:
		for (i = 0, v = btf_var_secinfos(t); i < vlen; i++, v++) {
			v->type = bswap_32(v->type);
			v->offset = bswap_32(v->offset);
			v->size = bswap_32(v->size);
		}
		return 0;
	case BTF_KIND_DECL_TAG:
		btf_decl_tag(t)->component_idx = bswap_32(btf_decl_tag(t)->component_idx);
		return 0;
	default:
		pr_debug("Unsupported BTF_KIND:%u\n", btf_kind(t));
		return -EINVAL;
	}
}

static int btf_parse_type_sec(struct btf *btf)
{
	struct btf_header *hdr = btf->hdr;
	void *next_type = btf->types_data;
	void *end_type = next_type + hdr->type_len;
	int err, type_size;

	while (next_type + sizeof(struct btf_type) <= end_type) {
		if (btf->swapped_endian)
			btf_bswap_type_base(next_type);

		type_size = btf_type_size(next_type);
		if (type_size < 0)
			return type_size;
		if (next_type + type_size > end_type) {
			pr_warn("BTF type [%d] is malformed\n", btf->start_id + btf->nr_types);
			return -EINVAL;
		}

		if (btf->swapped_endian && btf_bswap_type_rest(next_type))
			return -EINVAL;

		err = btf_add_type_idx_entry(btf, next_type - btf->types_data);
		if (err)
			return err;

		next_type += type_size;
		btf->nr_types++;
	}

	if (next_type != end_type) {
		pr_warn("BTF types data is malformed\n");
		return -EINVAL;
	}

	return 0;
}

__u32 btf__type_cnt(const struct btf *btf)
{
	return btf->start_id + btf->nr_types;
}

const struct btf *btf__base_btf(const struct btf *btf)
{
	return btf->base_btf;
}

/* internal helper returning non-const pointer to a type */
struct btf_type *btf_type_by_id(const struct btf *btf, __u32 type_id)
{
	if (type_id == 0)
		return &btf_void;
	if (type_id < btf->start_id)
		return btf_type_by_id(btf->base_btf, type_id);
	return btf->types_data + btf->type_offs[type_id - btf->start_id];
}

const struct btf_type *btf__type_by_id(const struct btf *btf, __u32 type_id)
{
	if (type_id >= btf->start_id + btf->nr_types)
		return errno = EINVAL, NULL;
	return btf_type_by_id((struct btf *)btf, type_id);
}

static int determine_ptr_size(const struct btf *btf)
{
	static const char * const long_aliases[] = {
		"long",
		"long int",
		"int long",
		"unsigned long",
		"long unsigned",
		"unsigned long int",
		"unsigned int long",
		"long unsigned int",
		"long int unsigned",
		"int unsigned long",
		"int long unsigned",
	};
	const struct btf_type *t;
	const char *name;
	int i, j, n;

	if (btf->base_btf && btf->base_btf->ptr_sz > 0)
		return btf->base_btf->ptr_sz;

	n = btf__type_cnt(btf);
	for (i = 1; i < n; i++) {
		t = btf__type_by_id(btf, i);
		if (!btf_is_int(t))
			continue;

		if (t->size != 4 && t->size != 8)
			continue;

		name = btf__name_by_offset(btf, t->name_off);
		if (!name)
			continue;

		for (j = 0; j < ARRAY_SIZE(long_aliases); j++) {
			if (strcmp(name, long_aliases[j]) == 0)
				return t->size;
		}
	}

	return -1;
}

static size_t btf_ptr_sz(const struct btf *btf)
{
	if (!btf->ptr_sz)
		((struct btf *)btf)->ptr_sz = determine_ptr_size(btf);
	return btf->ptr_sz < 0 ? sizeof(void *) : btf->ptr_sz;
}

size_t btf__pointer_size(const struct btf *btf)
{
	if (!btf->ptr_sz)
		((struct btf *)btf)->ptr_sz = determine_ptr_size(btf);

	if (btf->ptr_sz < 0)
		/* not enough BTF type info to guess */
		return 0;

	return btf->ptr_sz;
}

/* Override or set pointer size in bytes. Only values of 4 and 8 are
 * supported.
 */
int btf__set_pointer_size(struct btf *btf, size_t ptr_sz)
{
	if (ptr_sz != 4 && ptr_sz != 8)
		return libbpf_err(-EINVAL);
	btf->ptr_sz = ptr_sz;
	return 0;
}

static bool is_host_big_endian(void)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return false;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return true;
#else
# error "Unrecognized __BYTE_ORDER__"
#endif
}

enum btf_endianness btf__endianness(const struct btf *btf)
{
	if (is_host_big_endian())
		return btf->swapped_endian ? BTF_LITTLE_ENDIAN : BTF_BIG_ENDIAN;
	else
		return btf->swapped_endian ? BTF_BIG_ENDIAN : BTF_LITTLE_ENDIAN;
}

int btf__set_endianness(struct btf *btf, enum btf_endianness endian)
{
	if (endian != BTF_LITTLE_ENDIAN && endian != BTF_BIG_ENDIAN)
		return libbpf_err(-EINVAL);

	btf->swapped_endian = is_host_big_endian() != (endian == BTF_BIG_ENDIAN);
	if (!btf->swapped_endian) {
		free(btf->raw_data_swapped);
		btf->raw_data_swapped = NULL;
	}
	return 0;
}

static bool btf_type_is_void(const struct btf_type *t)
{
	return t == &btf_void || btf_is_fwd(t);
}

static bool btf_type_is_void_or_null(const struct btf_type *t)
{
	return !t || btf_type_is_void(t);
}

#define MAX_RESOLVE_DEPTH 32

__s64 btf__resolve_size(const struct btf *btf, __u32 type_id)
{
	const struct btf_array *array;
	const struct btf_type *t;
	__u32 nelems = 1;
	__s64 size = -1;
	int i;

	t = btf__type_by_id(btf, type_id);
	for (i = 0; i < MAX_RESOLVE_DEPTH && !btf_type_is_void_or_null(t); i++) {
		switch (btf_kind(t)) {
		case BTF_KIND_INT:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
		case BTF_KIND_DATASEC:
		case BTF_KIND_FLOAT:
			size = t->size;
			goto done;
		case BTF_KIND_PTR:
			size = btf_ptr_sz(btf);
			goto done;
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_VAR:
		case BTF_KIND_DECL_TAG:
		case BTF_KIND_TYPE_TAG:
			type_id = t->type;
			break;
		case BTF_KIND_ARRAY:
			array = btf_array(t);
			if (nelems && array->nelems > UINT32_MAX / nelems)
				return libbpf_err(-E2BIG);
			nelems *= array->nelems;
			type_id = array->type;
			break;
		default:
			return libbpf_err(-EINVAL);
		}

		t = btf__type_by_id(btf, type_id);
	}

done:
	if (size < 0)
		return libbpf_err(-EINVAL);
	if (nelems && size > UINT32_MAX / nelems)
		return libbpf_err(-E2BIG);

	return nelems * size;
}#define MAX_RESOLVE_DEPTH 32

__s64 btf__resolve_size(const struct btf *btf, __u32 type_id)
{
	const struct btf_array *array;
	const struct btf_type *t;
	__u32 nelems = 1;
	__s64 size = -1;
	int i;

	t = btf__type_by_id(btf, type_id);
	for (i = 0; i < MAX_RESOLVE_DEPTH && !btf_type_is_void_or_null(t); i++) {
		switch (btf_kind(t)) {
		case BTF_KIND_INT:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
		case BTF_KIND_DATASEC:
		case BTF_KIND_FLOAT:
			size = t->size;
			goto done;
		case BTF_KIND_PTR:
			size = btf_ptr_sz(btf);
			goto done;
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_VAR:
		case BTF_KIND_DECL_TAG:
		case BTF_KIND_TYPE_TAG:
			type_id = t->type;
			break;
		case BTF_KIND_ARRAY:
			array = btf_array(t);
			if (nelems && array->nelems > UINT32_MAX / nelems)
				return libbpf_err(-E2BIG);
			nelems *= array->nelems;
			type_id = array->type;
			break;
		default:
			return libbpf_err(-EINVAL);
		}

		t = btf__type_by_id(btf, type_id);
	}

done:
	if (size < 0)
		return libbpf_err(-EINVAL);
	if (nelems && size > UINT32_MAX / nelems)
		return libbpf_err(-E2BIG);

	return nelems * size;
}

int btf__align_of(const struct btf *btf, __u32 id)
{
	const struct btf_type *t = btf__type_by_id(btf, id);
	__u16 kind = btf_kind(t);

	switch (kind) {
	case BTF_KIND_INT:
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
	case BTF_KIND_FLOAT:
		return min(btf_ptr_sz(btf), (size_t)t->size);
	case BTF_KIND_PTR:
		return btf_ptr_sz(btf);
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPE_TAG:
		return btf__align_of(btf, t->type);
	case BTF_KIND_ARRAY:
		return btf__align_of(btf, btf_array(t)->type);
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		const struct btf_member *m = btf_members(t);
		__u16 vlen = btf_vlen(t);
		int i, max_align = 1, align;

		for (i = 0; i < vlen; i++, m++) {
			align = btf__align_of(btf, m->type);
			if (align <= 0)
				return libbpf_err(align);
			max_align = max(max_align, align);

			/* if field offset isn't aligned according to field
			 * type's alignment, then struct must be packed
			 */
			if (btf_member_bitfield_size(t, i) == 0 &&
			    (m->offset % (8 * align)) != 0)
				return 1;
		}

		/* if struct/union size isn't a multiple of its alignment,
		 * then struct must be packed
		 */
		if ((t->size % max_align) != 0)
			return 1;

		return max_align;
	}
	default:
		pr_warn("unsupported BTF_KIND:%u\n", btf_kind(t));
		return errno = EINVAL, 0;
	}
}

int btf__resolve_type(const struct btf *btf, __u32 type_id)
{
	const struct btf_type *t;
	int depth = 0;

	t = btf__type_by_id(btf, type_id);
	while (depth < MAX_RESOLVE_DEPTH &&
	       !btf_type_is_void_or_null(t) &&
	       (btf_is_mod(t) || btf_is_typedef(t) || btf_is_var(t))) {
		type_id = t->type;
		t = btf__type_by_id(btf, type_id);
		depth++;
	}

	if (depth == MAX_RESOLVE_DEPTH || btf_type_is_void_or_null(t))
		return libbpf_err(-EINVAL);

	return type_id;
}

__s32 btf__find_by_name(const struct btf *btf, const char *type_name)
{
	__u32 i, nr_types = btf__type_cnt(btf);

	if (!strcmp(type_name, "void"))
		return 0;

	for (i = 1; i < nr_types; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		const char *name = btf__name_by_offset(btf, t->name_off);

		if (name && !strcmp(type_name, name))
			return i;
	}

	return libbpf_err(-ENOENT);
}

static __s32 btf_find_by_name_kind(const struct btf *btf, int start_id,
				   const char *type_name, __u32 kind)
{
	__u32 i, nr_types = btf__type_cnt(btf);

	if (kind == BTF_KIND_UNKN || !strcmp(type_name, "void"))
		return 0;

	for (i = start_id; i < nr_types; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		const char *name;

		if (btf_kind(t) != kind)
			continue;
		name = btf__name_by_offset(btf, t->name_off);
		if (name && !strcmp(type_name, name))
			return i;
	}

	return libbpf_err(-ENOENT);
}

__s32 btf__find_by_name_kind_own(const struct btf *btf, const char *type_name,
				 __u32 kind)
{
	return btf_find_by_name_kind(btf, btf->start_id, type_name, kind);
}

__s32 btf__find_by_name_kind(const struct btf *btf, const char *type_name,
			     __u32 kind)
{
	return btf_find_by_name_kind(btf, 1, type_name, kind);
}

static bool btf_is_modifiable(const struct btf *btf)
{
	return (void *)btf->hdr != btf->raw_data;
}

void btf__free(struct btf *btf)
{
	if (IS_ERR_OR_NULL(btf))
		return;

	if (btf->fd >= 0)
		close(btf->fd);

	if (btf_is_modifiable(btf)) {
		/* if BTF was modified after loading, it will have a split
		 * in-memory representation for header, types, and strings
		 * sections, so we need to free all of them individually. It
		 * might still have a cached contiguous raw data present,
		 * which will be unconditionally freed below.
		 */
		free(btf->hdr);
		free(btf->types_data);
		strset__free(btf->strs_set);
	}
	free(btf->raw_data);
	free(btf->raw_data_swapped);
	free(btf->type_offs);
	free(btf);
}

static struct btf *btf_new_empty(struct btf *base_btf)
{
	struct btf *btf;

	btf = calloc(1, sizeof(*btf));
	if (!btf)
		return ERR_PTR(-ENOMEM);

	btf->nr_types = 0;
	btf->start_id = 1;
	btf->start_str_off = 0;
	btf->fd = -1;
	btf->ptr_sz = sizeof(void *);
	btf->swapped_endian = false;

	if (base_btf) {
		btf->base_btf = base_btf;
		btf->start_id = btf__type_cnt(base_btf);
		btf->start_str_off = base_btf->hdr->str_len;
	}

	/* +1 for empty string at offset 0 */
	btf->raw_size = sizeof(struct btf_header) + (base_btf ? 0 : 1);
	btf->raw_data = calloc(1, btf->raw_size);
	if (!btf->raw_data) {
		free(btf);
		return ERR_PTR(-ENOMEM);
	}

	btf->hdr = btf->raw_data;
	btf->hdr->hdr_len = sizeof(struct btf_header);
	btf->hdr->magic = BTF_MAGIC;
	btf->hdr->version = BTF_VERSION;

	btf->types_data = btf->raw_data + btf->hdr->hdr_len;
	btf->strs_data = btf->raw_data + btf->hdr->hdr_len;
	btf->hdr->str_len = base_btf ? 0 : 1; /* empty string at offset 0 */

	return btf;
}

struct btf *btf__new_empty(void)
{
	return libbpf_ptr(btf_new_empty(NULL));
}

struct btf *btf__new_empty_split(struct btf *base_btf)
{
	return libbpf_ptr(btf_new_empty(base_btf));
}

static struct btf *btf_new(const void *data, __u32 size, struct btf *base_btf)
{
	struct btf *btf;
	int err;

	btf = calloc(1, sizeof(struct btf));
	if (!btf)
		return ERR_PTR(-ENOMEM);

	btf->nr_types = 0;
	btf->start_id = 1;
	btf->start_str_off = 0;
	btf->fd = -1;

	if (base_btf) {
		btf->base_btf = base_btf;
		btf->start_id = btf__type_cnt(base_btf);
		btf->start_str_off = base_btf->hdr->str_len;
	}

	btf->raw_data = malloc(size);
	if (!btf->raw_data) {
		err = -ENOMEM;
		goto done;
	}
	memcpy(btf->raw_data, data, size);
	btf->raw_size = size;

	btf->hdr = btf->raw_data;
	err = btf_parse_hdr(btf);
	if (err)
		goto done;

	btf->strs_data = btf->raw_data + btf->hdr->hdr_len + btf->hdr->str_off;
	btf->types_data = btf->raw_data + btf->hdr->hdr_len + btf->hdr->type_off;

	err = btf_parse_str_sec(btf);
	err = err ?: btf_parse_type_sec(btf);
	if (err)
		goto done;

done:
	if (err) {
		btf__free(btf);
		return ERR_PTR(err);
	}

	return btf;
}

struct btf *btf__new(const void *data, __u32 size)
{
	return libbpf_ptr(btf_new(data, size, NULL));
}

static struct btf *btf_parse_elf(const char *path, struct btf *base_btf,
				 struct btf_ext **btf_ext)
{
	Elf_Data *btf_data = NULL, *btf_ext_data = NULL;
	int err = 0, fd = -1, idx = 0;
	struct btf *btf = NULL;
	Elf_Scn *scn = NULL;
	Elf *elf = NULL;
	GElf_Ehdr ehdr;
	size_t shstrndx;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		pr_warn("failed to init libelf for %s\n", path);
		return ERR_PTR(-LIBBPF_ERRNO__LIBELF);
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = -errno;
		pr_warn("failed to open %s: %s\n", path, strerror(errno));
		return ERR_PTR(err);
	}

	err = -LIBBPF_ERRNO__FORMAT;

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		pr_warn("failed to open %s as ELF file\n", path);
		goto done;
	}
	if (!gelf_getehdr(elf, &ehdr)) {
		pr_warn("failed to get EHDR from %s\n", path);
		goto done;
	}

	if (elf_getshdrstrndx(elf, &shstrndx)) {
		pr_warn("failed to get section names section index for %s\n",
			path);
		goto done;
	}

	if (!elf_rawdata(elf_getscn(elf, shstrndx), NULL)) {
		pr_warn("failed to get e_shstrndx from %s\n", path);
		goto done;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr sh;
		char *name;

		idx++;
		if (gelf_getshdr(scn, &sh) != &sh) {
			pr_warn("failed to get section(%d) header from %s\n",
				idx, path);
			goto done;
		}
		name = elf_strptr(elf, shstrndx, sh.sh_name);
		if (!name) {
			pr_warn("failed to get section(%d) name from %s\n",
				idx, path);
			goto done;
		}
		if (strcmp(name, BTF_ELF_SEC) == 0) {
			btf_data = elf_getdata(scn, 0);
			if (!btf_data) {
				pr_warn("failed to get section(%d, %s) data from %s\n",
					idx, name, path);
				goto done;
			}
			continue;
		} else if (btf_ext && strcmp(name, BTF_EXT_ELF_SEC) == 0) {
			btf_ext_data = elf_getdata(scn, 0);
			if (!btf_ext_data) {
				pr_warn("failed to get section(%d, %s) data from %s\n",
					idx, name, path);
				goto done;
			}
			continue;
		}
	}

	if (!btf_data) {
		pr_warn("failed to find '%s' ELF section in %s\n", BTF_ELF_SEC, path);
		err = -ENODATA;
		goto done;
	}
	btf = btf_new(btf_data->d_buf, btf_data->d_size, base_btf);
	err = libbpf_get_error(btf);
	if (err)
		goto done;

	switch (gelf_getclass(elf)) {
	case ELFCLASS32:
		btf__set_pointer_size(btf, 4);
		break;
	case ELFCLASS64:
		btf__set_pointer_size(btf, 8);
		break;
	default:
		pr_warn("failed to get ELF class (bitness) for %s\n", path);
		break;
	}

	if (btf_ext && btf_ext_data) {
		*btf_ext = btf_ext__new(btf_ext_data->d_buf, btf_ext_data->d_size);
		err = libbpf_get_error(*btf_ext);
		if (err)
			goto done;
	} else if (btf_ext) {
		*btf_ext = NULL;
	}
done:
	if (elf)
		elf_end(elf);
	close(fd);

	if (!err)
		return btf;

	if (btf_ext)
		btf_ext__free(*btf_ext);
	btf__free(btf);

	return ERR_PTR(err);
}

struct btf *btf__parse_elf(const char *path, struct btf_ext **btf_ext)
{
	return libbpf_ptr(btf_parse_elf(path, NULL, btf_ext));
}

struct btf *btf__parse_elf_split(const char *path, struct btf *base_btf)
{
	return libbpf_ptr(btf_parse_elf(path, base_btf, NULL));
}

static struct btf *btf_parse_raw(const char *path, struct btf *base_btf)
{
	struct btf *btf = NULL;
	void *data = NULL;
	FILE *f = NULL;
	__u16 magic;
	int err = 0;
	long sz;

	f = fopen(path, "rb");
	if (!f) {
		err = -errno;
		goto err_out;
	}

	/* check BTF magic */
	if (fread(&magic, 1, sizeof(magic), f) < sizeof(magic)) {
		err = -EIO;
		goto err_out;
	}
	if (magic != BTF_MAGIC && magic != bswap_16(BTF_MAGIC)) {
		/* definitely not a raw BTF */
		err = -EPROTO;
		goto err_out;
	}

	/* get file size */
	if (fseek(f, 0, SEEK_END)) {
		err = -errno;
		goto err_out;
	}
	sz = ftell(f);
	if (sz < 0) {
		err = -errno;
		goto err_out;
	}
	/* rewind to the start */
	if (fseek(f, 0, SEEK_SET)) {
		err = -errno;
		goto err_out;
	}

	/* pre-alloc memory and read all of BTF data */
	data = malloc(sz);
	if (!data) {
		err = -ENOMEM;
		goto err_out;
	}
	if (fread(data, 1, sz, f) < sz) {
		err = -EIO;
		goto err_out;
	}

	/* finally parse BTF data */
	btf = btf_new(data, sz, base_btf);

err_out:
	free(data);
	if (f)
		fclose(f);
	return err ? ERR_PTR(err) : btf;
}

struct btf *btf__parse_raw(const char *path)
{
	return libbpf_ptr(btf_parse_raw(path, NULL));
}

struct btf *btf__parse_raw_split(const char *path, struct btf *base_btf)
{
	return libbpf_ptr(btf_parse_raw(path, base_btf));
}

static struct btf *btf_parse(const char *path, struct btf *base_btf, struct btf_ext **btf_ext)
{
	struct btf *btf;
	int err;

	if (btf_ext)
		*btf_ext = NULL;

	btf = btf_parse_raw(path, base_btf);
	err = libbpf_get_error(btf);
	if (!err)
		return btf;
	if (err != -EPROTO)
		return ERR_PTR(err);
	return btf_parse_elf(path, base_btf, btf_ext);
}

struct btf *btf__parse(const char *path, struct btf_ext **btf_ext)
{
	return libbpf_ptr(btf_parse(path, NULL, btf_ext));
}

struct btf *btf__parse_split(const char *path, struct btf *base_btf)
{
	return libbpf_ptr(btf_parse(path, base_btf, NULL));
}

static void *btf_get_raw_data(const struct btf *btf, __u32 *size, bool swap_endian);

int btf_load_into_kernel(struct btf *btf, char *log_buf, size_t log_sz, __u32 log_level)
{
	LIBBPF_OPTS(bpf_btf_load_opts, opts);
	__u32 buf_sz = 0, raw_size;
	char *buf = NULL, *tmp;
	void *raw_data;
	int err = 0;

	if (btf->fd >= 0)
		return libbpf_err(-EEXIST);
	if (log_sz && !log_buf)
		return libbpf_err(-EINVAL);

	/* cache native raw data representation */
	raw_data = btf_get_raw_data(btf, &raw_size, false);
	if (!raw_data) {
		err = -ENOMEM;
		goto done;
	}
	btf->raw_size = raw_size;
	btf->raw_data = raw_data;

retry_load:
	if (log_level) {
		/* if caller didn't provide custom log_buf, we'll keep
		 * allocating our own progressively bigger buffers for BTF
		 * verification log
		 */
		if (!log_buf) {
			buf_sz = max((__u32)BPF_LOG_BUF_SIZE, buf_sz * 2);
			tmp = realloc(buf, buf_sz);
			if (!tmp) {
				err = -ENOMEM;
				goto done;
			}
			buf = tmp;
			buf[0] = '\0';
		}

		opts.log_buf = log_buf ? log_buf : buf;
		opts.log_size = log_buf ? log_sz : buf_sz;
		opts.log_level = log_level;
	}

	btf->fd = bpf_btf_load(raw_data, raw_size, &opts);
	if (btf->fd < 0) {
		/* time to turn on verbose mode and try again */
		if (log_level == 0) {
			log_level = 1;
			goto retry_load;
		}
		/* only retry if caller didn't provide custom log_buf, but
		 * make sure we can never overflow buf_sz
		 */
		if (!log_buf && errno == ENOSPC && buf_sz <= UINT_MAX / 2)
			goto retry_load;

		err = -errno;
		pr_warn("BTF loading error: %d\n", err);
		/* don't print out contents of custom log_buf */
		if (!log_buf && buf[0])
			pr_warn("-- BEGIN BTF LOAD LOG ---\n%s\n-- END BTF LOAD LOG --\n", buf);
	}

done:
	free(buf);
	return libbpf_err(err);
}

int btf__load_into_kernel(struct btf *btf)
{
	return btf_load_into_kernel(btf, NULL, 0, 0);
}

int btf__fd(const struct btf *btf)
{
	return btf->fd;
}

void btf__set_fd(struct btf *btf, int fd)
{
	btf->fd = fd;
}

static const void *btf_strs_data(const struct btf *btf)
{
	return btf->strs_data ? btf->strs_data : strset__data(btf->strs_set);
}

static void *btf_get_raw_data(const struct btf *btf, __u32 *size, bool swap_endian)
{
	struct btf_header *hdr = btf->hdr;
	struct btf_type *t;
	void *data, *p;
	__u32 data_sz;
	int i;

	data = swap_endian ? btf->raw_data_swapped : btf->raw_data;
	if (data) {
		*size = btf->raw_size;
		return data;
	}

	data_sz = hdr->hdr_len + hdr->type_len + hdr->str_len;
	data = calloc(1, data_sz);
	if (!data)
		return NULL;
	p = data;

	memcpy(p, hdr, hdr->hdr_len);
	if (swap_endian)
		btf_bswap_hdr(p);
	p += hdr->hdr_len;

	memcpy(p, btf->types_data, hdr->type_len);
	if (swap_endian) {
		for (i = 0; i < btf->nr_types; i++) {
			t = p + btf->type_offs[i];
			/* btf_bswap_type_rest() relies on native t->info, so
			 * we swap base type info after we swapped all the
			 * additional information
			 */
			if (btf_bswap_type_rest(t))
				goto err_out;
			btf_bswap_type_base(t);
		}
	}
	p += hdr->type_len;

	memcpy(p, btf_strs_data(btf), hdr->str_len);
	p += hdr->str_len;

	*size = data_sz;
	return data;
err_out:
	free(data);
	return NULL;
}

const void *btf__raw_data(const struct btf *btf_ro, __u32 *size)
{
	struct btf *btf = (struct btf *)btf_ro;
	__u32 data_sz;
	void *data;

	data = btf_get_raw_data(btf, &data_sz, btf->swapped_endian);
	if (!data)
		return errno = ENOMEM, NULL;

	btf->raw_size = data_sz;
	if (btf->swapped_endian)
		btf->raw_data_swapped = data;
	else
		btf->raw_data = data;
	*size = data_sz;
	return data;
}

__attribute__((alias("btf__raw_data")))
const void *btf__get_raw_data(const struct btf *btf, __u32 *size);

const char *btf__str_by_offset(const struct btf *btf, __u32 offset)
{
	if (offset < btf->start_str_off)
		return btf__str_by_offset(btf->base_btf, offset);
	else if (offset - btf->start_str_off < btf->hdr->str_len)
		return btf_strs_data(btf) + (offset - btf->start_str_off);
	else
		return errno = EINVAL, NULL;
}

const char *btf__name_by_offset(const struct btf *btf, __u32 offset)
{
	return btf__str_by_offset(btf, offset);
}

struct btf *btf_get_from_fd(int btf_fd, struct btf *base_btf)
{
	struct bpf_btf_info btf_info;
	__u32 len = sizeof(btf_info);
	__u32 last_size;
	struct btf *btf;
	void *ptr;
	int err;

	last_size = 4096;
	ptr = malloc(last_size);
	if (!ptr)
		return ERR_PTR(-ENOMEM);

	memset(&btf_info, 0, sizeof(btf_info));
	btf_info.btf = ptr_to_u64(ptr);
	btf_info.btf_size = last_size;
	err = bpf_btf_get_info_by_fd(btf_fd, &btf_info, &len);

	if (!err && btf_info.btf_size > last_size) {
		void *temp_ptr;

		last_size = btf_info.btf_size;
		temp_ptr = realloc(ptr, last_size);
		if (!temp_ptr) {
			btf = ERR_PTR(-ENOMEM);
			goto exit_free;
		}
		ptr = temp_ptr;

		len = sizeof(btf_info);
		memset(&btf_info, 0, sizeof(btf_info));
		btf_info.btf = ptr_to_u64(ptr);
		btf_info.btf_size = last_size;

		err = bpf_btf_get_info_by_fd(btf_fd, &btf_info, &len);
	}

	if (err || btf_info.btf_size > last_size) {
		btf = err ? ERR_PTR(-errno) : ERR_PTR(-E2BIG);
		goto exit_free;
	}

	btf = btf_new(ptr, btf_info.btf_size, base_btf);

exit_free:
	free(ptr);
	return btf;
}

struct btf *btf__load_from_kernel_by_id_split(__u32 id, struct btf *base_btf)
{
	struct btf *btf;
	int btf_fd;

	btf_fd = bpf_btf_get_fd_by_id(id);
	if (btf_fd < 0)
		return libbpf_err_ptr(-errno);

	btf = btf_get_from_fd(btf_fd, base_btf);
	close(btf_fd);

	return libbpf_ptr(btf);
}

struct btf *btf__load_from_kernel_by_id(__u32 id)
{
	return btf__load_from_kernel_by_id_split(id, NULL);
}

static void btf_invalidate_raw_data(struct btf *btf)
{
	if (btf->raw_data) {
		free(btf->raw_data);
		btf->raw_data = NULL;
	}
	if (btf->raw_data_swapped) {
		free(btf->raw_data_swapped);
		btf->raw_data_swapped = NULL;
	}
}

static int btf_ensure_modifiable(struct btf *btf)
{
	void *hdr, *types;
	struct strset *set = NULL;
	int err = -ENOMEM;

	if (btf_is_modifiable(btf)) {
		/* any BTF modification invalidates raw_data */
		btf_invalidate_raw_data(btf);
		return 0;
	}

	/* split raw data into three memory regions */
	hdr = malloc(btf->hdr->hdr_len);
	types = malloc(btf->hdr->type_len);
	if (!hdr || !types)
		goto err_out;

	memcpy(hdr, btf->hdr, btf->hdr->hdr_len);
	memcpy(types, btf->types_data, btf->hdr->type_len);

	/* build lookup index for all strings */
	set = strset__new(BTF_MAX_STR_OFFSET, btf->strs_data, btf->hdr->str_len);
	if (IS_ERR(set)) {
		err = PTR_ERR(set);
		goto err_out;
	}

	/* only when everything was successful, update internal state */
	btf->hdr = hdr;
	btf->types_data = types;
	btf->types_data_cap = btf->hdr->type_len;
	btf->strs_data = NULL;
	btf->strs_set = set;
	/* if BTF was created from scratch, all strings are guaranteed to be
	 * unique and deduplicated
	 */
	if (btf->hdr->str_len == 0)
		btf->strs_deduped = true;
	if (!btf->base_btf && btf->hdr->str_len == 1)
		btf->strs_deduped = true;

	/* invalidate raw_data representation */
	btf_invalidate_raw_data(btf);

	return 0;

err_out:
	strset__free(set);
	free(hdr);
	free(types);
	return err;
}

int btf__find_str(struct btf *btf, const char *s)
{
	int off;

	if (btf->base_btf) {
		off = btf__find_str(btf->base_btf, s);
		if (off != -ENOENT)
			return off;
	}

	/* BTF needs to be in a modifiable state to build string lookup index */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	off = strset__find_str(btf->strs_set, s);
	if (off < 0)
		return libbpf_err(off);

	return btf->start_str_off + off;
}

int btf__add_str(struct btf *btf, const char *s)
{
	int off;

	if (btf->base_btf) {
		off = btf__find_str(btf->base_btf, s);
		if (off != -ENOENT)
			return off;
	}

	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	off = strset__add_str(btf->strs_set, s);
	if (off < 0)
		return libbpf_err(off);

	btf->hdr->str_len = strset__data_size(btf->strs_set);

	return btf->start_str_off + off;
}

static void *btf_add_type_mem(struct btf *btf, size_t add_sz)
{
	return libbpf_add_mem(&btf->types_data, &btf->types_data_cap, 1,
			      btf->hdr->type_len, UINT_MAX, add_sz);
}

static void btf_type_inc_vlen(struct btf_type *t)
{
	t->info = btf_type_info(btf_kind(t), btf_vlen(t) + 1, btf_kflag(t));
}

static int btf_commit_type(struct btf *btf, int data_sz)
{
	int err;

	err = btf_add_type_idx_entry(btf, btf->hdr->type_len);
	if (err)
		return libbpf_err(err);

	btf->hdr->type_len += data_sz;
	btf->hdr->str_off += data_sz;
	btf->nr_types++;
	return btf->start_id + btf->nr_types - 1;
}

struct btf_pipe {
	const struct btf *src;
	struct btf *dst;
	struct hashmap *str_off_map; /* map string offsets from src to dst */
};

static int btf_rewrite_str(__u32 *str_off, void *ctx)
{
	struct btf_pipe *p = ctx;
	long mapped_off;
	int off, err;

	if (!*str_off) /* nothing to do for empty strings */
		return 0;

	if (p->str_off_map &&
	    hashmap__find(p->str_off_map, *str_off, &mapped_off)) {
		*str_off = mapped_off;
		return 0;
	}

	off = btf__add_str(p->dst, btf__str_by_offset(p->src, *str_off));
	if (off < 0)
		return off;

	/* Remember string mapping from src to dst.  It avoids
	 * performing expensive string comparisons.
	 */
	if (p->str_off_map) {
		err = hashmap__append(p->str_off_map, *str_off, off);
		if (err)
			return err;
	}

	*str_off = off;
	return 0;
}

int btf__add_type(struct btf *btf, const struct btf *src_btf, const struct btf_type *src_type)
{
	struct btf_pipe p = { .src = src_btf, .dst = btf };
	struct btf_type *t;
	int sz, err;

	sz = btf_type_size(src_type);
	if (sz < 0)
		return libbpf_err(sz);

	/* deconstruct BTF, if necessary, and invalidate raw_data */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	t = btf_add_type_mem(btf, sz);
	if (!t)
		return libbpf_err(-ENOMEM);

	memcpy(t, src_type, sz);

	err = btf_type_visit_str_offs(t, btf_rewrite_str, &p);
	if (err)
		return libbpf_err(err);

	return btf_commit_type(btf, sz);
}

static int btf_rewrite_type_ids(__u32 *type_id, void *ctx)
{
	struct btf *btf = ctx;

	if (!*type_id) /* nothing to do for VOID references */
		return 0;

	*type_id += btf->start_id + btf->nr_types - 1;
	return 0;
}

static size_t btf_dedup_identity_hash_fn(long key, void *ctx);
static bool btf_dedup_equal_fn(long k1, long k2, void *ctx);

int btf__add_btf(struct btf *btf, const struct btf *src_btf)
{
	struct btf_pipe p = { .src = src_btf, .dst = btf };
	int data_sz, sz, cnt, i, err, old_strs_len;
	__u32 *off;
	void *t;

	/* appending split BTF isn't supported yet */
	if (src_btf->base_btf)
		return libbpf_err(-ENOTSUP);

	/* deconstruct BTF, if necessary, and invalidate raw_data */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	old_strs_len = btf->hdr->str_len;

	data_sz = src_btf->hdr->type_len;
	cnt = btf__type_cnt(src_btf) - 1;

	/* pre-allocate enough memory for new types */
	t = btf_add_type_mem(btf, data_sz);
	if (!t)
		return libbpf_err(-ENOMEM);

	/* pre-allocate enough memory for type offset index for new types */
	off = btf_add_type_offs_mem(btf, cnt);
	if (!off)
		return libbpf_err(-ENOMEM);

	/* Map the string offsets from src_btf to the offsets from btf to improve performance */
	p.str_off_map = hashmap__new(btf_dedup_identity_hash_fn, btf_dedup_equal_fn, NULL);
	if (IS_ERR(p.str_off_map))
		return libbpf_err(-ENOMEM);

	/* bulk copy types data for all types from src_btf */
	memcpy(t, src_btf->types_data, data_sz);

	for (i = 0; i < cnt; i++) {
		sz = btf_type_size(t);
		if (sz < 0) {
			/* unlikely, has to be corrupted src_btf */
			err = sz;
			goto err_out;
		}

		/* fill out type ID to type offset mapping for lookups by type ID */
		*off = t - btf->types_data;

		/* add, dedup, and remap strings referenced by this BTF type */
		err = btf_type_visit_str_offs(t, btf_rewrite_str, &p);
		if (err)
			goto err_out;

		/* remap all type IDs referenced from this BTF type */
		err = btf_type_visit_type_ids(t, btf_rewrite_type_ids, btf);
		if (err)
			goto err_out;

		/* go to next type data and type offset index entry */
		t += sz;
		off++;
	}

	btf->hdr->type_len += data_sz;
	btf->hdr->str_off += data_sz;
	btf->nr_types += cnt;

	hashmap__free(p.str_off_map);

	/* return type ID of the first added BTF type */
	return btf->start_id + btf->nr_types - cnt;
err_out:
	/* zero out preallocated memory as if it was just allocated with
	 * libbpf_add_mem()
	 */
	memset(btf->types_data + btf->hdr->type_len, 0, data_sz);
	memset(btf->strs_data + old_strs_len, 0, btf->hdr->str_len - old_strs_len);

	btf->hdr->str_len = old_strs_len;

	hashmap__free(p.str_off_map)

	return libbpf_err(err);
}

int btf__add_int(struct btf *btf, const char *name, size_t byte_sz, int encoding)
{
	struct btf_type *t;
	int sz, name_off;

	/* non-empty name */
	if (!name || !name[0])
		return libbpf_err(-EINVAL);
	/* byte_sz must be power of 2 */
	if (!byte_sz || (byte_sz & (byte_sz - 1)) || byte_sz > 16)
		return libbpf_err(-EINVAL);
	if (encoding & ~(BTF_INT_SIGNED | BTF_INT_CHAR | BTF_INT_BOOL))
		return libbpf_err(-EINVAL);

	/* deconstruct BTF, if necessary, and invalidate raw_data */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_type) + sizeof(int);
	t = btf_add_type_mem(btf, sz);
	if (!t)
		return libbpf_err(-ENOMEM);

	name_off = btf__add_str(btf, name);
	if (name_off < 0)
		return name_off;

	t->name_off = name_off;
	t->info = btf_type_info(BTF_KIND_INT, 0, 0);
	t->size = byte_sz;
	/* set INT info, we don't allow setting legacy bit offset/size */
	*(__u32 *)(t + 1) = (encoding << 24) | (byte_sz * 8);

	return btf_commit_type(btf, sz);
}

int btf__add_float(struct btf *btf, const char *name, size_t byte_sz)
{
	struct btf_type *t;
	int sz, name_off;

	/* non-empty name */
	if (!name || !name[0])
		return libbpf_err(-EINVAL);

	/* byte_sz must be one of the explicitly allowed values */
	if (byte_sz != 2 && byte_sz != 4 && byte_sz != 8 && byte_sz != 12 &&
	    byte_sz != 16)
		return libbpf_err(-EINVAL);

	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_type);
	t = btf_add_type_mem(btf, sz);
	if (!t)
		return libbpf_err(-ENOMEM);

	name_off = btf__add_str(btf, name);
	if (name_off < 0)
		return name_off;

	t->name_off = name_off;
	t->info = btf_type_info(BTF_KIND_FLOAT, 0, 0);
	t->size = byte_sz;

	return btf_commit_type(btf, sz);
}

static int validate_type_id(int id)
{
	if (id < 0 || id > BTF_MAX_NR_TYPES)
		return -EINVAL;
	return 0;
}

/* generic append function for PTR, TYPEDEF, CONST/VOLATILE/RESTRICT */
static int btf_add_ref_kind(struct btf *btf, int kind, const char *name, int ref_type_id)
{
	struct btf_type *t;
	int sz, name_off = 0;

	if (validate_type_id(ref_type_id))
		return libbpf_err(-EINVAL);

	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_type);
	t = btf_add_type_mem(btf, sz);
	if (!t)
		return libbpf_err(-ENOMEM);

	if (name && name[0]) {
		name_off = btf__add_str(btf, name);
		if (name_off < 0)
			return name_off;
	}

	t->name_off = name_off;
	t->info = btf_type_info(kind, 0, 0);
	t->type = ref_type_id;

	return btf_commit_type(btf, sz);
}

int btf__add_struct(struct btf *btf, const char *name, __u32 byte_sz)
{
	return btf_add_composite(btf, BTF_KIND_STRUCT, name, byte_sz);
}

int btf__add_union(struct btf *btf, const char *name, __u32 byte_sz)
{
	return btf_add_composite(btf, BTF_KIND_UNION, name, byte_sz);
}

static struct btf_type *btf_last_type(struct btf *btf)
{
	return btf_type_by_id(btf, btf__type_cnt(btf) - 1);
}

int btf__add_field(struct btf *btf, const char *name, int type_id,
		   __u32 bit_offset, __u32 bit_size)
{
	struct btf_type *t;
	struct btf_member *m;
	bool is_bitfield;
	int sz, name_off = 0;

	/* last type should be union/struct */
	if (btf->nr_types == 0)
		return libbpf_err(-EINVAL);
	t = btf_last_type(btf);
	if (!btf_is_composite(t))
		return libbpf_err(-EINVAL);

	if (validate_type_id(type_id))
		return libbpf_err(-EINVAL);
	/* best-effort bit field offset/size enforcement */
	is_bitfield = bit_size || (bit_offset % 8 != 0);
	if (is_bitfield && (bit_size == 0 || bit_size > 255 || bit_offset > 0xffffff))
		return libbpf_err(-EINVAL);

	/* only offset 0 is allowed for unions */
	if (btf_is_union(t) && bit_offset)
		return libbpf_err(-EINVAL);

	/* decompose and invalidate raw data */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_member);
	m = btf_add_type_mem(btf, sz);
	if (!m)
		return libbpf_err(-ENOMEM);

	if (name && name[0]) {
		name_off = btf__add_str(btf, name);
		if (name_off < 0)
			return name_off;
	}

	m->name_off = name_off;
	m->type = type_id;
	m->offset = bit_offset | (bit_size << 24);

	/* btf_add_type_mem can invalidate t pointer */
	t = btf_last_type(btf);
	/* update parent type's vlen and kflag */
	t->info = btf_type_info(btf_kind(t), btf_vlen(t) + 1, is_bitfield || btf_kflag(t));

	btf->hdr->type_len += sz;
	btf->hdr->str_off += sz;
	return 0;
}

static int btf_add_enum_common(struct btf *btf, const char *name, __u32 byte_sz,
			       bool is_signed, __u8 kind)
{
	struct btf_type *t;
	int sz, name_off = 0;

	/* byte_sz must be power of 2 */
	if (!byte_sz || (byte_sz & (byte_sz - 1)) || byte_sz > 8)
		return libbpf_err(-EINVAL);

	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_type);
	t = btf_add_type_mem(btf, sz);
	if (!t)
		return libbpf_err(-ENOMEM);

	if (name && name[0]) {
		name_off = btf__add_str(btf, name);
		if (name_off < 0)
			return name_off;
	}

	/* start out with vlen=0; it will be adjusted when adding enum values */
	t->name_off = name_off;
	t->info = btf_type_info(kind, 0, is_signed);
	t->size = byte_sz;

	return btf_commit_type(btf, sz);
}

int btf__add_enum(struct btf *btf, const char *name, __u32 byte_sz)
{
	/*
	 * set the signedness to be unsigned, it will change to signed
	 * if any later enumerator is negative.
	 */
	return btf_add_enum_common(btf, name, byte_sz, false, BTF_KIND_ENUM);
}

int btf__add_enum_value(struct btf *btf, const char *name, __s64 value)
{
	struct btf_type *t;
	struct btf_enum *v;
	int sz, name_off;

	/* last type should be BTF_KIND_ENUM */
	if (btf->nr_types == 0)
		return libbpf_err(-EINVAL);
	t = btf_last_type(btf);
	if (!btf_is_enum(t))
		return libbpf_err(-EINVAL);

	/* non-empty name */
	if (!name || !name[0])
		return libbpf_err(-EINVAL);
	if (value < INT_MIN || value > UINT_MAX)
		return libbpf_err(-E2BIG);

	/* decompose and invalidate raw data */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_enum);
	v = btf_add_type_mem(btf, sz);
	if (!v)
		return libbpf_err(-ENOMEM);

	name_off = btf__add_str(btf, name);
	if (name_off < 0)
		return name_off;

	v->name_off = name_off;
	v->val = value;

	/* update parent type's vlen */
	t = btf_last_type(btf);
	btf_type_inc_vlen(t);

	/* if negative value, set signedness to signed */
	if (value < 0)
		t->info = btf_type_info(btf_kind(t), btf_vlen(t), true);

	btf->hdr->type_len += sz;
	btf->hdr->str_off += sz;
	return 0;
}

int btf__add_enum64(struct btf *btf, const char *name, __u32 byte_sz,
		    bool is_signed)
{
	return btf_add_enum_common(btf, name, byte_sz, is_signed,
				   BTF_KIND_ENUM64);
}

int btf__add_enum64_value(struct btf *btf, const char *name, __u64 value)
{
	struct btf_enum64 *v;
	struct btf_type *t;
	int sz, name_off;

	/* last type should be BTF_KIND_ENUM64 */
	if (btf->nr_types == 0)
		return libbpf_err(-EINVAL);
	t = btf_last_type(btf);
	if (!btf_is_enum64(t))
		return libbpf_err(-EINVAL);

	/* non-empty name */
	if (!name || !name[0])
		return libbpf_err(-EINVAL);

	/* decompose and invalidate raw data */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_enum64);
	v = btf_add_type_mem(btf, sz);
	if (!v)
		return libbpf_err(-ENOMEM);

	name_off = btf__add_str(btf, name);
	if (name_off < 0)
		return name_off;

	v->name_off = name_off;
	v->val_lo32 = (__u32)value;
	v->val_hi32 = value >> 32;

	/* update parent type's vlen */
	t = btf_last_type(btf);
	btf_type_inc_vlen(t);

	btf->hdr->type_len += sz;
	btf->hdr->str_off += sz;
	return 0;
}

int btf__add_fwd(struct btf *btf, const char *name, enum btf_fwd_kind fwd_kind)
{
	if (!name || !name[0])
		return libbpf_err(-EINVAL);

	switch (fwd_kind) {
	case BTF_FWD_STRUCT:
	case BTF_FWD_UNION: {
		struct btf_type *t;
		int id;

		id = btf_add_ref_kind(btf, BTF_KIND_FWD, name, 0);
		if (id <= 0)
			return id;
		t = btf_type_by_id(btf, id);
		t->info = btf_type_info(BTF_KIND_FWD, 0, fwd_kind == BTF_FWD_UNION);
		return id;
	}
	case BTF_FWD_ENUM:
		/* enum forward in BTF currently is just an enum with no enum
		 * values; we also assume a standard 4-byte size for it
		 */
		return btf__add_enum(btf, name, sizeof(int));
	default:
		return libbpf_err(-EINVAL);
	}
}

int btf__add_typedef(struct btf *btf, const char *name, int ref_type_id)
{
	if (!name || !name[0])
		return libbpf_err(-EINVAL);

	return btf_add_ref_kind(btf, BTF_KIND_TYPEDEF, name, ref_type_id);
}

int btf__add_volatile(struct btf *btf, int ref_type_id)
{
	return btf_add_ref_kind(btf, BTF_KIND_VOLATILE, NULL, ref_type_id);
}

int btf__add_const(struct btf *btf, int ref_type_id)
{
	return btf_add_ref_kind(btf, BTF_KIND_CONST, NULL, ref_type_id);
}

int btf__add_restrict(struct btf *btf, int ref_type_id)
{
	return btf_add_ref_kind(btf, BTF_KIND_RESTRICT, NULL, ref_type_id);
}

int btf__add_type_tag(struct btf *btf, const char *value, int ref_type_id)
{
	if (!value || !value[0])
		return libbpf_err(-EINVAL);

	return btf_add_ref_kind(btf, BTF_KIND_TYPE_TAG, value, ref_type_id);
}

int btf__add_func(struct btf *btf, const char *name,
		  enum btf_func_linkage linkage, int proto_type_id)
{
	int id;

	if (!name || !name[0])
		return libbpf_err(-EINVAL);
	if (linkage != BTF_FUNC_STATIC && linkage != BTF_FUNC_GLOBAL &&
	    linkage != BTF_FUNC_EXTERN)
		return libbpf_err(-EINVAL);

	id = btf_add_ref_kind(btf, BTF_KIND_FUNC, name, proto_type_id);
	if (id > 0) {
		struct btf_type *t = btf_type_by_id(btf, id);

		t->info = btf_type_info(BTF_KIND_FUNC, linkage, 0);
	}
	return libbpf_err(id);
}

int btf__add_func_proto(struct btf *btf, int ret_type_id)
{
	struct btf_type *t;
	int sz;

	if (validate_type_id(ret_type_id))
		return libbpf_err(-EINVAL);

	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_type);
	t = btf_add_type_mem(btf, sz);
	if (!t)
		return libbpf_err(-ENOMEM);

	/* start out with vlen=0; this will be adjusted when adding enum
	 * values, if necessary
	 */
	t->name_off = 0;
	t->info = btf_type_info(BTF_KIND_FUNC_PROTO, 0, 0);
	t->type = ret_type_id;

	return btf_commit_type(btf, sz);
}

int btf__add_func_param(struct btf *btf, const char *name, int type_id)
{
	struct btf_type *t;
	struct btf_param *p;
	int sz, name_off = 0;

	if (validate_type_id(type_id))
		return libbpf_err(-EINVAL);

	/* last type should be BTF_KIND_FUNC_PROTO */
	if (btf->nr_types == 0)
		return libbpf_err(-EINVAL);
	t = btf_last_type(btf);
	if (!btf_is_func_proto(t))
		return libbpf_err(-EINVAL);

	/* decompose and invalidate raw data */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_param);
	p = btf_add_type_mem(btf, sz);
	if (!p)
		return libbpf_err(-ENOMEM);

	if (name && name[0]) {
		name_off = btf__add_str(btf, name);
		if (name_off < 0)
			return name_off;
	}

	p->name_off = name_off;
	p->type = type_id;

	/* update parent type's vlen */
	t = btf_last_type(btf);
	btf_type_inc_vlen(t);

	btf->hdr->type_len += sz;
	btf->hdr->str_off += sz;
	return 0;
}

int btf__add_var(struct btf *btf, const char *name, int linkage, int type_id)
{
	struct btf_type *t;
	struct btf_var *v;
	int sz, name_off;

	/* non-empty name */
	if (!name || !name[0])
		return libbpf_err(-EINVAL);
	if (linkage != BTF_VAR_STATIC && linkage != BTF_VAR_GLOBAL_ALLOCATED &&
	    linkage != BTF_VAR_GLOBAL_EXTERN)
		return libbpf_err(-EINVAL);
	if (validate_type_id(type_id))
		return libbpf_err(-EINVAL);

	/* deconstruct BTF, if necessary, and invalidate raw_data */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_type) + sizeof(struct btf_var);
	t = btf_add_type_mem(btf, sz);
	if (!t)
		return libbpf_err(-ENOMEM);

	name_off = btf__add_str(btf, name);
	if (name_off < 0)
		return name_off;

	t->name_off = name_off;
	t->info = btf_type_info(BTF_KIND_VAR, 0, 0);
	t->type = type_id;

	v = btf_var(t);
	v->linkage = linkage;

	return btf_commit_type(btf, sz);
}

int btf__add_datasec(struct btf *btf, const char *name, __u32 byte_sz)
{
	struct btf_type *t;
	int sz, name_off;

	/* non-empty name */
	if (!name || !name[0])
		return libbpf_err(-EINVAL);

	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_type);
	t = btf_add_type_mem(btf, sz);
	if (!t)
		return libbpf_err(-ENOMEM);

	name_off = btf__add_str(btf, name);
	if (name_off < 0)
		return name_off;

	/* start with vlen=0, which will be update as var_secinfos are added */
	t->name_off = name_off;
	t->info = btf_type_info(BTF_KIND_DATASEC, 0, 0);
	t->size = byte_sz;

	return btf_commit_type(btf, sz);
}

int btf__add_datasec_var_info(struct btf *btf, int var_type_id, __u32 offset, __u32 byte_sz)
{
	struct btf_type *t;
	struct btf_var_secinfo *v;
	int sz;

	/* last type should be BTF_KIND_DATASEC */
	if (btf->nr_types == 0)
		return libbpf_err(-EINVAL);
	t = btf_last_type(btf);
	if (!btf_is_datasec(t))
		return libbpf_err(-EINVAL);

	if (validate_type_id(var_type_id))
		return libbpf_err(-EINVAL);

	/* decompose and invalidate raw data */
	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_var_secinfo);
	v = btf_add_type_mem(btf, sz);
	if (!v)
		return libbpf_err(-ENOMEM);

	v->type = var_type_id;
	v->offset = offset;
	v->size = byte_sz;

	/* update parent type's vlen */
	t = btf_last_type(btf);
	btf_type_inc_vlen(t);

	btf->hdr->type_len += sz;
	btf->hdr->str_off += sz;
	return 0;
}

int btf__add_decl_tag(struct btf *btf, const char *value, int ref_type_id,
		 int component_idx)
{
	struct btf_type *t;
	int sz, value_off;

	if (!value || !value[0] || component_idx < -1)
		return libbpf_err(-EINVAL);

	if (validate_type_id(ref_type_id))
		return libbpf_err(-EINVAL);

	if (btf_ensure_modifiable(btf))
		return libbpf_err(-ENOMEM);

	sz = sizeof(struct btf_type) + sizeof(struct btf_decl_tag);
	t = btf_add_type_mem(btf, sz);
	if (!t)
		return libbpf_err(-ENOMEM);

	value_off = btf__add_str(btf, value);
	if (value_off < 0)
		return value_off;

	t->name_off = value_off;
	t->info = btf_type_info(BTF_KIND_DECL_TAG, 0, false);
	t->type = ref_type_id;
	btf_decl_tag(t)->component_idx = component_idx;

	return btf_commit_type(btf, sz);
}

struct btf_ext_sec_setup_param {
	__u32 off;
	__u32 len;
	__u32 min_rec_size;
	struct btf_ext_info *ext_info;
	const char *desc;
};

static int btf_ext_setup_info(struct btf_ext *btf_ext,
			      struct btf_ext_sec_setup_param *ext_sec)
{
	const struct btf_ext_info_sec *sinfo;
	struct btf_ext_info *ext_info;
	__u32 info_left, record_size;
	size_t sec_cnt = 0;
	/* The start of the info sec (including the __u32 record_size). */
	void *info;

	if (ext_sec->len == 0)
		return 0;

	if (ext_sec->off & 0x03) {
		pr_debug(".BTF.ext %s section is not aligned to 4 bytes\n",
		     ext_sec->desc);
		return -EINVAL;
	}

	info = btf_ext->data + btf_ext->hdr->hdr_len + ext_sec->off;
	info_left = ext_sec->len;

	if (btf_ext->data + btf_ext->data_size < info + ext_sec->len) {
		pr_debug("%s section (off:%u len:%u) is beyond the end of the ELF section .BTF.ext\n",
			 ext_sec->desc, ext_sec->off, ext_sec->len);
		return -EINVAL;
	}

	info = btf_ext->data + btf_ext->hdr->hdr_len + ext_sec->off;
	info_left = ext_sec->len;

	if (btf_ext->data + btf_ext->data_size < info + ext_sec->len) {
		pr_debug("%s section (off:%u len:%u) is beyond the end of the ELF section .BTF.ext\n",
			 ext_sec->desc, ext_sec->off, ext_sec->len);
		return -EINVAL;
	}

	/* At least a record size */
	if (info_left < sizeof(__u32)) {
		pr_debug(".BTF.ext %s record size not found\n", ext_sec->desc);
		return -EINVAL;
	}

	/* The record size needs to meet the minimum standard */
	record_size = *(__u32 *)info;
	if (record_size < ext_sec->min_rec_size ||
	    record_size & 0x03) {
		pr_debug("%s section in .BTF.ext has invalid record size %u\n",
			 ext_sec->desc, record_size);
		return -EINVAL;
	}

	sinfo = info + sizeof(__u32);
	info_left -= sizeof(__u32);

	/* If no records, return failure now so .BTF.ext won't be used. */
	if (!info_left) {
		pr_debug("%s section in .BTF.ext has no records", ext_sec->desc);
		return -EINVAL;
	}

		while (info_left) {
		unsigned int sec_hdrlen = sizeof(struct btf_ext_info_sec);
		__u64 total_record_size;
		__u32 num_records;

		if (info_left < sec_hdrlen) {
			pr_debug("%s section header is not found in .BTF.ext\n",
			     ext_sec->desc);
			return -EINVAL;
		}

		num_records = sinfo->num_info;
		if (num_records == 0) {
			pr_debug("%s section has incorrect num_records in .BTF.ext\n",
			     ext_sec->desc);
			return -EINVAL;
		}

		total_record_size = sec_hdrlen + (__u64)num_records * record_size;
		if (info_left < total_record_size) {
			pr_debug("%s section has incorrect num_records in .BTF.ext\n",
			     ext_sec->desc);
			return -EINVAL;
		}

		info_left -= total_record_size;
		sinfo = (void *)sinfo + total_record_size;
		sec_cnt++;
	}

	ext_info = ext_sec->ext_info;
	ext_info->len = ext_sec->len - sizeof(__u32);
	ext_info->rec_size = record_size;
	ext_info->info = info + sizeof(__u32);
	ext_info->sec_cnt = sec_cnt;

	return 0;
}

static int btf_ext_setup_func_info(struct btf_ext *btf_ext)
{
	struct btf_ext_sec_setup_param param = {
		.off = btf_ext->hdr->func_info_off,
		.len = btf_ext->hdr->func_info_len,
		.min_rec_size = sizeof(struct bpf_func_info_min),
		.ext_info = &btf_ext->func_info,
		.desc = "func_info"
	};

	return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_setup_line_info(struct btf_ext *btf_ext)
{
	struct btf_ext_sec_setup_param param = {
		.off = btf_ext->hdr->line_info_off,
		.len = btf_ext->hdr->line_info_len,
		.min_rec_size = sizeof(struct bpf_line_info_min),
		.ext_info = &btf_ext->line_info,
		.desc = "line_info",
	};

	return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_setup_core_relos(struct btf_ext *btf_ext)
{
	struct btf_ext_sec_setup_param param = {
		.off = btf_ext->hdr->core_relo_off,
		.len = btf_ext->hdr->core_relo_len,
		.min_rec_size = sizeof(struct bpf_core_relo),
		.ext_info = &btf_ext->core_relo_info,
		.desc = "core_relo",
	};

	return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_parse_hdr(__u8 *data, __u32 data_size)
{
	const struct btf_ext_header *hdr = (struct btf_ext_header *)data;

	if (data_size < offsetofend(struct btf_ext_header, hdr_len) ||
	    data_size < hdr->hdr_len) {
		pr_debug("BTF.ext header not found");
		return -EINVAL;
	}

	if (hdr->magic == bswap_16(BTF_MAGIC)) {
		pr_warn("BTF.ext in non-native endianness is not supported\n");
		return -ENOTSUP;
	} else if (hdr->magic != BTF_MAGIC) {
		pr_debug("Invalid BTF.ext magic:%x\n", hdr->magic);
		return -EINVAL;
	}

	if (hdr->version != BTF_VERSION) {
		pr_debug("Unsupported BTF.ext version:%u\n", hdr->version);
		return -ENOTSUP;
	}

	if (hdr->flags) {
		pr_debug("Unsupported BTF.ext flags:%x\n", hdr->flags);
		return -ENOTSUP;
	}

	if (data_size == hdr->hdr_len) {
		pr_debug("BTF.ext has no data\n");
		return -EINVAL;
	}

	return 0;
}

void btf_ext__free(struct btf_ext *btf_ext)
{
	if (IS_ERR_OR_NULL(btf_ext))
		return;
	free(btf_ext->func_info.sec_idxs);
	free(btf_ext->line_info.sec_idxs);
	free(btf_ext->core_relo_info.sec_idxs);
	free(btf_ext->data);
	free(btf_ext);
}

struct btf_ext *btf_ext__new(const __u8 *data, __u32 size)
{
	struct btf_ext *btf_ext;
	int err;

	btf_ext = calloc(1, sizeof(struct btf_ext));
	if (!btf_ext)
		return libbpf_err_ptr(-ENOMEM);

	btf_ext->data_size = size;
	btf_ext->data = malloc(size);
	if (!btf_ext->data) {
		err = -ENOMEM;
		goto done;
	}
	memcpy(btf_ext->data, data, size);

	err = btf_ext_parse_hdr(btf_ext->data, size);
	if (err)
		goto done;

	if (btf_ext->hdr->hdr_len < offsetofend(struct btf_ext_header, line_info_len)) {
		err = -EINVAL;
		goto done;
	}

	err = btf_ext_setup_func_info(btf_ext);
	if (err)
		goto done;

	err = btf_ext_setup_line_info(btf_ext);
	if (err)
		goto done;

	if (btf_ext->hdr->hdr_len < offsetofend(struct btf_ext_header, core_relo_len))
		goto done; /* skip core relos parsing */

	err = btf_ext_setup_core_relos(btf_ext);
	if (err)
		goto done;

done:
	if (err) {
		btf_ext__free(btf_ext);
		return libbpf_err_ptr(err);
	}

	return btf_ext;
}

const void *btf_ext__get_raw_data(const struct btf_ext *btf_ext, __u32 *size)
{
	*size = btf_ext->data_size;
	return btf_ext->data;
}

struct btf_dedup;

static struct btf_dedup *btf_dedup_new(struct btf *btf, const struct btf_dedup_opts *opts);
static void btf_dedup_free(struct btf_dedup *d);
static int btf_dedup_prep(struct btf_dedup *d);
static int btf_dedup_strings(struct btf_dedup *d);
static int btf_dedup_prim_types(struct btf_dedup *d);
static int btf_dedup_struct_types(struct btf_dedup *d);
static int btf_dedup_ref_types(struct btf_dedup *d);
static int btf_dedup_resolve_fwds(struct btf_dedup *d);
static int btf_dedup_compact_types(struct btf_dedup *d);
static int btf_dedup_remap_types(struct btf_dedup *d);

int btf__dedup(struct btf *btf, const struct btf_dedup_opts *opts)
{
	struct btf_dedup *d;
	int err;

	if (!OPTS_VALID(opts, btf_dedup_opts))
		return libbpf_err(-EINVAL);

	d = btf_dedup_new(btf, opts);
	if (IS_ERR(d)) {
		pr_debug("btf_dedup_new failed: %ld", PTR_ERR(d));
		return libbpf_err(-EINVAL);
	}

	if (btf_ensure_modifiable(btf)) {
		err = -ENOMEM;
		goto done;
	}

	err = btf_dedup_prep(d);
	if (err) {
		pr_debug("btf_dedup_prep failed:%d\n", err);
		goto done;
	}
	err = btf_dedup_strings(d);
	if (err < 0) {
		pr_debug("btf_dedup_strings failed:%d\n", err);
		goto done;
	}
	err = btf_dedup_prim_types(d);
	if (err < 0) {
		pr_debug("btf_dedup_prim_types failed:%d\n", err);
		goto done;
	}
	err = btf_dedup_struct_types(d);
	if (err < 0) {
		pr_debug("btf_dedup_struct_types failed:%d\n", err);
		goto done;
	}
	err = btf_dedup_resolve_fwds(d);
	if (err < 0) {
		pr_debug("btf_dedup_resolve_fwds failed:%d\n", err);
		goto done;
	}
	err = btf_dedup_ref_types(d);
	if (err < 0) {
		pr_debug("btf_dedup_ref_types failed:%d\n", err);
		goto done;
	}
	err = btf_dedup_compact_types(d);
	if (err < 0) {
		pr_debug("btf_dedup_compact_types failed:%d\n", err);
		goto done;
	}
	err = btf_dedup_remap_types(d);
	if (err < 0) {
		pr_debug("btf_dedup_remap_types failed:%d\n", err);
		goto done;
	}

done:
	btf_dedup_free(d);
	return libbpf_err(err);
}

#define BTF_UNPROCESSED_ID ((__u32)-1)
#define BTF_IN_PROGRESS_ID ((__u32)-2)

struct btf_dedup {
	/* .BTF section to be deduped in-place */
	struct btf *btf;
	struct btf_ext *btf_ext;
	struct hashmap *dedup_table;
	/* Canonical types map */
	__u32 *map;
	/* Hypothetical mapping, used during type graph equivalence checks */
	__u32 *hypot_map;
	__u32 *hypot_list;
	size_t hypot_cnt;
	size_t hypot_cap;
	bool hypot_adjust_canon;
	/* Various option modifying behavior of algorithm */
	struct btf_dedup_opts opts;
	/* temporary strings deduplication state */
	struct strset *strs_set;
};

static long hash_combine(long h, long value)
{
	return h * 31 + value;
}

#define for_each_dedup_cand(d, node, hash) \
	hashmap__for_each_key_entry(d->dedup_table, node, hash)

static int btf_dedup_table_add(struct btf_dedup *d, long hash, __u32 type_id)
{
	return hashmap__append(d->dedup_table, hash, type_id);
}

static int btf_dedup_hypot_map_add(struct btf_dedup *d,
				   __u32 from_id, __u32 to_id)
{
	if (d->hypot_cnt == d->hypot_cap) {
		__u32 *new_list;

		d->hypot_cap += max((size_t)16, d->hypot_cap / 2);
		new_list = libbpf_reallocarray(d->hypot_list, d->hypot_cap, sizeof(__u32));
		if (!new_list)
			return -ENOMEM;
		d->hypot_list = new_list;
	}
	d->hypot_list[d->hypot_cnt++] = from_id;
	d->hypot_map[from_id] = to_id;
	return 0;
}

static void btf_dedup_clear_hypot_map(struct btf_dedup *d)
{
	int i;

	for (i = 0; i < d->hypot_cnt; i++)
		d->hypot_map[d->hypot_list[i]] = BTF_UNPROCESSED_ID;
	d->hypot_cnt = 0;
	d->hypot_adjust_canon = false;
}

static void btf_dedup_free(struct btf_dedup *d)
{
	hashmap__free(d->dedup_table);
	d->dedup_table = NULL;

	free(d->map);
	d->map = NULL;

	free(d->hypot_map);
	d->hypot_map = NULL;

	free(d->hypot_list);
	d->hypot_list = NULL;

	free(d);
}

static size_t btf_dedup_identity_hash_fn(long key, void *ctx)
{
	return key;
}

static size_t btf_dedup_collision_hash_fn(long key, void *ctx)
{
	return 0;
}

static bool btf_dedup_equal_fn(long k1, long k2, void *ctx)
{
	return k1 == k2;
}

static struct btf_dedup *btf_dedup_new(struct btf *btf, const struct btf_dedup_opts *opts)
{
	struct btf_dedup *d = calloc(1, sizeof(struct btf_dedup));
	hashmap_hash_fn hash_fn = btf_dedup_identity_hash_fn;
	int i, err = 0, type_cnt;

	if (!d)
		return ERR_PTR(-ENOMEM);

	if (OPTS_GET(opts, force_collisions, false))
		hash_fn = btf_dedup_collision_hash_fn;

	d->btf = btf;
	d->btf_ext = OPTS_GET(opts, btf_ext, NULL);

	d->dedup_table = hashmap__new(hash_fn, btf_dedup_equal_fn, NULL);
	if (IS_ERR(d->dedup_table)) {
		err = PTR_ERR(d->dedup_table);
		d->dedup_table = NULL;
		goto done;
	}

	type_cnt = btf__type_cnt(btf);
	d->map = malloc(sizeof(__u32) * type_cnt);
	if (!d->map) {
		err = -ENOMEM;
		goto done;
	}
	/* special BTF "void" type is made canonical immediately */
	d->map[0] = 0;
	for (i = 1; i < type_cnt; i++) {
		struct btf_type *t = btf_type_by_id(d->btf, i);

		/* VAR and DATASEC are never deduped and are self-canonical */
		if (btf_is_var(t) || btf_is_datasec(t))
			d->map[i] = i;
		else
			d->map[i] = BTF_UNPROCESSED_ID;
	}

	d->hypot_map = malloc(sizeof(__u32) * type_cnt);
	if (!d->hypot_map) {
		err = -ENOMEM;
		goto done;
	}
	for (i = 0; i < type_cnt; i++)
		d->hypot_map[i] = BTF_UNPROCESSED_ID;

done:
	if (err) {
		btf_dedup_free(d);
		return ERR_PTR(err);
	}

	return d;
}

static int btf_for_each_str_off(struct btf_dedup *d, str_off_visit_fn fn, void *ctx)
{
	int i, r;

	for (i = 0; i < d->btf->nr_types; i++) {
		struct btf_type *t = btf_type_by_id(d->btf, d->btf->start_id + i);

		r = btf_type_visit_str_offs(t, fn, ctx);
		if (r)
			return r;
	}

	if (!d->btf_ext)
		return 0;

	r = btf_ext_visit_str_offs(d->btf_ext, fn, ctx);
	if (r)
		return r;

	return 0;
}

static int strs_dedup_remap_str_off(__u32 *str_off_ptr, void *ctx)
{
	struct btf_dedup *d = ctx;
	__u32 str_off = *str_off_ptr;
	const char *s;
	int off, err;

	/* don't touch empty string or string in main BTF */
	if (str_off == 0 || str_off < d->btf->start_str_off)
		return 0;

	s = btf__str_by_offset(d->btf, str_off);
	if (d->btf->base_btf) {
		err = btf__find_str(d->btf->base_btf, s);
		if (err >= 0) {
			*str_off_ptr = err;
			return 0;
		}
		if (err != -ENOENT)
			return err;
	}

	off = strset__add_str(d->strs_set, s);
	if (off < 0)
		return off;

	*str_off_ptr = d->btf->start_str_off + off;
	return 0;
}

static int btf_dedup_strings(struct btf_dedup *d)
{
	int err;

	if (d->btf->strs_deduped)
		return 0;

	d->strs_set = strset__new(BTF_MAX_STR_OFFSET, NULL, 0);
	if (IS_ERR(d->strs_set)) {
		err = PTR_ERR(d->strs_set);
		goto err_out;
	}

	if (!d->btf->base_btf) {
		/* insert empty string; we won't be looking it up during strings
		 * dedup, but it's good to have it for generic BTF string lookups
		 */
		err = strset__add_str(d->strs_set, "");
		if (err < 0)
			goto err_out;
	}

	/* remap string offsets */
	err = btf_for_each_str_off(d, strs_dedup_remap_str_off, d);
	if (err)
		goto err_out;

	/* replace BTF string data and hash with deduped ones */
	strset__free(d->btf->strs_set);
	d->btf->hdr->str_len = strset__data_size(d->strs_set);
	d->btf->strs_set = d->strs_set;
	d->strs_set = NULL;
	d->btf->strs_deduped = true;
	return 0;

err_out:
	strset__free(d->strs_set);
	d->strs_set = NULL;

	return err;
}

static long btf_hash_common(struct btf_type *t)
{
	long h;

	h = hash_combine(0, t->name_off);
	h = hash_combine(h, t->info);
	h = hash_combine(h, t->size);
	return h;
}

static bool btf_equal_common(struct btf_type *t1, struct btf_type *t2)
{
	return t1->name_off == t2->name_off &&
	       t1->info == t2->info &&
	       t1->size == t2->size;
}

/* Calculate type signature hash of INT or TAG. */
static long btf_hash_int_decl_tag(struct btf_type *t)
{
	__u32 info = *(__u32 *)(t + 1);
	long h;

	h = btf_hash_common(t);
	h = hash_combine(h, info);
	return h;
}

/* Check structural equality of two INTs or TAGs. */
static bool btf_equal_int_tag(struct btf_type *t1, struct btf_type *t2)
{
	__u32 info1, info2;

	if (!btf_equal_common(t1, t2))
		return false;
	info1 = *(__u32 *)(t1 + 1);
	info2 = *(__u32 *)(t2 + 1);
	return info1 == info2;
}

/* Calculate type signature hash of ENUM/ENUM64. */
static long btf_hash_enum(struct btf_type *t)
{
	long h;

	/* don't hash vlen, enum members and size to support enum fwd resolving */
	h = hash_combine(0, t->name_off);
	return h;
}

static bool btf_equal_enum_members(struct btf_type *t1, struct btf_type *t2)
{
	const struct btf_enum *m1, *m2;
	__u16 vlen;
	int i;

	vlen = btf_vlen(t1);
	m1 = btf_enum(t1);
	m2 = btf_enum(t2);
	for (i = 0; i < vlen; i++) {
		if (m1->name_off != m2->name_off || m1->val != m2->val)
			return false;
		m1++;
		m2++;
	}
	return true;
}

static bool btf_equal_enum64_members(struct btf_type *t1, struct btf_type *t2)
{
	const struct btf_enum64 *m1, *m2;
	__u16 vlen;
	int i;

	vlen = btf_vlen(t1);
	m1 = btf_enum64(t1);
	m2 = btf_enum64(t2);
	for (i = 0; i < vlen; i++) {
		if (m1->name_off != m2->name_off || m1->val_lo32 != m2->val_lo32 ||
		    m1->val_hi32 != m2->val_hi32)
			return false;
		m1++;
		m2++;
	}
	return true;
}

/* Check structural equality of two ENUMs or ENUM64s. */
static bool btf_equal_enum(struct btf_type *t1, struct btf_type *t2)
{
	if (!btf_equal_common(t1, t2))
		return false;

	/* t1 & t2 kinds are identical because of btf_equal_common */
	if (btf_kind(t1) == BTF_KIND_ENUM)
		return btf_equal_enum_members(t1, t2);
	else
		return btf_equal_enum64_members(t1, t2);
}

static inline bool btf_is_enum_fwd(struct btf_type *t)
{
	return btf_is_any_enum(t) && btf_vlen(t) == 0;
}

static bool btf_compat_enum(struct btf_type *t1, struct btf_type *t2)
{
	if (!btf_is_enum_fwd(t1) && !btf_is_enum_fwd(t2))
		return btf_equal_enum(t1, t2);
	return t1->name_off == t2->name_off &&
	       btf_is_any_enum(t1) && btf_is_any_enum(t2);
}

static long btf_hash_struct(struct btf_type *t)
{
	const struct btf_member *member = btf_members(t);
	__u32 vlen = btf_vlen(t);
	long h = btf_hash_common(t);
	int i;

	for (i = 0; i < vlen; i++) {
		h = hash_combine(h, member->name_off);
		h = hash_combine(h, member->offset);
		/* no hashing of referenced type ID, it can be unresolved yet */
		member++;
	}
	return h;
}

static bool btf_shallow_equal_struct(struct btf_type *t1, struct btf_type *t2)
{
	const struct btf_member *m1, *m2;
	__u16 vlen;
	int i;

	if (!btf_equal_common(t1, t2))
		return false;

	vlen = btf_vlen(t1);
	m1 = btf_members(t1);
	m2 = btf_members(t2);
	for (i = 0; i < vlen; i++) {
		if (m1->name_off != m2->name_off || m1->offset != m2->offset)
			return false;
		m1++;
		m2++;
	}
	return true;
}

static long btf_hash_array(struct btf_type *t)
{
	const struct btf_array *info = btf_array(t);
	long h = btf_hash_common(t);

	h = hash_combine(h, info->type);
	h = hash_combine(h, info->index_type);
	h = hash_combine(h, info->nelems);
	return h;
}

static bool btf_equal_array(struct btf_type *t1, struct btf_type *t2)
{
	const struct btf_array *info1, *info2;

	if (!btf_equal_common(t1, t2))
		return false;

	info1 = btf_array(t1);
	info2 = btf_array(t2);
	return info1->type == info2->type &&
	       info1->index_type == info2->index_type &&
	       info1->nelems == info2->nelems;
}

static bool btf_compat_array(struct btf_type *t1, struct btf_type *t2)
{
	if (!btf_equal_common(t1, t2))
		return false;

	return btf_array(t1)->nelems == btf_array(t2)->nelems;
}

static long btf_hash_fnproto(struct btf_type *t)
{
	const struct btf_param *member = btf_params(t);
	__u16 vlen = btf_vlen(t);
	long h = btf_hash_common(t);
	int i;

	for (i = 0; i < vlen; i++) {
		h = hash_combine(h, member->name_off);
		h = hash_combine(h, member->type);
		member++;
	}
	return h;
}

static bool btf_equal_fnproto(struct btf_type *t1, struct btf_type *t2)
{
	const struct btf_param *m1, *m2;
	__u16 vlen;
	int i;

	if (!btf_equal_common(t1, t2))
		return false;

	vlen = btf_vlen(t1);
	m1 = btf_params(t1);
	m2 = btf_params(t2);
	for (i = 0; i < vlen; i++) {
		if (m1->name_off != m2->name_off || m1->type != m2->type)
			return false;
		m1++;
		m2++;
	}
	return true;
}

static bool btf_compat_fnproto(struct btf_type *t1, struct btf_type *t2)
{
	const struct btf_param *m1, *m2;
	__u16 vlen;
	int i;

	/* skip return type ID */
	if (t1->name_off != t2->name_off || t1->info != t2->info)
		return false;

	vlen = btf_vlen(t1);
	m1 = btf_params(t1);
	m2 = btf_params(t2);
	for (i = 0; i < vlen; i++) {
		if (m1->name_off != m2->name_off)
			return false;
		m1++;
		m2++;
	}
	return true;
}
