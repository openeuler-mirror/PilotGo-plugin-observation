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
