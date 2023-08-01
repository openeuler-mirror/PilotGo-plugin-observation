/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2018 Facebook */
/*! \file */

#ifndef __LIBBPF_BTF_H
#define __LIBBPF_BTF_H

#include <stdarg.h>
#include <stdbool.h>
#include <linux/btf.h>
#include <linux/types.h>

#include "libbpf_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BTF_ELF_SEC ".BTF"
#define BTF_EXT_ELF_SEC ".BTF.ext"
#define MAPS_ELF_SEC ".maps"

struct btf;
struct btf_ext;
struct btf_type;

struct bpf_object;

enum btf_endianness {
	BTF_LITTLE_ENDIAN = 0,
	BTF_BIG_ENDIAN = 1,
};

LIBBPF_API void btf__free(struct btf *btf);
LIBBPF_API struct btf *btf__new(const void *data, __u32 size);
LIBBPF_API struct btf *btf__new_split(const void *data, __u32 size, struct btf *base_btf);
LIBBPF_API struct btf *btf__new_empty(void);
LIBBPF_API struct btf *btf__new_empty_split(struct btf *base_btf);
LIBBPF_API struct btf *btf__parse(const char *path, struct btf_ext **btf_ext);
LIBBPF_API struct btf *btf__parse_split(const char *path, struct btf *base_btf);
LIBBPF_API struct btf *btf__parse_elf(const char *path, struct btf_ext **btf_ext);
LIBBPF_API struct btf *btf__parse_elf_split(const char *path, struct btf *base_btf);
LIBBPF_API struct btf *btf__parse_raw(const char *path);
LIBBPF_API struct btf *btf__parse_raw_split(const char *path, struct btf *base_btf);
LIBBPF_API struct btf *btf__load_vmlinux_btf(void);
LIBBPF_API struct btf *btf__load_module_btf(const char *module_name, struct btf *vmlinux_btf);
LIBBPF_API struct btf *btf__load_from_kernel_by_id(__u32 id);
LIBBPF_API struct btf *btf__load_from_kernel_by_id_split(__u32 id, struct btf *base_btf);
LIBBPF_API int btf__load_into_kernel(struct btf *btf);
LIBBPF_API __s32 btf__find_by_name(const struct btf *btf,
				   const char *type_name);
LIBBPF_API __s32 btf__find_by_name_kind(const struct btf *btf,
					const char *type_name, __u32 kind);
LIBBPF_API __u32 btf__type_cnt(const struct btf *btf);
LIBBPF_API const struct btf *btf__base_btf(const struct btf *btf);
LIBBPF_API const struct btf_type *btf__type_by_id(const struct btf *btf,
						  __u32 id);
LIBBPF_API size_t btf__pointer_size(const struct btf *btf);
LIBBPF_API int btf__set_pointer_size(struct btf *btf, size_t ptr_sz);
LIBBPF_API enum btf_endianness btf__endianness(const struct btf *btf);
LIBBPF_API int btf__set_endianness(struct btf *btf, enum btf_endianness endian);
LIBBPF_API __s64 btf__resolve_size(const struct btf *btf, __u32 type_id);
LIBBPF_API int btf__resolve_type(const struct btf *btf, __u32 type_id);
LIBBPF_API int btf__align_of(const struct btf *btf, __u32 id);
LIBBPF_API int btf__fd(const struct btf *btf);
LIBBPF_API void btf__set_fd(struct btf *btf, int fd);
LIBBPF_API const void *btf__raw_data(const struct btf *btf, __u32 *size);
LIBBPF_API const char *btf__name_by_offset(const struct btf *btf, __u32 offset);
LIBBPF_API const char *btf__str_by_offset(const struct btf *btf, __u32 offset);
LIBBPF_API struct btf_ext *btf_ext__new(const __u8 *data, __u32 size);
LIBBPF_API void btf_ext__free(struct btf_ext *btf_ext);
LIBBPF_API const void *btf_ext__raw_data(const struct btf_ext *btf_ext, __u32 *size);

LIBBPF_API int btf__find_str(struct btf *btf, const char *s);
LIBBPF_API int btf__add_str(struct btf *btf, const char *s);
LIBBPF_API int btf__add_type(struct btf *btf, const struct btf *src_btf,
			     const struct btf_type *src_type);
LIBBPF_API int btf__add_btf(struct btf *btf, const struct btf *src_btf);

LIBBPF_API int btf__add_int(struct btf *btf, const char *name, size_t byte_sz, int encoding);
LIBBPF_API int btf__add_float(struct btf *btf, const char *name, size_t byte_sz);
LIBBPF_API int btf__add_ptr(struct btf *btf, int ref_type_id);
LIBBPF_API int btf__add_array(struct btf *btf,
			      int index_type_id, int elem_type_id, __u32 nr_elems);
/* struct/union construction APIs */
LIBBPF_API int btf__add_struct(struct btf *btf, const char *name, __u32 sz);
LIBBPF_API int btf__add_union(struct btf *btf, const char *name, __u32 sz);
LIBBPF_API int btf__add_field(struct btf *btf, const char *name, int field_type_id,
			      __u32 bit_offset, __u32 bit_size);

/* enum construction APIs */
LIBBPF_API int btf__add_enum(struct btf *btf, const char *name, __u32 bytes_sz);
LIBBPF_API int btf__add_enum_value(struct btf *btf, const char *name, __s64 value);
LIBBPF_API int btf__add_enum64(struct btf *btf, const char *name, __u32 bytes_sz, bool is_signed);
LIBBPF_API int btf__add_enum64_value(struct btf *btf, const char *name, __u64 value);

enum btf_fwd_kind {
	BTF_FWD_STRUCT = 0,
	BTF_FWD_UNION = 1,
	BTF_FWD_ENUM = 2,
};

LIBBPF_API int btf__add_fwd(struct btf *btf, const char *name, enum btf_fwd_kind fwd_kind);
LIBBPF_API int btf__add_typedef(struct btf *btf, const char *name, int ref_type_id);
LIBBPF_API int btf__add_volatile(struct btf *btf, int ref_type_id);
LIBBPF_API int btf__add_const(struct btf *btf, int ref_type_id);
LIBBPF_API int btf__add_restrict(struct btf *btf, int ref_type_id);
LIBBPF_API int btf__add_type_tag(struct btf *btf, const char *value, int ref_type_id);

/* func and func_proto construction APIs */
LIBBPF_API int btf__add_func(struct btf *btf, const char *name,
			     enum btf_func_linkage linkage, int proto_type_id);
LIBBPF_API int btf__add_func_proto(struct btf *btf, int ret_type_id);
LIBBPF_API int btf__add_func_param(struct btf *btf, const char *name, int type_id);

/* var & datasec construction APIs */
LIBBPF_API int btf__add_var(struct btf *btf, const char *name, int linkage, int type_id);
LIBBPF_API int btf__add_datasec(struct btf *btf, const char *name, __u32 byte_sz);
LIBBPF_API int btf__add_datasec_var_info(struct btf *btf, int var_type_id,
					 __u32 offset, __u32 byte_sz);

/* tag construction API */
LIBBPF_API int btf__add_decl_tag(struct btf *btf, const char *value, int ref_type_id,
			    int component_idx);

struct btf_dedup_opts {
	size_t sz;
	/* optional .BTF.ext info to dedup along the main BTF info */
	struct btf_ext *btf_ext;
	/* force hash collisions (used for testing) */
	bool force_collisions;
	size_t :0;
};

#define btf_dedup_opts__last_field force_collisions

LIBBPF_API int btf__dedup(struct btf *btf, const struct btf_dedup_opts *opts);

struct btf_dump;

struct btf_dump_opts {
	size_t sz;
};