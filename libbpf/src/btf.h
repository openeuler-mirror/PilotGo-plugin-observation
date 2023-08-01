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
