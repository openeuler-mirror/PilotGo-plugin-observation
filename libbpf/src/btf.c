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
