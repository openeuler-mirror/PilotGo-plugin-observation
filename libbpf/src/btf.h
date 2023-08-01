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
