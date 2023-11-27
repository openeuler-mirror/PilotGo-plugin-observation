// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2018 Facebook */

#include <string.h>
#include <stdlib.h>
#include <linux/err.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "libbpf_internal.h"

struct bpf_prog_linfo {
	void *raw_linfo;
	void *raw_jited_linfo;
	__u32 *nr_jited_linfo_per_func;
	__u32 *jited_linfo_func_idx;
	__u32 nr_linfo;
	__u32 nr_jited_func;
	__u32 rec_size;
	__u32 jited_rec_size;
};
