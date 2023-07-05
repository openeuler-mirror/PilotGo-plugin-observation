// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#include "compat.h"
#include "trace_helpers.h"
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>

#define PERF_BUFFER_PAGES	64

struct bpf_buffer {
	struct bpf_map *events;
	void *inner;
	bpf_buffer_sample_fn fn;
	void *ctx;
	int type;
};
