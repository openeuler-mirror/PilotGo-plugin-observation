// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Based on funcslower.py - Copyright 2017, Sasha Goldshtein

#include "commons.h"
#include "funcslower.h"
#include "funcslower.skel.h"
#include "compat.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"
#include <sys/param.h>

#define MAX_FUNCTIONS	10

static volatile sig_atomic_t exiting = 0;
static struct ksyms *ksyms;
static struct syms_cache *syms_cache;

static struct env {
	bool need_grab_args;
	bool need_kernel_stack;
	bool need_user_stack;
	bool pid;
	__u64 duration_ns;
	bool ms;
	bool timestamp;
	bool time;
	bool verbose;
	int arguments;
	const char *functions[MAX_FUNCTIONS];
	int perf_max_stack_depth;
	int stack_storage_size;
} env = {
	.duration_ns = 1000000,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
};
