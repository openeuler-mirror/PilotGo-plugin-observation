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

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case OPT_PERF_MAX_STACK_DEPTH:
		env.perf_max_stack_depth = argp_parse_long(key, arg, state);
		break;
	case OPT_STACK_STORAGE_SIZE:
		env.stack_storage_size = argp_parse_long(key, arg, state);
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'm':
		env.duration_ns = argp_parse_long(key, arg, state) * 1000000;
		break;
	case 'u':
		env.duration_ns = argp_parse_long(key, arg, state) * 1000;
		break;
	case 'U':
		env.need_user_stack = true;
		break;
	case 'K':
		env.need_kernel_stack = true;
		break;
	case 'a':
		env.need_grab_args = true;
		env.arguments = argp_parse_long(key, arg, state);
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'T':
		env.time = true;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num >= MAX_FUNCTIONS) {
			warning("Too many function, limit to %d\n", MAX_FUNCTIONS);
			argp_usage(state);
		}
		env.functions[state->arg_num] = arg;
		break;
	case ARGP_KEY_END:
		if (env.duration_ns >= 1000000)
			env.ms = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}
