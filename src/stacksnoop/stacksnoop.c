// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on stacksnoop.py - Brendan Gregg

#include "commons.h"
#include "stacksnoop.h"
#include "stacksnoop.skel.h"
#include "compat.h"
#include "trace_helpers.h"

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "show extra columns" },
	{ "pid", 'p', "PID", 0, "Trace PID only" },
	{ "offset", 's', NULL, 0, "Also show symbol offsets" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH, "PERF_MAX_STACK_DEPTH",
	  0, "The limit for both kernel and user stack traces (default 127)" },
	{ "stack-map-max-entries", OPT_STACK_MAP_MAX_ENTRIES, "STACK_MAP_MAX_ENTRIES",
	  0, "The number of unique stack traces that can be stored and displayed (default 1024)" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 's':
		env.print_offset = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		env.perf_max_stack_depth = argp_parse_long(key, arg, state);
		break;
	case OPT_STACK_MAP_MAX_ENTRIES:
		env.stack_map_max_entries = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num != 0) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}

		env.function = strdup(arg);
		break;
	case ARGP_KEY_END:
		if (!env.function)
			argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct stacksnoop_bpf *obj;
	int err;
	bool support_fentry;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
}
