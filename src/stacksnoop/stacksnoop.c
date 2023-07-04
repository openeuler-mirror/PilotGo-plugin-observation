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

static volatile sig_atomic_t exiting;

static struct env {
	bool print_offset;
	bool verbose;
	pid_t pid;
	const char *function;
	int perf_max_stack_depth;
	int stack_map_max_entries;
} env = {
	.perf_max_stack_depth = 127,
	.stack_map_max_entries = 1024,
};

struct ksyms *ksyms;
static __u64 *stacks;

const char *argp_program_version = "stacksnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace a kernel function and print all kernel stack traces.\n"
"\n"
"USAGE: stacksnoop [-h] [-v] [-s] [-p PID] function\n";

#define OPT_PERF_MAX_STACK_DEPTH	1	/* --perf-max-stack-depth */
#define OPT_STACK_MAP_MAX_ENTRIES	2	/* --stack-map-max-entries */

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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
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
	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

        obj = stacksnoop_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	/* alloc space for storing a stack trace */
	stacks = calloc(env.perf_max_stack_depth, sizeof(*stacks));
	if (!stacks) {
		warning("Failed to allocate stack array\n");
		err = -ENOMEM;
		goto cleanup;
	}
cleanup:
	bpf_buffer__free(buf);
	stacksnoop_bpf__destroy(obj);
	ksyms__free(ksyms);
	free(stacks);

	return err != 0;
}
