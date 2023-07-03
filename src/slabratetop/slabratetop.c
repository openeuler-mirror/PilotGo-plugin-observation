// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "slabratetop.h"
#include "slabratetop.skel.h"
#include "trace_helpers.h"

#include <sys/param.h>

#define OUTPUT_ROWS_LIMIT	10240

enum SORT_BY {
	SORT_BY_CACHE_NAME,
	SORT_BY_CACHE_COUNT,
	SORT_BY_CACHE_SIZE,
};

static volatile sig_atomic_t exiting;

static pid_t target_pid = 0;
static bool clear_screen = true;
static int output_rows = 20;
static int sort_by = SORT_BY_CACHE_SIZE;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "slabratetop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace slab kmem cache alloc by process.\n"
"\n"
"USAGE: slabratetop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    slabratetop            # slab rate top, refresh every 1s\n"
"    slabratetop -p 181     # only trace PID 181\n"
"    slabratetop -s count   # sort columns by count\n"
"    slabratetop -r 100     # print 100 rows\n"
"    slabratetop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "sort", 's', "SORT", 0, "Sort columns, default size [name, count, size]" },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'p':
		target_pid = argp_parse_pid(key, arg, state);
		break;
	case 'C':
		clear_screen = false;
		break;
	case 's':
		if (!strcmp(arg, "name")) {
			sort_by = SORT_BY_CACHE_NAME;
		} else if (!strcmp(arg, "count")) {
			sort_by = SORT_BY_CACHE_COUNT;
		} else if (!strcmp(arg, "size")) {
			sort_by = SORT_BY_CACHE_SIZE;
		} else {
			warning("Invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		output_rows = MIN(OUTPUT_ROWS_LIMIT, argp_parse_long(key, arg, state));
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			interval = argp_parse_long(key, arg, state);
		} else if (pos_args == 1) {
			count = argp_parse_long(key, arg, state);
		} else {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
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
	struct slabratetop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
		
	return err != 0;
}
