// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include <linux/perf_event.h>
#include "runqlen.h"
#include "runqlen.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include <sys/syscall.h>

struct env {
	bool per_cpu;
	bool runqocc;
	bool timestamp;
	bool host;
	time_t interval;
	int freq;
	int times;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
	.freq = 99,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "runqlen 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize scheduler run queue length as a histogram.\n"
"\n"
"USAGE: runqlen [--help] [-C] [-O] [-T] [-f FREQUENCY] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    runqlen         # summarize run queue length as a histogram\n"
"    runqlen 1 10    # print 1 second summaries, 10 times\n"
"    runqlen -T 1    # 1s summaries and timestamps\n"
"    runqlen -O      # report run queue occupancy\n"
"    runqlen -C      # show each CPU separately\n"
"    runqlen -H      # show nr_running from host's rq instead of cfs_rq\n"
"    runqlen -f 199  # sample at 199HZ\n";


static const struct argp_option opts[] = {
	{ "cpus", 'C', NULL, 0, "Print output for each cpu separately" },
	{ "frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency" },
	{ "runqocc", 'O', NULL, 0, "Report run queue occupancy" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "verbose", 'v', NULL, 0, "Verbose output debug" },
	{ "host", 'H', NULL, 0, "Report nr_running from host's rq" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'C':
		env.per_cpu = true;
		break;
	case 'O':
		env.runqocc = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'H':
		env.host = true;
		break;
	case 'f':
		errno = 0;
		env.freq = strtol(arg, NULL, 10);
		if (errno) {
			warning("Invalid freq (in hz): %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				warning("Invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				warning("Invalid times\n");
				argp_usage(state);
			}
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