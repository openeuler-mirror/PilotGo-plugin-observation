// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "exitsnoop.h"
#include "exitsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;
static volatile bool verbose = false;

struct argument {
	char *cgroupspath;
	bool cg;
	bool emit_timestamp;
	pid_t target_pid;
	bool trace_failed_only;
	bool trace_by_process;
};

const char *argp_program_version = "exitsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace process termination.\n"
"\n"
"USAGE: exitsnoop [-h] [-t] [-x] [-p PID] [-T] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    exitsnoop             # trace process exit events\n"
"    exitsnoop -t          # include timestamps\n"
"    exitsnoop -x          # trace error exits only\n"
"    exitsnoop -p 1216     # only trace PID 1216\n"
"    exitsnoop -T          # trace by thread\n"
"    exitsnoop -c CG       # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "failed", 'x', NULL, 0, "Trace error exits only" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "threadid", 'T', NULL, 0, "Trace by thread" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct argument *argument = state->input;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		verbose = true;
		break;
	case 't':
		argument->emit_timestamp = true;
		break;
	case 'x':
		argument->trace_failed_only = true;
		break;
	case 'T':
		argument->trace_by_process = true;
		break;
	case 'c':
		argument->cgroupspath = arg;
		argument->cg = true;
		break;
	case 'p':
		argument->target_pid = argp_parse_pid(key, arg, state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
