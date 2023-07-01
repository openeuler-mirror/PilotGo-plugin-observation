// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "drsnoop.h"
#include "drsnoop.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;
static volatile bool verbose = false;

struct argument {
	pid_t pid;
	pid_t tid;
	time_t duration;
	bool extended;
};

const char *argp_program_version = "drsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace direct reclaim latency.\n"
"\n"
"USAGE: drsnoop [--help] [-p PID] [-t TID] [-d DURATION] [-e]\n"
"\n"
"EXAMPLES:\n"
"    drsnoop         # trace all direct reclaim events\n"
"    drsnoop -p 123  # trace pid 123\n"
"    drsnoop -t 123  # trace tid 123 (use for threads only)\n"
"    drsnoop -d 10   # trace for 10 seconds only\n"
"    drsnoop -e      # trace all direct reclaim events with extended faileds\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Total duration of trace in seconds" },
	{ "extended", 'e', NULL, 0, "Extended fields output" },
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "tid", 't', "TID", 0, "Thread TID to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static int pagesize;

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
	case 'd':
		errno = 0;
		argument->duration = strtol(arg, NULL, 10);
		if (errno || argument->duration <= 0) {
			warning("Invalid Duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'e':
		argument->extended = true;
		break;
	case 'p':
		argument->pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		errno = 0;
		argument->tid = strtol(arg, NULL, 10);
		if (errno || argument->tid <= 0) {
			warning("Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
