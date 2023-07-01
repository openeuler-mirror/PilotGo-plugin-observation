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
