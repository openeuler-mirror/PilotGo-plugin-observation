// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "runqslower.h"
#include "runqslower.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting = 0;

struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	bool previous;
	bool verbose;
} env = {
	.min_us = 1000,
};

const char *argp_program_version = "runqslower 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace high run queue latency.\n"
"\n"
"USAGE: runqslower [--help] [-p PID] [-t tid] [-P] [min_us]\n"
"\n"
"EXAMPLES:\n"
"  runqslower         # trace latency higher than 10000 us (default)\n"
"  runqslower 1000    # trace latency higher than 1000 us\n"
"  runqslower -p 123  # trace pid 123 only\n"
"  runqslower -t 123  # trace tid 123 (use for threads only)\n"
"  runqslower -P      # also show previous task name and TID\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "tid", 't', "TID", 0, "Thread ID to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "previous", 'P', NULL, 0, "also show previous task name and TID" },
	{ "NULL", 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};