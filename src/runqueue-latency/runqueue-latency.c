// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "runqueue-latency.h"
#include "runqueue-latency.skel.h"
#include "trace_helpers.h"

struct env {
	time_t interval;
	pid_t pid;
	int times;
	bool milliseconds;
	bool per_process;
	bool per_thread;
	bool per_pidns;
	bool timestamp;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "runqueue-latency 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize run queue (scheduler) latency as a histogram.\n"
"\n"
"USAGE: runqlat [--help] [-T] [-m] [--pidnss] [-L] [-P] [-p PID] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    runqlat         # summarize run queue latency as a histogram\n"
"    runqlat 1 10    # print 1 second summaries, 10 times\n"
"    runqlat -mT 1   # 1s summaries, milliseconds, and timestamps\n"
"    runqlat -P      # show each PID separately\n"
"    runqlat -p 185  # trace PID 185 only\n"
"    runqlat -c CG   # Trace process under cgroupsPath CG\n";

#define OPT_PIDNSS	1 /* --pidnss */