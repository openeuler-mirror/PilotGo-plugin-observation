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
