// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include "llcstat.h"
#include "llcstat.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

struct env {
	int sample_period;
	time_t duration;
	bool verbose;
	bool per_thread;
} env = {
	.sample_period = 100,
	.duration = 10,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "llcstat 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize cache references and misses by PID.\n"
"\n"
"USAGE: llcstat [--help] [-c SAMPLE_PERIOD] [duration]\n";

static const struct argp_option opts[] = {
	{ "sample_period", 'c', "SAMPLE_PERIOD", 0, "Sample one in this many "
	  "number of cache reference / miss events" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "tid", 't', NULL, 0,
	  "Summarize cacge references and misses by PID/TTID" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

