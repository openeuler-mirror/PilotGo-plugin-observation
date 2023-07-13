// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "tcpconnlat.h"
#include "tcpconnlat.skel.h"
#include "trace_helpers.h"
#include "compat.h"

#include <arpa/inet.h>

static volatile sig_atomic_t exiting;

static struct env {
	__u64 min_us;
	pid_t pid;
	bool timestamp;
	bool lport;
	bool verbose;
} env;

const char *argp_program_version = "tcpconnlat 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"\nTrace TCP connects and show connection latency.\n"
"\n"
"USAGE: tcpconnlat [--help] [-t] [-p PID] [-L]\n"
"\n"
"EXAMPLES:\n"
"    tcpconnlat              # summarize on-CPU time as a histogram\n"
"    tcpconnlat 1            # trace connection latency slower than 1 ms\n"
"    tcpconnlat 0.1          # trace connection latency slower than 100 us\n"
"    tcpconnlat -t           # 1s summaries, milliseconds, and timestamps\n"
"    tcpconnlat -p 185       # trace PID 185 only\n"
"    tcpconnlat -L           # include LPORT while printing outputs\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "lport", 'L', NULL, 0, "Include LPORT on output" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};
