// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "funclatency.h"
#include "funclatency.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"

static struct env {
	int units;
	pid_t pid;
	unsigned int duration;
	unsigned int interval;
	unsigned int iterations;
	bool timestamp;
	char *funcname;
	bool verbose;
	bool kprobes;
	char *cgroupspath;
	bool cg;
	bool is_kernel_func;
} env = {
	.interval = 99999999,
	.iterations = 99999999,
};

const char *argp_program_version = "funclatency 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char args_doc[] = "FUNCTION";
const char argp_program_doc[] =
"Time functions and print latency as a histogram\n"
"\n"
"Usage: funclatency [-h] [-m|-u] [-p PID] [-d DURATION] [ -i INTERVAL ] [-c CG]\n"
"                   [-T] FUNCTION\n"
"       Choices for FUNCTION: FUNCTION         (kprobe)\n"
"                             LIBRARY:FUNCTION (uprobe a library in -p PID)\n"
"                             :FUNCTION        (uprobe the binary of -p PID)\n"
"                             PROGRAM:FUNCTION (uprobe the binary PROGRAM)\n"
"\v"
"Examples:\n"
"  ./funclatency do_sys_open         # time the do_sys_open() kernel function\n"
"  ./funclatency -m do_nanosleep     # time do_nanosleep(), in milliseconds\n"
"  ./funclatency -c CG               # Trace process under cgroupsPath CG\n"
"  ./funclatency -u vfs_read         # time vfs_read(), in microseconds\n"
"  ./funclatency -p 181 vfs_read     # time process 181 only\n"
"  ./funclatency -p 181 c:read       # time the read() C library function\n"
"  ./funclatency -p 181 :foo         # time foo() from pid 181's userspace\n"
"  ./funclatency -i 2 -d 10 vfs_read # output every 2 seconds, for 10s\n"
"  ./funclatency -mTi 5 vfs_read     # output every 5 seconds, with timestamps\n";

static const struct argp_option opts[] = {
	{ "milliseconds", 'm', NULL, 0, "Output in milliseconds" },
	{ "microseconds", 'u', NULL, 0, "Output in microseconds" },
	{ 0, 0, 0, 0, "" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ 0, 0, 0, 0, "" },
	{ "interval", 'i', "INTERVAL", 0, "Summary interval in seconds" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "duration", 'd', "DURATION", 0, "Duration to trace" },
	{ "timestamp", 'T', NULL, 0, "Print timestamp" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "kprobes", 'k', NULL, 0, "Use kprobes instead of fentry" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};
