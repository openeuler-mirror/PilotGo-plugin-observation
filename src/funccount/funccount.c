// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// WARNING: This program can only be run on kernels that support kprobe multi.
// If it is not supported, it will exit directly. Currently, on X86, at least
// the kernel must be greater than v5.18-rc1 and Config must be enable
// CONFIG_FPROBE, currently not supported on other platforms.
//
// Baseon funccount.py - 2015 Brendan Gregg

#include "commons.h"
#include "funccount.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool verbose;
	int interval;
	int interations;
	pid_t pid;
	int duration;
	bool timestamp;
	const char *functions;
} env = {
	.interval = 99999999,
	.interations = 9999999,
};

const char *argp_program_version = "funccount 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Count functions, tracepoints.\n"
"\n"
"USAGE: funccount [-v] [-i INTERVAL] [-p PID] [-d DURATION] [-T] funcname\n"
"\n"
" funccount   func          -- probe a kernel function\n"
"             lib:func      -- probe a user-space function in the library 'lib\n"
"             /path:func    -- probe a user-space function in binary '/path'\n"
"             p::func       -- same thing as 'func'\n"
"             p:lib:func    -- same thing as 'lib:func'\n"
"             t:cat:event   -- probe a kernel tracepoint\n"
"             u:lib:probe   -- probe a USDT tracepoint\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "interval", 'i', "INTERVAL", 0, "Output interval, in seconds" },
	{ "pid", 'p', "PID", 0, "Trace process id PID only" },
	{ "duration", 'd', "DURATION", 0, "total duration of trace, seconds" },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};
