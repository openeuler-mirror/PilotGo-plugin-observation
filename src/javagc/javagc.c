// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "javagc.skel.h"
#include "javagc.h"
#include "compat.h"

#define BINARY_PATH_SIZE	256

static volatile sig_atomic_t exiting;

static struct env {
	pid_t pid;
	int time;
	bool verbose;
} env = {
	.pid = -1,
	.time = 1000,
};

const char *argp_program_version = "javagc 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Monitor javagc time cost.\n"
"\n"
"USAGE: javagc [--help] [-t GC time] PID\n"
"\n"
"EXAMPLES:\n"
"javagc 185         # trace PID 185\n"
"javagc 185 -t 100  # trace PID 185 java gc time beyond 100us\n";

static const struct argp_option opts[] = {
	{ "time", 't', "TIME", 0, "Java gc time" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};