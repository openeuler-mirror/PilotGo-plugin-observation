// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "setuids.h"
#include "setuids.skel.h"
#include "compat.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool verbose;
	bool timestamp;
} env;

const char *argp_program_version = "setuids 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace the setuid syscalls: privilege escalation.\n"
"\n"
"USAGS:    setuids [-v] [-T]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};
