// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "execsnoop.skel.h"
#include "execsnoop.h"
#include "trace_helpers.h"
#include "btf_helpers.h"

#define MAX_ARGS_KEY		259

static volatile sig_atomic_t exiting;

static struct env {
	bool time;
	bool timestamp;
	bool fails;
	uid_t uid;
	bool quote;
	const char *name;
	const char *line;
	bool print_uid;
	bool verbose;
	int max_args;
	char *cgroupspath;
	bool cg;
} env = {
	.max_args = DEFAULT_MAX_ARGS,
	.uid = INVALID_UID
};

const char *argp_program_version = "execsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace exec syscalls\n"
"\n"
"USAGE: execsnoop [-h] [-T] [-t] [-x] [-u UID] [-q] [-n NAME] [-l LINE] [-U] [-c CG]\n"
"                 [--max-args MAX_ARGS]\n"
"\n"
"EXAMPLES:\n"
"   ./execsnoop           # trace all exec() syscalls\n"
"   ./execsnoop -x        # include failed exec()s\n"
"   ./execsnoop -T        # include time (HH:MM:SS)\n"
"   ./execsnoop -U        # include UID\n"
"   ./execsnoop -u 1000   # only trace UID 1000\n"
"   ./execsnoop -t        # include timestamps\n"
"   ./execsnoop -q        # add \"quotemarks\" around arguments\n"
"   ./execsnoop -n main   # only print command lines containing \"main\"\n"
"   ./execsnoop -l tpkg   # only print command where arguments contains \"tpkg\"\n"
"   ./execsnoop -c CG     # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "time", 'T', NULL, 0, "Include time colum on output (HH:MM:SS)" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "fails", 'x', NULL, 0, "Include failed exec()s" },
	{ "uid", 'u', "UID", 0, "Trace this UID only" },
	{ "quote", 'q', NULL, 0, "Add quotemarks (\") around arguments" },
	{ "name", 'n', "NAME", 0, "only print commands matching this name, any arg" },
	{ "line", 'l', "LINE", 0, "only print commands where arg contains this line" },
	{ "print-uid", 'U', NULL, 0, "print UID column" },
	{ "max-args", MAX_ARGS_KEY, "MAX_ARGS", 0,
		"maximum number of arguments parsed and displayed, default to 20" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};