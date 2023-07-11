// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "gethostlatency.h"
#include "gethostlatency.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool verbose;
	pid_t pid;
	char *libc_path;
} env = {};

const char *argp_program_version = "gethostlatency 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Show latency for getaddrinfo/gethostbyname[2] calls.\n"
"\n"
"USAGE: gethostlatency [-h] [-p PID] [-l LIBC]\n"
"\n"
"EXAMPLES:\n"
"    gethostlatency             # time getaddrinfo/gethostbyname[2] calls\n"
"    gethostlatency -p 1216     # only trace PID 1216\n";
