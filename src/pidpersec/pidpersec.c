// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "pidpersec.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;
static bool verbose = false;

const char *argp_program_version = "pidpersec 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
    "Count new procesess (via fork)\n"
    "\n"
    "USAGE:      pidpersec [-v]\n"
    "\n"
    "Examples:\n"
    "    pidpersec              # Count new process every seconds\n";
