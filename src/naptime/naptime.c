// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "naptime.h"
#include "naptime.skel.h"
#include "btf_helpers.h"
#include "compat.h"

static volatile sig_atomic_t exiting;
static bool verbose = false;
static bool timestamp = false;

const char *argp_program_version = "naptime 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
    "Show voluntary sleep calls.\n"
    "\n"
    "USAGE:    naptime [-v] [-T]\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"timestamp", 'T', NULL, 0, "Include timestamp on output"},
    {NULL, 'h', NULL, 0, "Show the full help"},
    {}};