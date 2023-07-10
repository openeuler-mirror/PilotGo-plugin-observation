// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "readahead.h"
#include "readahead.skel.h"
#include "trace_helpers.h"

static struct env
{
    int duration;
    bool verbose;
} env = {
    .duration = -1};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "readahead 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
    "Show fs automatic read-ahead usage.\n"
    "\n"
    "USAGE: readahead [--help] [-d DURATION]\n"
    "\n"
    "EXAMPLES:\n"
    "    readahead              # summarize on-CPU time as a histogram\n"
    "    readahead -d 10        # trace for 10 seconds only\n";

static const struct argp_option opts[] = {
    {"duration", 'd', "DURATION", 0, "Duration to trace"},
    {"verbose", 'v', NULL, 0, "Verbose output debug"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {}};