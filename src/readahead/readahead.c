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

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'd':
        env.duration = argp_parse_long(key, arg, state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    exiting = 1;
}
