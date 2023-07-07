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

static void sig_handler(int sig)
{
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG && !verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 'v':
        verbose = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case 'T':
        timestamp = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;

    if (timestamp)
    {
        char ts[32];

        strftime_now(ts, sizeof(ts), "%H:%M:%S");
        printf("%-8s ", ts);
    }

    printf("%-6d %-16s %-6d %-16s %lld.%03lld\n",
           e->ppid, e->pcomm, e->pid, e->comm, e->tv_sec, e->tv_nsec / 1000000);

    return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    warning("Lost %llu event on CPU #%d!\n", lost_cnt, cpu);
}