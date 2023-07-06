// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "mountsnoop.h"
#include "mountsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"

static volatile sig_atomic_t exiting;

static pid_t target_pid = 0;
static bool emit_timestamp = false;
static bool output_vertically = false;
static bool verbose = false;
static const char *flag_names[] = {
    [0] = "MS_RDONLY",
    [1] = "MS_NOSUID",
    [2] = "MS_NODEV",
    [3] = "MS_NOEXEC",
    [4] = "MS_SYNCHRONOUS",
    [5] = "MS_REMOUNT",
    [6] = "MS_MANDLOCK",
    [7] = "MS_DIRSYNC",
    [8] = "MS_NOSYMFOLLOW",
    [9] = "MS_NOATIME",
    [10] = "MS_NODIRATIME",
    [11] = "MS_BIND",
    [12] = "MS_MOVE",
    [13] = "MS_REC",
    [14] = "MS_VERBOSE",
    [15] = "MS_SLIENT",
    [16] = "MS_POSIXACL",
    [17] = "MS_UNBINDABLE",
    [18] = "MS_PRIVATE",
    [19] = "MS_SLAVE",
    [20] = "MS_SHARED",
    [21] = "MS_RELATIME",
    [22] = "MS_KERNMOUNT",
    [23] = "MS_I_VERSION",
    [24] = "MS_STRICTATIME",
    [25] = "MS_LAZYTIME",
    [26] = "MS_SUBMOUNT",
    [27] = "MS_NOREMOTELOCK",
    [28] = "MS_NOSEC",
    [29] = "MS_BORN",
    [30] = "MS_ACTIVE",
    [32] = "MS_NOUSER",
};

const char *argp_program_version = "mountsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
    "Trace mount and umount syscalls.\n"
    "\n"
    "USAGE: mountsnoop [-h] [-T] [-p PID] [-v]\n"
    "\n"
    "EXAMPLES:\n"
    "    mountsnoop         # trace mount and umount syscalls\n"
    "    mountsnoop -d      # detailed output (one line per column value)\n"
    "    mountsnoop -p 1216 # only trace PID 1216\n";

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "Process ID to trace"},
    {"timestamp", 'T', NULL, 0, "Include timestamp on output"},
    {NULL, 't', NULL, OPTION_ALIAS, "Include timestamp on output"},
    {"detailed", 'd', NULL, 0, "Output result in detail mode"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 'p':
        target_pid = argp_parse_pid(key, arg, state);
        break;
    case 'T':
    case 't':
        emit_timestamp = true;
        break;
    case 'd':
        output_vertically = true;
        break;
    case 'v':
        verbose = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG && !verbose)
        return 0;

    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    exiting = 1;
}

static const char *strflags(__u64 flags)
{
    static char str[512];

    if (!flags)
        return "0x0";

    str[0] = 0;

    for (int i = 0; i < ARRAY_SIZE(flag_names); i++)
    {
        if (!((1 << i) & flags))
            continue;
        if (str[0])
            strcat(str, " | ");
        strcat(str, flag_names[i]);
    }
    return str;
}

static const char *gen_call(const struct event *e)
{
    static char call[10240] = {};

    if (e->op == UMOUNT)
    {
        snprintf(call, sizeof(call), "umount(\"%s\", %s) = %s",
                 e->dest, strflags(e->flags), strerrno(e->ret));
    }
    else
    {
        snprintf(call, sizeof(call), "mount(\"%s\", \"%s\", \"%s\", %s, \"%s\") = %s",
                 e->src, e->dest, e->fs, strflags(e->flags), e->data, strerrno(e->ret));
    }
    return call;
}