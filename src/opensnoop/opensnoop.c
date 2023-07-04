// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "opensnoop.h"
#include "opensnoop.skel.h"
#include "compat.h"

#include <libgen.h>
#include <fcntl.h>

#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

static volatile sig_atomic_t exiting;

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#endif

static struct env
{
    pid_t pid;
    pid_t tid;
    uid_t uid;
    int duration;
    bool verbose;
    bool timestamp;
    bool print_uid;
    bool extended;
    bool fuller_extended;
    bool failed;
    char *name;
#ifdef USE_BLAZESYM
    bool callers;
#endif
} env = {
    .uid = INVALID_UID};

struct openflag
{
    int flag;
    const char *name;
};

static struct openflag openflags[] = {
    {O_RDONLY, "O_RDONLY"},
    {O_WRONLY, "O_WRONLY"},
    {O_RDWR, "O_RDWR"},
    {O_APPEND, "O_APPEND"},
    {O_CREAT, "O_CREAT"},
    {O_CLOEXEC, "O_CLOEXEC"},
    {O_EXCL, "O_EXCL"},
    {O_TRUNC, "O_TRUNC"},
    {O_DIRECTORY, "O_DIRCTORY"},
    {O_NONBLOCK, "O_NONBLOCK"},
    {O_DSYNC, "O_DSYNC"},
    {O_SYNC, "O_SYNC"},
    {O_NOCTTY, "O_NOCTTY"},
    {O_NOFOLLOW, "O_NOFOLLOW"},
    {O_RSYNC, "O_RSYNC"},
};

struct openmode
{
    unsigned short mode;
    const char *name;
};

static struct openmode openmodes[] = {
    {S_IRWXU, "S_IRWXU"},
    {S_IRUSR, "S_IRUSR"},
    {S_IWUSR, "S_IWUSR"},
    {S_IXUSR, "S_IXUSR"},
    {S_IRWXG, "S_IRWXG"},
    {S_IRGRP, "S_IRGRP"},
    {S_IWGRP, "S_IWGRP"},
    {S_IXGRP, "S_IXGRP"},
    {S_IRWXO, "S_IRWXO"},
    {S_IROTH, "S_IROTH"},
    {S_IWOTH, "S_IWOTH"},
    {S_IXOTH, "S_IXOTH"},
    {S_ISUID, "S_ISUID"},
    {S_ISGID, "S_ISGID"},
    {S_ISVTX, "S_ISVTX"},
};

const char *argp_program_version = "opensnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
    "Trace open family syscalls\n"
    "\n"
    "USAGE: opensnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID] [-u UID] [-d DURATION]\n"
#ifdef USE_BLAZESYM
    "                 [-n NAME] [-e] [-c]\n"
#else
    "                 [-n NAME] [-e]\n"
#endif
    "\n"
    "EXAMPLES:\n"
    "    ./opensnoop           # trace all open() syscalls\n"
    "    ./opensnoop -T        # include timestamps\n"
    "    ./opensnoop -U        # include UID\n"
    "    ./opensnoop -x        # only show failed opens\n"
    "    ./opensnoop -p 181    # only trace PID 181\n"
    "    ./opensnoop -t 123    # only trace TID 123\n"
    "    ./opensnoop -u 1000   # only trace UID 1000\n"
    "    ./opensnoop -d 10     # trace for 10 seconds only\n"
    "    ./opensnoop -n main   # only print process names containing \"main\"\n"
    "    ./opensnoop -e        # show extended fields\n"
    "    ./opensnoop -E        # show formated extended fields\n"
#ifdef USE_BLAZESYM
    "    ./opensnoop -c        # show calling functions\n"
#endif
    "";

static const struct argp_option opts[] = {
    {"duration", 'd', "DURATION", 0, "Duration to trace"},
    {"extended-fields", 'e', NULL, 0, "Print extended fields"},
    {"format-extended-fields", 'E', NULL, 0, "Print formated extended fields"},
    {"name", 'n', "NAME", 0, "Trace process names containing this"},
    {"pid", 'p', "PID", 0, "Process PID to trace"},
    {"tid", 't', "TID", 0, "Thread ID to trace "},
    {"timestamp", 'T', NULL, 0, "Print timestamp"},
    {"uid", 'u', "UID", 0, "User ID to trace"},
    {"print-uid", 'U', NULL, 0, "Print UID"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"failed", 'x', NULL, 0, "Failed opens only"},
#ifdef USE_BLAZESYM
    {"callers", 'c', NULL, 0, "Show calling functions"},
#endif
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {}};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    static int pos_args;

    switch (key)
    {
    case 'e':
        env.extended = true;
        break;
    case 'E':
        env.fuller_extended = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case 'T':
        env.timestamp = true;
        break;
    case 'U':
        env.print_uid = true;
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'x':
        env.failed = true;
        break;
    case 'd':
        env.duration = argp_parse_long(key, arg, state);
        break;
    case 'n':
        env.name = arg;
        break;
    case 'p':
        env.pid = argp_parse_pid(key, arg, state);
        break;
    case 't':
        env.tid = argp_parse_pid(key, arg, state);
        break;
    case 'u':
        errno = 0;
        env.uid = strtol(arg, NULL, 10);
        if (errno || env.uid < 0 || env.uid >= INVALID_UID)
        {
            warning("Invalid UID %s\n", arg);
            argp_usage(state);
        }
        break;
#ifdef USE_BLAZESYM
    case 'c':
        env.callers = true;
        break;
#endif
    case ARGP_KEY_ARG:
        if (pos_args++)
        {
            warning("Unrecognized positional argument: %s\n", arg);
            argp_usage(state);
        }
        errno = 0;
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

static void parse_open_flags(int flag, int sps_cnt)
{
    char flags_string[1024] = {0};

    for (int j = 0; j < ARRAY_SIZE(openflags); j++)
    {
        if (!(flag & openflags[j].flag))
            continue;
        if (flags_string[0])
            strcat(flags_string, " | ");
        strcat(flags_string, openflags[j].name);
    }
    if (strlen(flags_string) == 0)
        return;

    for (int j = 0; j < sps_cnt; j++)
        printf(" ");

    printf("FLAGS: %s\n", flags_string);
}

static void parse_open_modes(unsigned short mode, int sps_cnt)
{
    char modes_string[1024] = {0};

    for (int j = 0; j < ARRAY_SIZE(openmodes); j++)
    {
        if (!(mode & openmodes[j].mode))
            continue;
        if (modes_string[0])
            strcat(modes_string, " | ");
        strcat(modes_string, openmodes[j].name);
    }
    if (strlen(modes_string) == 0)
        return;

    for (int j = 0; j < sps_cnt; j++)
        printf(" ");

    printf("MODES: %s\n", modes_string);
}