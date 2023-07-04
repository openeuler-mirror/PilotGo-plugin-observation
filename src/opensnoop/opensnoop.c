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