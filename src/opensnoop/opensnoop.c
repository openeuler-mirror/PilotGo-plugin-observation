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