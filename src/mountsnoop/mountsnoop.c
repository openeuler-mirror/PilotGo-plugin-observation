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