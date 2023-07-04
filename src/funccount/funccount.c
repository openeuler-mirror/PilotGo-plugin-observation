// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// WARNING: This program can only be run on kernels that support kprobe multi.
// If it is not supported, it will exit directly. Currently, on X86, at least
// the kernel must be greater than v5.18-rc1 and Config must be enable
// CONFIG_FPROBE, currently not supported on other platforms.
//
// Baseon funccount.py - 2015 Brendan Gregg

#include "commons.h"
#include "funccount.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool verbose;
	int interval;
	int interations;
	pid_t pid;
	int duration;
	bool timestamp;
	const char *functions;
} env = {
	.interval = 99999999,
	.interations = 9999999,
};
