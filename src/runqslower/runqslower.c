// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "runqslower.h"
#include "runqslower.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting = 0;

struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	bool previous;
	bool verbose;
} env = {
	.min_us = 1000,
};