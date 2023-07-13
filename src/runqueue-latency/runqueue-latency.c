// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "runqueue-latency.h"
#include "runqueue-latency.skel.h"
#include "trace_helpers.h"

struct env {
	time_t interval;
	pid_t pid;
	int times;
	bool milliseconds;
	bool per_process;
	bool per_thread;
	bool per_pidns;
	bool timestamp;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile sig_atomic_t exiting;