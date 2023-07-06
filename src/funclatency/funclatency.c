// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "funclatency.h"
#include "funclatency.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"

static struct env {
	int units;
	pid_t pid;
	unsigned int duration;
	unsigned int interval;
	unsigned int iterations;
	bool timestamp;
	char *funcname;
	bool verbose;
	bool kprobes;
	char *cgroupspath;
	bool cg;
	bool is_kernel_func;
} env = {
	.interval = 99999999,
	.iterations = 99999999,
};
