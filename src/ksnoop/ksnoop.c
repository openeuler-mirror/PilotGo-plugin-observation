// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "ksnoop.h"
#include "ksnoop.skel.h"
#include <bpf/btf.h>

#ifndef KSNOOP_VERSION
#define KSNOOP_VERSION	"0.1"
#endif

static volatile sig_atomic_t exiting;
static struct btf *vmlinux_btf;
static const char *bin_name;
static int pages = PAGES_DEFAULT;

enum log_level {
	DEBUG,
	WARN,
	ERROR,
};

static enum log_level log_level = WARN;
static bool verbose = false;

static __u32 filter_pid;
static bool stack_mode;
