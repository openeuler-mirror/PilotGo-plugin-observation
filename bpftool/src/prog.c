// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017-2018 Netronome Systems, Inc. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <dirent.h>

#include <linux/err.h>
#include <linux/perf_event.h>
#include <linux/sizes.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/hashmap.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_internal.h>
#include <bpf/skel_internal.h>

#include "cfg.h"
#include "main.h"
#include "xlated_dumper.h"

int do_prog(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
