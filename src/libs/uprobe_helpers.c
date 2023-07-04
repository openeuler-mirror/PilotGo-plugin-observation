// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Google LLC. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <gelf.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

/*
 * Returns 0 on success; -1 on failure.  On sucess, returns via `path` the full
 * path to the program for pid.
 */
int get_pid_binary_path(pid_t pid, char *path, size_t path_sz)
{
	ssize_t ret;
	char proc_pid_exe[32];

	if (snprintf(proc_pid_exe, sizeof(proc_pid_exe), "/proc/%d/exe", pid)
	    >= sizeof(proc_pid_exe)) {
		warn("snprintf /proc/PID/exe failed");
		return -1;
	}
	ret = readlink(proc_pid_exe, path, path_sz);
	if (ret < 0) {
		warn("No such pid %d\n", pid);
		return -1;
	}
	if (ret >= path_sz) {
		warn("readlink truncation");
		return -1;
	}
	path[ret] = '\0';

	return 0;
}
