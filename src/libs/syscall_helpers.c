// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Anton Protopopov
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

static const char **syscall_names;
static size_t syscall_names_size;

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

static const char *parse_syscall(const char *buf, int *number)
{
	char *end;
	long x;

	errno = 0;
	x = strtol(buf, &end, 10);
	if (errno) {
		warn("strtol(%s): %s\n", buf, strerror(errno));
		return NULL;
	} else if (end == buf) {
		warn("strtol(%s): no digits found\n", buf);
		return NULL;
	} else if (x < 0 || x > INT_MAX) {
		warn("strtol(%s): bad syscall number: %ld\n", buf, x);
		return NULL;
	}
	if (*end != '\t') {
		warn("bad input: %s (expected <num>\t<name>)\n", buf);
		return NULL;
	}

	*number = x;
	return ++end;
}
