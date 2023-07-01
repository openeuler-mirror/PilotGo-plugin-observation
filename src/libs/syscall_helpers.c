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

void init_syscall_names(void)
{
	size_t old_size, size = 1024;
	const char *name;
	char buf[64];
	int number;
	int err;
	FILE *f;

	f = popen("ausyscall --dump 2>/dev/null", "r");
	if (!f) {
		warn("popen: ausyscall --dump: %s\n", strerror(errno));
		return;
	}

	syscall_names = calloc(size, sizeof(char *));
	if (!syscall_names) {
		warn("calloc: %s\n", strerror(errno));
		goto close;
	}

	/* skip the header, ignore the result of fgets, outwit the comiler */
	(void) !!fgets(buf, sizeof(buf), f);

	while (fgets(buf, sizeof(buf), f)) {
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';

		name = parse_syscall(buf, &number);
		if (!name || !name[0])
			goto close;

		/* In a rare case when syscall number is > than initial 1024 */
		if (number >= size) {
			old_size = size;
			size = 1024 * (1 + number / 1024);
			syscall_names = realloc(syscall_names,
						size * sizeof(char *));
			if (!syscall_names) {
				warn("realloc: %s\n", strerror(errno));
				goto close;
			}
			memset(syscall_names+old_size, 0,
			       (size - old_size) * sizeof(char *));
		}

		if (syscall_names[number]) {
			warn("duplicate number: %d (stored: %s)",
				number, syscall_names[number]);
			goto close;
		}

		syscall_names[number] = strdup(name);
		if (!syscall_names[number]) {
			warn("strdup: %s\n", strerror(errno));
			goto close;
		}
		syscall_names_size = MAX(number+1, syscall_names_size);
	}

	if (ferror(f))
		warn("fgets: %s\n", strerror(errno));
close:
	err = pclose(f);
	if (err < 0)
		warn("pclose: %s\n", strerror(errno));
}
