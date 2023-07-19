// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017-2018 Netronome Systems, Inc. */

#include <errno.h>
#include <fcntl.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/hashmap.h>

#include "json_writer.h"
#include "main.h"

int do_map(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
