// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (C) 2017 Facebook
// Author: Roman Gushchin <guro@fb.com>

#define _XOPEN_SOURCE 500
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>

#include "main.h"

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s { show | list } CGROUP [**effective**]\n"
		"       %1$s %2$s tree [CGROUP_ROOT] [**effective**]\n"
		"       %1$s %2$s attach CGROUP ATTACH_TYPE PROG [ATTACH_FLAGS]\n"
		"       %1$s %2$s detach CGROUP ATTACH_TYPE PROG\n"
		"       %1$s %2$s help\n"
		"\n"
		HELP_SPEC_ATTACH_TYPES "\n"
		"       " HELP_SPEC_ATTACH_FLAGS "\n"
		"       " HELP_SPEC_PROGRAM "\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-f|--bpffs} }\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "tree",   do_show_tree },
	{ "attach",	do_attach },
	{ "detach",	do_detach },
	{ "help",	do_help },
	{ 0 }
};

int do_cgroup(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
