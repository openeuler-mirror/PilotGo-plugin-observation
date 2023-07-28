#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#include <bpf/bpf.h>

#include "main.h"

static int do_show(int argc, char **argv)
{
	int err;

	if (!has_perf_query_support())
		return -1;

	if (json_output)
		jsonw_start_array(json_wtr);
	err = show_proc();
	if (json_output)
		jsonw_end_array(json_wtr);

	return err;
}

static int do_help(int argc, char **argv)
{
	fprintf(stderr,
		"Usage: %1$s %2$s { show | list }\n"
		"       %1$s %2$s help }\n"
		"\n"
		"       " HELP_SPEC_OPTIONS " }\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "help",	do_help },
	{ 0 }
};

int do_perf(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
