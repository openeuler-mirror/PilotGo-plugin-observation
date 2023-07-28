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

static int perf_query_supported;
static bool has_perf_query_support(void)
{
	__u64 probe_offset, probe_addr;
	__u32 len, prog_id, fd_type;
	char buf[256];
	int fd;

	if (perf_query_supported)
		goto out;

	fd = open("/", O_RDONLY);
	if (fd < 0) {
		p_err("perf_query_support: cannot open directory \"/\" (%s)",
		      strerror(errno));
		goto out;
	}

	/* the following query will fail as no bpf attachment,
	 * the expected errno is ENOTSUPP
	 */
	errno = 0;
	len = sizeof(buf);
	bpf_task_fd_query(getpid(), fd, 0, buf, &len, &prog_id,
			  &fd_type, &probe_offset, &probe_addr);

	if (errno == 524 /* ENOTSUPP */) {
		perf_query_supported = 1;
		goto close_fd;
	}

	perf_query_supported = 2;
	p_err("perf_query_support: %s", strerror(errno));
	fprintf(stderr,
		"HINT: non root or kernel doesn't support TASK_FD_QUERY\n");

close_fd:
	close(fd);
out:
	return perf_query_supported == 1;
}

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
