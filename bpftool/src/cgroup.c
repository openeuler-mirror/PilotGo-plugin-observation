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

static int do_show(int argc, char **argv)
{
	enum bpf_attach_type type;
	int has_attached_progs;
	const char *path;
	int cgroup_fd;
	int ret = -1;

	query_flags = 0;

	if (!REQ_ARGS(1))
		return -1;
	path = GET_ARG();

	while (argc) {
		if (is_prefix(*argv, "effective")) {
			if (query_flags & BPF_F_QUERY_EFFECTIVE) {
				p_err("duplicated argument: %s", *argv);
				return -1;
			}
			query_flags |= BPF_F_QUERY_EFFECTIVE;
			NEXT_ARG();
		} else {
			p_err("expected no more arguments, 'effective', got: '%s'?",
			      *argv);
			return -1;
		}
	}

	cgroup_fd = open(path, O_RDONLY);
	if (cgroup_fd < 0) {
		p_err("can't open cgroup %s", path);
		goto exit;
	}

	has_attached_progs = cgroup_has_attached_progs(cgroup_fd);
	if (has_attached_progs < 0) {
		p_err("can't query bpf programs attached to %s: %s",
		      path, strerror(errno));
		goto exit_cgroup;
	} else if (!has_attached_progs) {
		ret = 0;
		goto exit_cgroup;
	}

	if (json_output)
		jsonw_start_array(json_wtr);
	else if (query_flags & BPF_F_QUERY_EFFECTIVE)
		printf("%-8s %-15s %-15s\n", "ID", "AttachType", "Name");
	else
		printf("%-8s %-15s %-15s %-15s\n", "ID", "AttachType",
		       "AttachFlags", "Name");

	btf_vmlinux = libbpf_find_kernel_btf();
	for (type = 0; type < __MAX_BPF_ATTACH_TYPE; type++) {
		if (show_bpf_progs(cgroup_fd, type, 0) == 0)
			ret = 0;
	}

	if (json_output)
		jsonw_end_array(json_wtr);

exit_cgroup:
	close(cgroup_fd);
exit:
	return ret;
}


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
