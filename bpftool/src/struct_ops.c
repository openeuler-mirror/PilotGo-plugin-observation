#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <linux/err.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "json_writer.h"
#include "main.h"

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s { show | list } [STRUCT_OPS_MAP]\n"
		"       %1$s %2$s dump [STRUCT_OPS_MAP]\n"
		"       %1$s %2$s register OBJ\n"
		"       %1$s %2$s unregister STRUCT_OPS_MAP\n"
		"       %1$s %2$s help\n"
		"\n"
		"       STRUCT_OPS_MAP := [ id STRUCT_OPS_MAP_ID | name STRUCT_OPS_MAP_NAME ]\n"
		"       " HELP_SPEC_OPTIONS " }\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "register",	do_register },
	{ "unregister",	do_unregister },
	{ "dump",	do_dump },
	{ "help",	do_help },
	{ 0 }
};

int do_struct_ops(int argc, char **argv)
{
	int err;

	err = cmd_select(cmds, argc, argv, do_help);

	btf__free(btf_vmlinux);

	return err;
}
