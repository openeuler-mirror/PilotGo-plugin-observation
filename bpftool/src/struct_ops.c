#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <linux/err.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "json_writer.h"
#include "main.h"

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
