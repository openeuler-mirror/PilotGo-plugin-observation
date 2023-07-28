#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <linux/tc_act/tc_bpf.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "bpf/nlattr.h"
#include "main.h"
#include "netlink_dumper.h"

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "attach",	do_attach },
	{ "detach",	do_detach },
	{ "help",	do_help },
	{ 0 }
};

int do_net(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
