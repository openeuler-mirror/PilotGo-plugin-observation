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

static int net_parse_dev(int *argc, char ***argv)
{
	int ifindex;

	if (is_prefix(**argv, "dev")) {
		NEXT_ARGP();

		ifindex = if_nametoindex(**argv);
		if (!ifindex)
			p_err("invalid devname %s", **argv);

		NEXT_ARGP();
	} else {
		p_err("expected 'dev', got: '%s'?", **argv);
		return -1;
	}

	return ifindex;
}

static int do_attach_detach_xdp(int progfd, enum net_attach_type attach_type,
				int ifindex, bool overwrite)
{
	__u32 flags = 0;

	if (!overwrite)
		flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
	if (attach_type == NET_ATTACH_TYPE_XDP_GENERIC)
		flags |= XDP_FLAGS_SKB_MODE;
	if (attach_type == NET_ATTACH_TYPE_XDP_DRIVER)
		flags |= XDP_FLAGS_DRV_MODE;
	if (attach_type == NET_ATTACH_TYPE_XDP_OFFLOAD)
		flags |= XDP_FLAGS_HW_MODE;

	return bpf_xdp_attach(ifindex, progfd, flags, NULL);
}

static int do_show(int argc, char **argv)
{
	struct bpf_attach_info attach_info = {};
	int i, sock, ret, filter_idx = -1;
	struct bpf_netdev_t dev_array;
	unsigned int nl_pid = 0;
	char err_buf[256];

	if (argc == 2) {
		filter_idx = net_parse_dev(&argc, &argv);
		if (filter_idx < 1)
			return -1;
	} else if (argc != 0) {
		usage();
	}

	ret = query_flow_dissector(&attach_info);
	if (ret)
		return -1;

	sock = netlink_open(&nl_pid);
	if (sock < 0) {
		fprintf(stderr, "failed to open netlink sock\n");
		return -1;
	}

	dev_array.devices = NULL;
	dev_array.used_len = 0;
	dev_array.array_len = 0;
	dev_array.filter_idx = filter_idx;

	if (json_output)
		jsonw_start_array(json_wtr);
	NET_START_OBJECT;
	NET_START_ARRAY("xdp", "%s:\n");
	ret = netlink_get_link(sock, nl_pid, dump_link_nlmsg, &dev_array);
	NET_END_ARRAY("\n");

	if (!ret) {
		NET_START_ARRAY("tc", "%s:\n");
		for (i = 0; i < dev_array.used_len; i++) {
			ret = show_dev_tc_bpf(sock, nl_pid,
					      &dev_array.devices[i]);
			if (ret)
				break;
		}
		NET_END_ARRAY("\n");
	}

	NET_START_ARRAY("flow_dissector", "%s:\n");
	if (attach_info.flow_dissector_id > 0)
		NET_DUMP_UINT("id", "id %u", attach_info.flow_dissector_id);
	NET_END_ARRAY("\n");

	NET_END_OBJECT;
	if (json_output)
		jsonw_end_array(json_wtr);

	if (ret) {
		if (json_output)
			jsonw_null(json_wtr);
		libbpf_strerror(ret, err_buf, sizeof(err_buf));
		fprintf(stderr, "Error: %s\n", err_buf);
	}
	free(dev_array.devices);
	close(sock);
	return ret;
}

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
