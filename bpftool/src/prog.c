#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <dirent.h>

#include <linux/err.h>
#include <linux/perf_event.h>
#include <linux/sizes.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/hashmap.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_internal.h>
#include <bpf/skel_internal.h>

#include "cfg.h"
#include "main.h"
#include "xlated_dumper.h"

static struct hashmap *prog_table;

static int show_prog(int fd)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	int err;

	err = bpf_prog_get_info_by_fd(fd, &info, &len);
	if (err) {
		p_err("can't get prog info: %s", strerror(errno));
		return -1;
	}

	if (json_output)
		print_prog_json(&info, fd);
	else
		print_prog_plain(&info, fd);

	return 0;
}

static int do_show_subset(int argc, char **argv)
{
	int *fds = NULL;
	int nb_fds, i;
	int err = -1;

	fds = malloc(sizeof(int));
	if (!fds) {
		p_err("mem alloc failed");
		return -1;
	}
	nb_fds = prog_parse_fds(&argc, &argv, &fds);
	if (nb_fds < 1)
		goto exit_free;

	if (json_output && nb_fds > 1)
		jsonw_start_array(json_wtr);	/* root array */
	for (i = 0; i < nb_fds; i++) {
		err = show_prog(fds[i]);
		if (err) {
			for (; i < nb_fds; i++)
				close(fds[i]);
			break;
		}
		close(fds[i]);
	}
	if (json_output && nb_fds > 1)
		jsonw_end_array(json_wtr);	/* root array */

exit_free:
	free(fds);
	return err;
}

static int do_show(int argc, char **argv)
{
	__u32 id = 0;
	int err;
	int fd;

	if (show_pinned) {
		prog_table = hashmap__new(hash_fn_for_key_as_id,
					  equal_fn_for_key_as_id, NULL);
		if (IS_ERR(prog_table)) {
			p_err("failed to create hashmap for pinned paths");
			return -1;
		}
		build_pinned_obj_table(prog_table, BPF_OBJ_PROG);
	}
	build_obj_refs_table(&refs_table, BPF_OBJ_PROG);

	if (argc == 2)
		return do_show_subset(argc, argv);

	if (argc)
		return BAD_ARG();

	if (json_output)
		jsonw_start_array(json_wtr);
	while (true) {
		err = bpf_prog_get_next_id(id, &id);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			p_err("can't get next program: %s%s", strerror(errno),
			      errno == EINVAL ? " -- kernel too old?" : "");
			err = -1;
			break;
		}

		fd = bpf_prog_get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			p_err("can't get prog by id (%u): %s",
			      id, strerror(errno));
			err = -1;
			break;
		}

		err = show_prog(fd);
		close(fd);
		if (err)
			break;
	}

	if (json_output)
		jsonw_end_array(json_wtr);

	delete_obj_refs_table(refs_table);

	if (show_pinned)
		delete_pinned_obj_table(prog_table);

	return err;
}


static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s { show | list } [PROG]\n"
		"       %1$s %2$s dump xlated PROG [{ file FILE | [opcodes] [linum] [visual] }]\n"
		"       %1$s %2$s dump jited  PROG [{ file FILE | [opcodes] [linum] }]\n"
		"       %1$s %2$s pin   PROG FILE\n"
		"       %1$s %2$s { load | loadall } OBJ  PATH \\\n"
		"                         [type TYPE] [dev NAME] \\\n"
		"                         [map { idx IDX | name NAME } MAP]\\\n"
		"                         [pinmaps MAP_DIR]\n"
		"                         [autoattach]\n"
		"       %1$s %2$s attach PROG ATTACH_TYPE [MAP]\n"
		"       %1$s %2$s detach PROG ATTACH_TYPE [MAP]\n"
		"       %1$s %2$s run PROG \\\n"
		"                         data_in FILE \\\n"
		"                         [data_out FILE [data_size_out L]] \\\n"
		"                         [ctx_in FILE [ctx_out FILE [ctx_size_out M]]] \\\n"
		"                         [repeat N]\n"
		"       %1$s %2$s profile PROG [duration DURATION] METRICs\n"
		"       %1$s %2$s tracelog\n"
		"       %1$s %2$s help\n"
		"\n"
		"       " HELP_SPEC_MAP "\n"
		"       " HELP_SPEC_PROGRAM "\n"
		"       TYPE := { socket | kprobe | kretprobe | classifier | action |\n"
		"                 tracepoint | raw_tracepoint | xdp | perf_event | cgroup/skb |\n"
		"                 cgroup/sock | cgroup/dev | lwt_in | lwt_out | lwt_xmit |\n"
		"                 lwt_seg6local | sockops | sk_skb | sk_msg | lirc_mode2 |\n"
		"                 sk_reuseport | flow_dissector | cgroup/sysctl |\n"
		"                 cgroup/bind4 | cgroup/bind6 | cgroup/post_bind4 |\n"
		"                 cgroup/post_bind6 | cgroup/connect4 | cgroup/connect6 |\n"
		"                 cgroup/getpeername4 | cgroup/getpeername6 |\n"
		"                 cgroup/getsockname4 | cgroup/getsockname6 | cgroup/sendmsg4 |\n"
		"                 cgroup/sendmsg6 | cgroup/recvmsg4 | cgroup/recvmsg6 |\n"
		"                 cgroup/getsockopt | cgroup/setsockopt | cgroup/sock_release |\n"
		"                 struct_ops | fentry | fexit | freplace | sk_lookup }\n"
		"       ATTACH_TYPE := { sk_msg_verdict | sk_skb_verdict | sk_skb_stream_verdict |\n"
		"                        sk_skb_stream_parser | flow_dissector }\n"
		"       METRIC := { cycles | instructions | l1d_loads | llc_misses | itlb_misses | dtlb_misses }\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-f|--bpffs} | {-m|--mapcompat} | {-n|--nomount} |\n"
		"                    {-L|--use-loader} }\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static int do_dump(int argc, char **argv)
{
	struct bpf_prog_info info;
	__u32 info_len = sizeof(info);
	size_t info_data_sz = 0;
	void *info_data = NULL;
	char *filepath = NULL;
	bool opcodes = false;
	bool visual = false;
	enum dump_mode mode;
	bool linum = false;
	int nb_fds, i = 0;
	int *fds = NULL;
	int err = -1;

	if (is_prefix(*argv, "jited")) {
		if (disasm_init())
			return -1;
		mode = DUMP_JITED;
	} else if (is_prefix(*argv, "xlated")) {
		mode = DUMP_XLATED;
	} else {
		p_err("expected 'xlated' or 'jited', got: %s", *argv);
		return -1;
	}
	NEXT_ARG();

	if (argc < 2)
		usage();

	fds = malloc(sizeof(int));
	if (!fds) {
		p_err("mem alloc failed");
		return -1;
	}
	nb_fds = prog_parse_fds(&argc, &argv, &fds);
	if (nb_fds < 1)
		goto exit_free;

	while (argc) {
		if (is_prefix(*argv, "file")) {
			NEXT_ARG();
			if (!argc) {
				p_err("expected file path");
				goto exit_close;
			}
			if (nb_fds > 1) {
				p_err("several programs matched");
				goto exit_close;
			}

			filepath = *argv;
			NEXT_ARG();
		} else if (is_prefix(*argv, "opcodes")) {
			opcodes = true;
			NEXT_ARG();
		} else if (is_prefix(*argv, "visual")) {
			if (nb_fds > 1) {
				p_err("several programs matched");
				goto exit_close;
			}

			visual = true;
			NEXT_ARG();
		} else if (is_prefix(*argv, "linum")) {
			linum = true;
			NEXT_ARG();
		} else {
			usage();
			goto exit_close;
		}
	}

}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "help",	do_help },
	{ "dump",	do_dump },
	{ "pin",	do_pin },
	{ "load",	do_load },
	{ "loadall",	do_loadall },
	{ "attach",	do_attach },
	{ "detach",	do_detach },
	{ "tracelog",	do_tracelog },
	{ "run",	do_run },
	{ "profile",	do_profile },
	{ 0 }
};

int do_prog(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
