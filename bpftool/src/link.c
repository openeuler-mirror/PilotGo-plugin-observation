#include <errno.h>
#include <linux/err.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/hashmap.h>

#include "json_writer.h"
#include "main.h"

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s { show | list }   [LINK]\n"
		"       %1$s %2$s pin        LINK  FILE\n"
		"       %1$s %2$s detach     LINK\n"
		"       %1$s %2$s help\n"
		"\n"
		"       " HELP_SPEC_LINK "\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-f|--bpffs} | {-n|--nomount} }\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static int do_show_link(int fd)
{
	struct bpf_link_info info;
	__u32 len = sizeof(info);
	char buf[256];
	int err;

	memset(&info, 0, sizeof(info));
again:
	err = bpf_link_get_info_by_fd(fd, &info, &len);
	if (err) {
		p_err("can't get link info: %s",
		      strerror(errno));
		close(fd);
		return err;
	}
	if (info.type == BPF_LINK_TYPE_RAW_TRACEPOINT &&
	    !info.raw_tracepoint.tp_name) {
		info.raw_tracepoint.tp_name = (unsigned long)&buf;
		info.raw_tracepoint.tp_name_len = sizeof(buf);
		goto again;
	}
	if (info.type == BPF_LINK_TYPE_ITER &&
	    !info.iter.target_name) {
		info.iter.target_name = (unsigned long)&buf;
		info.iter.target_name_len = sizeof(buf);
		goto again;
	}

	if (json_output)
		show_link_close_json(fd, &info);
	else
		show_link_close_plain(fd, &info);

	close(fd);
	return 0;
}

static int do_show(int argc, char **argv)
{
	__u32 id = 0;
	int err, fd;

	if (show_pinned) {
		link_table = hashmap__new(hash_fn_for_key_as_id,
					  equal_fn_for_key_as_id, NULL);
		if (IS_ERR(link_table)) {
			p_err("failed to create hashmap for pinned paths");
			return -1;
		}
		build_pinned_obj_table(link_table, BPF_OBJ_LINK);
	}
	build_obj_refs_table(&refs_table, BPF_OBJ_LINK);

	if (argc == 2) {
		fd = link_parse_fd(&argc, &argv);
		if (fd < 0)
			return fd;
		return do_show_link(fd);
	}

	if (argc)
		return BAD_ARG();

	if (json_output)
		jsonw_start_array(json_wtr);
	while (true) {
		err = bpf_link_get_next_id(id, &id);
		if (err) {
			if (errno == ENOENT)
				break;
			p_err("can't get next link: %s%s", strerror(errno),
			      errno == EINVAL ? " -- kernel too old?" : "");
			break;
		}

		fd = bpf_link_get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			p_err("can't get link by id (%u): %s",
			      id, strerror(errno));
			break;
		}

		err = do_show_link(fd);
		if (err)
			break;
	}
	if (json_output)
		jsonw_end_array(json_wtr);

	delete_obj_refs_table(refs_table);

	if (show_pinned)
		delete_pinned_obj_table(link_table);

	return errno == ENOENT ? 0 : -1;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "help",	do_help },
	{ "pin",	do_pin },
	{ "detach",	do_detach },
	{ 0 }
};

int do_link(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
