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

static int
get_prog_type_by_name(const char *name, enum bpf_prog_type *prog_type,
		      enum bpf_attach_type *expected_attach_type)
{
	libbpf_print_fn_t print_backup;
	int ret;

	ret = libbpf_prog_type_by_name(name, prog_type, expected_attach_type);
	if (!ret)
		return ret;

	/* libbpf_prog_type_by_name() failed, let's re-run with debug level */
	print_backup = libbpf_set_print(print_all_levels);
	ret = libbpf_prog_type_by_name(name, prog_type, expected_attach_type);
	libbpf_set_print(print_backup);

	return ret;
}

static int do_pin(int argc, char **argv)
{
	int err;

	err = do_pin_any(argc, argv, prog_parse_fd);
	if (!err && json_output)
		jsonw_null(json_wtr);
	return err;
}

static int do_loader(int argc, char **argv)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	DECLARE_LIBBPF_OPTS(gen_loader_opts, gen);
	struct bpf_object *obj;
	const char *file;
	int err = 0;

	if (!REQ_ARGS(1))
		return -1;
	file = GET_ARG();

	if (verifier_logs)
		/* log_level1 + log_level2 + stats, but not stable UAPI */
		open_opts.kernel_log_level = 1 + 2 + 4;

	obj = bpf_object__open_file(file, &open_opts);
	if (!obj) {
		p_err("failed to open object file");
		goto err_close_obj;
	}

	err = bpf_object__gen_loader(obj, &gen);
	if (err)
		goto err_close_obj;

	err = bpf_object__load(obj);
	if (err) {
		p_err("failed to load object file");
		goto err_close_obj;
	}

	if (verifier_logs) {
		struct dump_data dd = {};

		kernel_syms_load(&dd);
		dump_xlated_plain(&dd, (void *)gen.insns, gen.insns_sz, false, false);
		kernel_syms_destroy(&dd);
	}
	err = try_loader(&gen);
err_close_obj:
	bpf_object__close(obj);
	return err;
}

static int load_with_options(int argc, char **argv, bool first_prog_only)
{
	enum bpf_prog_type common_prog_type = BPF_PROG_TYPE_UNSPEC;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts,
		.relaxed_maps = relaxed_maps,
	);
	enum bpf_attach_type expected_attach_type;
	struct map_replace *map_replace = NULL;
	struct bpf_program *prog = NULL, *pos;
	unsigned int old_map_fds = 0;
	const char *pinmaps = NULL;
	bool auto_attach = false;
	struct bpf_object *obj;
	struct bpf_map *map;
	const char *pinfile;
	unsigned int i, j;
	__u32 ifindex = 0;
	const char *file;
	int idx, err;


	if (!REQ_ARGS(2))
		return -1;
	file = GET_ARG();
	pinfile = GET_ARG();

	while (argc) {
		if (is_prefix(*argv, "type")) {
			NEXT_ARG();

			if (common_prog_type != BPF_PROG_TYPE_UNSPEC) {
				p_err("program type already specified");
				goto err_free_reuse_maps;
			}
			if (!REQ_ARGS(1))
				goto err_free_reuse_maps;

			err = libbpf_prog_type_by_name(*argv, &common_prog_type,
						       &expected_attach_type);
			if (err < 0) {
				char *type = malloc(strlen(*argv) + 2);

				if (!type) {
					p_err("mem alloc failed");
					goto err_free_reuse_maps;
				}
				*type = 0;
				strcat(type, *argv);
				strcat(type, "/");

				err = get_prog_type_by_name(type, &common_prog_type,
							    &expected_attach_type);
				free(type);
				if (err < 0)
					goto err_free_reuse_maps;
			}

			NEXT_ARG();
		} else if (is_prefix(*argv, "map")) {
			void *new_map_replace;
			char *endptr, *name;
			int fd;

			NEXT_ARG();

			if (!REQ_ARGS(4))
				goto err_free_reuse_maps;

			if (is_prefix(*argv, "idx")) {
				NEXT_ARG();

				idx = strtoul(*argv, &endptr, 0);
				if (*endptr) {
					p_err("can't parse %s as IDX", *argv);
					goto err_free_reuse_maps;
				}
				name = NULL;
			} else if (is_prefix(*argv, "name")) {
				NEXT_ARG();

				name = *argv;
				idx = -1;
			} else {
				p_err("expected 'idx' or 'name', got: '%s'?",
				      *argv);
				goto err_free_reuse_maps;
			}
			NEXT_ARG();

			fd = map_parse_fd(&argc, &argv);
			if (fd < 0)
				goto err_free_reuse_maps;

			new_map_replace = libbpf_reallocarray(map_replace,
							      old_map_fds + 1,
							      sizeof(*map_replace));
			if (!new_map_replace) {
				p_err("mem alloc failed");
				goto err_free_reuse_maps;
			}
			map_replace = new_map_replace;

			map_replace[old_map_fds].idx = idx;
			map_replace[old_map_fds].name = name;
			map_replace[old_map_fds].fd = fd;
			old_map_fds++;
		} else if (is_prefix(*argv, "dev")) {
			NEXT_ARG();

			if (ifindex) {
				p_err("offload device already specified");
				goto err_free_reuse_maps;
			}
			if (!REQ_ARGS(1))
				goto err_free_reuse_maps;

			ifindex = if_nametoindex(*argv);
			if (!ifindex) {
				p_err("unrecognized netdevice '%s': %s",
				      *argv, strerror(errno));
				goto err_free_reuse_maps;
			}
			NEXT_ARG();
		} else if (is_prefix(*argv, "pinmaps")) {
			NEXT_ARG();

			if (!REQ_ARGS(1))
				goto err_free_reuse_maps;

			pinmaps = GET_ARG();
		} else if (is_prefix(*argv, "autoattach")) {
			auto_attach = true;
			NEXT_ARG();
		} else {
			p_err("expected no more arguments, 'type', 'map' or 'dev', got: '%s'?",
			      *argv);
			goto err_free_reuse_maps;
		}
	}

	set_max_rlimit();

	if (verifier_logs)
		/* log_level1 + log_level2 + stats, but not stable UAPI */
		open_opts.kernel_log_level = 1 + 2 + 4;

	obj = bpf_object__open_file(file, &open_opts);
	if (!obj) {
		p_err("failed to open object file");
		goto err_free_reuse_maps;
	}

	bpf_object__for_each_program(pos, obj) {
		enum bpf_prog_type prog_type = common_prog_type;

		if (prog_type == BPF_PROG_TYPE_UNSPEC) {
			const char *sec_name = bpf_program__section_name(pos);

			err = get_prog_type_by_name(sec_name, &prog_type,
						    &expected_attach_type);
			if (err < 0)
				goto err_close_obj;
		}

		bpf_program__set_ifindex(pos, ifindex);
		if (bpf_program__type(pos) != prog_type)
			bpf_program__set_type(pos, prog_type);
		bpf_program__set_expected_attach_type(pos, expected_attach_type);
	}

	qsort(map_replace, old_map_fds, sizeof(*map_replace),
	      map_replace_compar);

	/* After the sort maps by name will be first on the list, because they
	 * have idx == -1.  Resolve them.
	 */
	j = 0;
	while (j < old_map_fds && map_replace[j].name) {
		i = 0;
		bpf_object__for_each_map(map, obj) {
			if (!strcmp(bpf_map__name(map), map_replace[j].name)) {
				map_replace[j].idx = i;
				break;
			}
			i++;
		}
		if (map_replace[j].idx == -1) {
			p_err("unable to find map '%s'", map_replace[j].name);
			goto err_close_obj;
		}
		j++;
	}
	/* Resort if any names were resolved */
	if (j)
		qsort(map_replace, old_map_fds, sizeof(*map_replace),
		      map_replace_compar);

	/* Set ifindex and name reuse */
	j = 0;
	idx = 0;
	bpf_object__for_each_map(map, obj) {
		if (bpf_map__type(map) != BPF_MAP_TYPE_PERF_EVENT_ARRAY)
			bpf_map__set_ifindex(map, ifindex);

		if (j < old_map_fds && idx == map_replace[j].idx) {
			err = bpf_map__reuse_fd(map, map_replace[j++].fd);
			if (err) {
				p_err("unable to set up map reuse: %d", err);
				goto err_close_obj;
			}

			/* Next reuse wants to apply to the same map */
			if (j < old_map_fds && map_replace[j].idx == idx) {
				p_err("replacement for map idx %d specified more than once",
				      idx);
				goto err_close_obj;
			}
		}

		idx++;
	}
	if (j < old_map_fds) {
		p_err("map idx '%d' not used", map_replace[j].idx);
		goto err_close_obj;
	}

	err = bpf_object__load(obj);
	if (err) {
		p_err("failed to load object file");
		goto err_close_obj;
	}

	err = mount_bpffs_for_pin(pinfile);
	if (err)
		goto err_close_obj;

	if (first_prog_only) {
		prog = bpf_object__next_program(obj, NULL);
		if (!prog) {
			p_err("object file doesn't contain any bpf program");
			goto err_close_obj;
		}

		if (auto_attach)
			err = auto_attach_program(prog, pinfile);
		else
			err = bpf_obj_pin(bpf_program__fd(prog), pinfile);
		if (err) {
			p_err("failed to pin program %s",
			      bpf_program__section_name(prog));
			goto err_close_obj;
		}
	} else {
		if (auto_attach)
			err = auto_attach_programs(obj, pinfile);
		else
			err = bpf_object__pin_programs(obj, pinfile);
		if (err) {
			p_err("failed to pin all programs");
			goto err_close_obj;
		}
	}

	if (pinmaps) {
		err = bpf_object__pin_maps(obj, pinmaps);
		if (err) {
			p_err("failed to pin all maps");
			goto err_unpin;
		}
	}

	if (json_output)
		jsonw_null(json_wtr);

	bpf_object__close(obj);
	for (i = 0; i < old_map_fds; i++)
		close(map_replace[i].fd);
	free(map_replace);

	return 0;

err_unpin:
	if (first_prog_only)
		unlink(pinfile);
	else
		bpf_object__unpin_programs(obj, pinfile);
err_close_obj:
	bpf_object__close(obj);
err_free_reuse_maps:
	for (i = 0; i < old_map_fds; i++)
		close(map_replace[i].fd);
	free(map_replace);
	return -1;
}

static int do_load(int argc, char **argv)
{
	if (use_loader)
		return do_loader(argc, argv);
	return load_with_options(argc, argv, true);
}

static int do_loadall(int argc, char **argv)
{
	return load_with_options(argc, argv, false);
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
