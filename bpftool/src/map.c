#include <errno.h>
#include <fcntl.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
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
		"Usage: %1$s %2$s { show | list }   [MAP]\n"
		"       %1$s %2$s create     FILE type TYPE key KEY_SIZE value VALUE_SIZE \\\n"
		"                                  entries MAX_ENTRIES name NAME [flags FLAGS] \\\n"
		"                                  [inner_map MAP] [dev NAME]\n"
		"       %1$s %2$s dump       MAP\n"
		"       %1$s %2$s update     MAP [key DATA] [value VALUE] [UPDATE_FLAGS]\n"
		"       %1$s %2$s lookup     MAP [key DATA]\n"
		"       %1$s %2$s getnext    MAP [key DATA]\n"
		"       %1$s %2$s delete     MAP  key DATA\n"
		"       %1$s %2$s pin        MAP  FILE\n"
		"       %1$s %2$s event_pipe MAP [cpu N index M]\n"
		"       %1$s %2$s peek       MAP\n"
		"       %1$s %2$s push       MAP value VALUE\n"
		"       %1$s %2$s pop        MAP\n"
		"       %1$s %2$s enqueue    MAP value VALUE\n"
		"       %1$s %2$s dequeue    MAP\n"
		"       %1$s %2$s freeze     MAP\n"
		"       %1$s %2$s help\n"
		"\n"
		"       " HELP_SPEC_MAP "\n"
		"       DATA := { [hex] BYTES }\n"
		"       " HELP_SPEC_PROGRAM "\n"
		"       VALUE := { DATA | MAP | PROG }\n"
		"       UPDATE_FLAGS := { any | exist | noexist }\n"
		"       TYPE := { hash | array | prog_array | perf_event_array | percpu_hash |\n"
		"                 percpu_array | stack_trace | cgroup_array | lru_hash |\n"
		"                 lru_percpu_hash | lpm_trie | array_of_maps | hash_of_maps |\n"
		"                 devmap | devmap_hash | sockmap | cpumap | xskmap | sockhash |\n"
		"                 cgroup_storage | reuseport_sockarray | percpu_cgroup_storage |\n"
		"                 queue | stack | sk_storage | struct_ops | ringbuf | inode_storage |\n"
		"                 task_storage | bloom_filter | user_ringbuf | cgrp_storage }\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-f|--bpffs} | {-n|--nomount} }\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static int do_show(int argc, char **argv)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	__u32 id = 0;
	int err;
	int fd;

	if (show_pinned) {
		map_table = hashmap__new(hash_fn_for_key_as_id,
					 equal_fn_for_key_as_id, NULL);
		if (IS_ERR(map_table)) {
			p_err("failed to create hashmap for pinned paths");
			return -1;
		}
		build_pinned_obj_table(map_table, BPF_OBJ_MAP);
	}
	build_obj_refs_table(&refs_table, BPF_OBJ_MAP);

	if (argc == 2)
		return do_show_subset(argc, argv);

	if (argc)
		return BAD_ARG();

	if (json_output)
		jsonw_start_array(json_wtr);
	while (true) {
		err = bpf_map_get_next_id(id, &id);
		if (err) {
			if (errno == ENOENT)
				break;
			p_err("can't get next map: %s%s", strerror(errno),
			      errno == EINVAL ? " -- kernel too old?" : "");
			break;
		}

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			p_err("can't get map by id (%u): %s",
			      id, strerror(errno));
			break;
		}

		err = bpf_map_get_info_by_fd(fd, &info, &len);
		if (err) {
			p_err("can't get map info: %s", strerror(errno));
			close(fd);
			break;
		}

		if (json_output)
			show_map_close_json(fd, &info);
		else
			show_map_close_plain(fd, &info);
	}
	if (json_output)
		jsonw_end_array(json_wtr);

	delete_obj_refs_table(refs_table);

	if (show_pinned)
		delete_pinned_obj_table(map_table);

	return errno == ENOENT ? 0 : -1;
}

int map_parse_fds(int *argc, char ***argv, int **fds)
{
	if (is_prefix(**argv, "id")) {
		unsigned int id;
		char *endptr;

		NEXT_ARGP();

		id = strtoul(**argv, &endptr, 0);
		if (*endptr) {
			p_err("can't parse %s as ID", **argv);
			return -1;
		}
		NEXT_ARGP();

		(*fds)[0] = bpf_map_get_fd_by_id(id);
		if ((*fds)[0] < 0) {
			p_err("get map by id (%u): %s", id, strerror(errno));
			return -1;
		}
		return 1;
	} else if (is_prefix(**argv, "name")) {
		char *name;

		NEXT_ARGP();

		name = **argv;
		if (strlen(name) > BPF_OBJ_NAME_LEN - 1) {
			p_err("can't parse name");
			return -1;
		}
		NEXT_ARGP();

		return map_fd_by_name(name, fds);
	} else if (is_prefix(**argv, "pinned")) {
		char *path;

		NEXT_ARGP();

		path = **argv;
		NEXT_ARGP();

		(*fds)[0] = open_obj_pinned_any(path, BPF_OBJ_MAP);
		if ((*fds)[0] < 0)
			return -1;
		return 1;
	}

	p_err("expected 'id', 'name' or 'pinned', got: '%s'?", **argv);
	return -1;
}

static int do_dump(int argc, char **argv)
{
	json_writer_t *wtr = NULL, *btf_wtr = NULL;
	struct bpf_map_info info = {};
	int nb_fds, i = 0;
	__u32 len = sizeof(info);
	int *fds = NULL;
	int err = -1;

	if (argc != 2)
		usage();

	fds = malloc(sizeof(int));
	if (!fds) {
		p_err("mem alloc failed");
		return -1;
	}
	nb_fds = map_parse_fds(&argc, &argv, &fds);
	if (nb_fds < 1)
		goto exit_free;

	if (json_output) {
		wtr = json_wtr;
	} else {
		int do_plain_btf;

		do_plain_btf = maps_have_btf(fds, nb_fds);
		if (do_plain_btf < 0)
			goto exit_close;

		if (do_plain_btf) {
			btf_wtr = get_btf_writer();
			wtr = btf_wtr;
			if (!btf_wtr)
				p_info("failed to create json writer for btf. falling back to plain output");
		}
	}

	if (wtr && nb_fds > 1)
		jsonw_start_array(wtr);	/* root array */
	for (i = 0; i < nb_fds; i++) {
		if (bpf_map_get_info_by_fd(fds[i], &info, &len)) {
			p_err("can't get map info: %s", strerror(errno));
			break;
		}
		err = map_dump(fds[i], &info, wtr, nb_fds > 1);
		if (!wtr && i != nb_fds - 1)
			printf("\n");

		if (err)
			break;
		close(fds[i]);
	}
	if (wtr && nb_fds > 1)
		jsonw_end_array(wtr);	/* root array */

	if (btf_wtr)
		jsonw_destroy(&btf_wtr);
exit_close:
	for (; i < nb_fds; i++)
		close(fds[i]);
exit_free:
	free(fds);
	btf__free(btf_vmlinux);
	return err;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "help",	do_help },
	{ "dump",	do_dump },
	{ "update",	do_update },
	{ "lookup",	do_lookup },
	{ "getnext",	do_getnext },
	{ "delete",	do_delete },
	{ "pin",	do_pin },
	{ "event_pipe",	do_event_pipe },
	{ "create",	do_create },
	{ "peek",	do_lookup },
	{ "push",	do_update },
	{ "enqueue",	do_update },
	{ "pop",	do_pop_dequeue },
	{ "dequeue",	do_pop_dequeue },
	{ "freeze",	do_freeze },
	{ 0 }
};

int do_map(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
