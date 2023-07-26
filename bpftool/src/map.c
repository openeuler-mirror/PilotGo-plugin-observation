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

static int parse_elem(char **argv, struct bpf_map_info *info,
		      void *key, void *value, __u32 key_size, __u32 value_size,
		      __u32 *flags, __u32 **value_fd)
{
	if (!*argv) {
		if (!key && !value)
			return 0;
		p_err("did not find %s", key ? "key" : "value");
		return -1;
	}

	if (is_prefix(*argv, "key")) {
		if (!key) {
			if (key_size)
				p_err("duplicate key");
			else
				p_err("unnecessary key");
			return -1;
		}

		argv = parse_bytes(argv + 1, "key", key, key_size);
		if (!argv)
			return -1;

		return parse_elem(argv, info, NULL, value, key_size, value_size,
				  flags, value_fd);
	} else if (is_prefix(*argv, "value")) {
		int fd;

		if (!value) {
			if (value_size)
				p_err("duplicate value");
			else
				p_err("unnecessary value");
			return -1;
		}

		argv++;

		if (map_is_map_of_maps(info->type)) {
			int argc = 2;

			if (value_size != 4) {
				p_err("value smaller than 4B for map in map?");
				return -1;
			}
			if (!argv[0] || !argv[1]) {
				p_err("not enough value arguments for map in map");
				return -1;
			}

			fd = map_parse_fd(&argc, &argv);
			if (fd < 0)
				return -1;

			*value_fd = value;
			**value_fd = fd;
		} else if (map_is_map_of_progs(info->type)) {
			int argc = 2;

			if (value_size != 4) {
				p_err("value smaller than 4B for map of progs?");
				return -1;
			}
			if (!argv[0] || !argv[1]) {
				p_err("not enough value arguments for map of progs");
				return -1;
			}
			if (is_prefix(*argv, "id"))
				p_info("Warning: updating program array via MAP_ID, make sure this map is kept open\n"
				       "         by some process or pinned otherwise update will be lost");

			fd = prog_parse_fd(&argc, &argv);
			if (fd < 0)
				return -1;

			*value_fd = value;
			**value_fd = fd;
		} else {
			argv = parse_bytes(argv, "value", value, value_size);
			if (!argv)
				return -1;

			fill_per_cpu_value(info, value);
		}

		return parse_elem(argv, info, key, NULL, key_size, value_size,
				  flags, NULL);
	} else if (is_prefix(*argv, "any") || is_prefix(*argv, "noexist") ||
		   is_prefix(*argv, "exist")) {
		if (!flags) {
			p_err("flags specified multiple times: %s", *argv);
			return -1;
		}

		if (is_prefix(*argv, "any"))
			*flags = BPF_ANY;
		else if (is_prefix(*argv, "noexist"))
			*flags = BPF_NOEXIST;
		else if (is_prefix(*argv, "exist"))
			*flags = BPF_EXIST;

		return parse_elem(argv + 1, info, key, value, key_size,
				  value_size, NULL, value_fd);
	}

	p_err("expected key or value, got: %s", *argv);
	return -1;
}

static void print_entry_json(struct bpf_map_info *info, unsigned char *key,
			     unsigned char *value, struct btf *btf)
{
	jsonw_start_object(json_wtr);

	if (!map_is_per_cpu(info->type)) {
		jsonw_name(json_wtr, "key");
		print_hex_data_json(key, info->key_size);
		jsonw_name(json_wtr, "value");
		print_hex_data_json(value, info->value_size);
		if (btf) {
			struct btf_dumper d = {
				.btf = btf,
				.jw = json_wtr,
				.is_plain_text = false,
			};

			jsonw_name(json_wtr, "formatted");
			do_dump_btf(&d, info, key, value);
		}
	} else {
		unsigned int i, n, step;

		n = get_possible_cpus();
		step = round_up(info->value_size, 8);

		jsonw_name(json_wtr, "key");
		print_hex_data_json(key, info->key_size);

		jsonw_name(json_wtr, "values");
		jsonw_start_array(json_wtr);
		for (i = 0; i < n; i++) {
			jsonw_start_object(json_wtr);

			jsonw_int_field(json_wtr, "cpu", i);

			jsonw_name(json_wtr, "value");
			print_hex_data_json(value + i * step,
					    info->value_size);

			jsonw_end_object(json_wtr);
		}
		jsonw_end_array(json_wtr);
		if (btf) {
			struct btf_dumper d = {
				.btf = btf,
				.jw = json_wtr,
				.is_plain_text = false,
			};

			jsonw_name(json_wtr, "formatted");
			do_dump_btf(&d, info, key, value);
		}
	}

	jsonw_end_object(json_wtr);
}


static int dump_map_elem(int fd, void *key, void *value,
			 struct bpf_map_info *map_info, struct btf *btf,
			 json_writer_t *btf_wtr)
{
	if (bpf_map_lookup_elem(fd, key, value)) {
		print_entry_error(map_info, key, errno);
		return -1;
	}

	if (json_output) {
		print_entry_json(map_info, key, value, btf);
	} else if (btf) {
		struct btf_dumper d = {
			.btf = btf,
			.jw = btf_wtr,
			.is_plain_text = true,
		};

		do_dump_btf(&d, map_info, key, value);
	} else {
		print_entry_plain(map_info, key, value);
	}

	return 0;
}

static json_writer_t *get_btf_writer(void)
{
	json_writer_t *jw = jsonw_new(stdout);

	if (!jw)
		return NULL;
	jsonw_pretty(jw, true);

	return jw;
}

static int maps_have_btf(int *fds, int nb_fds)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	int err, i;

	for (i = 0; i < nb_fds; i++) {
		err = bpf_map_get_info_by_fd(fds[i], &info, &len);
		if (err) {
			p_err("can't get map info: %s", strerror(errno));
			return -1;
		}

		if (!info.btf_id)
			return 0;
	}

	return 1;
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

static int get_map_kv_btf(const struct bpf_map_info *info, struct btf **btf)
{
	int err = 0;

	if (info->btf_vmlinux_value_type_id) {
		if (!btf_vmlinux) {
			btf_vmlinux = libbpf_find_kernel_btf();
			if (!btf_vmlinux) {
				p_err("failed to get kernel btf");
				return -errno;
			}
		}
		*btf = btf_vmlinux;
	} else if (info->btf_value_type_id) {
		*btf = btf__load_from_kernel_by_id(info->btf_id);
		if (!*btf) {
			err = -errno;
			p_err("failed to get btf");
		}
	} else {
		*btf = NULL;
	}

	return err;
}

static void free_map_kv_btf(struct btf *btf)
{
	if (btf != btf_vmlinux)
		btf__free(btf);
}

static int
map_dump(int fd, struct bpf_map_info *info, json_writer_t *wtr,
	 bool show_header)
{
	void *key, *value, *prev_key;
	unsigned int num_elems = 0;
	struct btf *btf = NULL;
	int err;

	key = malloc(info->key_size);
	value = alloc_value(info);
	if (!key || !value) {
		p_err("mem alloc failed");
		err = -1;
		goto exit_free;
	}

	prev_key = NULL;

	if (wtr) {
		err = get_map_kv_btf(info, &btf);
		if (err) {
			goto exit_free;
		}

		if (show_header) {
			jsonw_start_object(wtr);	/* map object */
			show_map_header_json(info, wtr);
			jsonw_name(wtr, "elements");
		}
		jsonw_start_array(wtr);		/* elements */
	} else if (show_header) {
		show_map_header_plain(info);
	}

	if (info->type == BPF_MAP_TYPE_REUSEPORT_SOCKARRAY &&
	    info->value_size != 8) {
		const char *map_type_str;

		map_type_str = libbpf_bpf_map_type_str(info->type);
		p_info("Warning: cannot read values from %s map with value_size != 8",
		       map_type_str);
	}
	while (true) {
		err = bpf_map_get_next_key(fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
		if (!dump_map_elem(fd, key, value, info, btf, wtr))
			num_elems++;
		prev_key = key;
	}

	if (wtr) {
		jsonw_end_array(wtr);	/* elements */
		if (show_header)
			jsonw_end_object(wtr);	/* map object */
	} else {
		printf("Found %u element%s\n", num_elems,
		       num_elems != 1 ? "s" : "");
	}

exit_free:
	free(key);
	free(value);
	close(fd);
	free_map_kv_btf(btf);

	return err;
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

static int alloc_key_value(struct bpf_map_info *info, void **key, void **value)
{
	*key = NULL;
	*value = NULL;

	if (info->key_size) {
		*key = malloc(info->key_size);
		if (!*key) {
			p_err("key mem alloc failed");
			return -1;
		}
	}

	if (info->value_size) {
		*value = alloc_value(info);
		if (!*value) {
			p_err("value mem alloc failed");
			free(*key);
			*key = NULL;
			return -1;
		}
	}

	return 0;
}

static int do_update(int argc, char **argv)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	__u32 *value_fd = NULL;
	__u32 flags = BPF_ANY;
	void *key, *value;
	int fd, err;

	if (argc < 2)
		usage();

	fd = map_parse_fd_and_info(&argc, &argv, &info, &len);
	if (fd < 0)
		return -1;

	err = alloc_key_value(&info, &key, &value);
	if (err)
		goto exit_free;

	err = parse_elem(argv, &info, key, value, info.key_size,
			 info.value_size, &flags, &value_fd);
	if (err)
		goto exit_free;

	err = bpf_map_update_elem(fd, key, value, flags);
	if (err) {
		p_err("update failed: %s", strerror(errno));
		goto exit_free;
	}

exit_free:
	if (value_fd)
		close(*value_fd);
	free(key);
	free(value);
	close(fd);

	if (!err && json_output)
		jsonw_null(json_wtr);
	return err;
}

static int do_lookup(int argc, char **argv)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	void *key, *value;
	int err;
	int fd;

	if (argc < 2)
		usage();

	fd = map_parse_fd_and_info(&argc, &argv, &info, &len);
	if (fd < 0)
		return -1;

	err = alloc_key_value(&info, &key, &value);
	if (err)
		goto exit_free;

	err = parse_elem(argv, &info, key, NULL, info.key_size, 0, NULL, NULL);
	if (err)
		goto exit_free;

	err = bpf_map_lookup_elem(fd, key, value);
	if (err) {
		if (errno == ENOENT) {
			if (json_output) {
				jsonw_null(json_wtr);
			} else {
				printf("key:\n");
				fprint_hex(stdout, key, info.key_size, " ");
				printf("\n\nNot found\n");
			}
		} else {
			p_err("lookup failed: %s", strerror(errno));
		}

		goto exit_free;
	}

	/* here means bpf_map_lookup_elem() succeeded */
	print_key_value(&info, key, value);

exit_free:
	free(key);
	free(value);
	close(fd);

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
