#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <mntent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <linux/unistd.h>

#include <bpf/bpf.h>
#include <bpf/hashmap.h>
#include <bpf/libbpf.h> /* libbpf_num_possible_cpus */
#include <bpf/btf.h>

#include "main.h"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC		0xcafe4a11
#endif

void p_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (json_output) {
		jsonw_start_object(json_wtr);
		jsonw_name(json_wtr, "error");
		jsonw_vprintf_enquote(json_wtr, fmt, ap);
		jsonw_end_object(json_wtr);
	} else {
		fprintf(stderr, "Error: ");
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);
}

int __printf(2, 0)
print_all_levels(__maybe_unused enum libbpf_print_level level,
		 const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

void delete_pinned_obj_table(struct hashmap *map)
{
	struct hashmap_entry *entry;
	size_t bkt;

	if (!map)
		return;

	hashmap__for_each_entry(map, entry, bkt)
		free(entry->pvalue);

	hashmap__free(map);
}

static int
mnt_fs(const char *target, const char *type, char *buff, size_t bufflen)
{
	bool bind_done = false;

	while (mount("", target, "none", MS_PRIVATE | MS_REC, NULL)) {
		if (errno != EINVAL || bind_done) {
			snprintf(buff, bufflen,
				 "mount --make-private %s failed: %s",
				 target, strerror(errno));
			return -1;
		}

		if (mount(target, target, "none", MS_BIND, NULL)) {
			snprintf(buff, bufflen,
				 "mount --bind %s %s failed: %s",
				 target, target, strerror(errno));
			return -1;
		}

		bind_done = true;
	}

	if (mount(type, target, type, 0, "mode=0700")) {
		snprintf(buff, bufflen, "mount -t %s %s %s failed: %s",
			 type, type, target, strerror(errno));
		return -1;
	}

	return 0;
}

static bool known_to_need_rlimit(void)
{
	struct rlimit rlim_init, rlim_cur_zero = {};
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	size_t insn_cnt = ARRAY_SIZE(insns);
	union bpf_attr attr;
	int prog_fd, err;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insns = ptr_to_u64(insns);
	attr.insn_cnt = insn_cnt;
	attr.license = ptr_to_u64("GPL");

	if (getrlimit(RLIMIT_MEMLOCK, &rlim_init))
		return false;

	rlim_cur_zero.rlim_max = rlim_init.rlim_max;
	if (setrlimit(RLIMIT_MEMLOCK, &rlim_cur_zero))
		return false;

	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	err = errno;

	setrlimit(RLIMIT_MEMLOCK, &rlim_init);

	if (prog_fd < 0)
		return err == EPERM;

	close(prog_fd);
	return false;
}

int open_obj_pinned(const char *path, bool quiet)
{
	char *pname;
	int fd = -1;

	pname = strdup(path);
	if (!pname) {
		if (!quiet)
			p_err("mem alloc failed");
		goto out_ret;
	}

	fd = bpf_obj_get(pname);
	if (fd < 0) {
		if (!quiet)
			p_err("bpf obj get (%s): %s", pname,
			      errno == EACCES && !is_bpffs(dirname(pname)) ?
			    "directory not in bpf file system (bpffs)" :
			    strerror(errno));
		goto out_free;
	}

out_free:
	free(pname);
out_ret:
	return fd;
}

void set_max_rlimit(void)
{
	struct rlimit rinf = { RLIM_INFINITY, RLIM_INFINITY };

	if (known_to_need_rlimit())
		setrlimit(RLIMIT_MEMLOCK, &rinf);
}

int open_obj_pinned_any(const char *path, enum bpf_obj_type exp_type)
{
	enum bpf_obj_type type;
	int fd;

	fd = open_obj_pinned(path, false);
	if (fd < 0)
		return -1;

	type = get_fd_type(fd);
	if (type < 0) {
		close(fd);
		return type;
	}
	if (type != exp_type) {
		p_err("incorrect object type: %s", get_fd_type_name(type));
		close(fd);
		return -1;
	}

	return fd;
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


int map_parse_fd(int *argc, char ***argv)
{
	int *fds = NULL;
	int nb_fds, fd;

	fds = malloc(sizeof(int));
	if (!fds) {
		p_err("mem alloc failed");
		return -1;
	}
	nb_fds = map_parse_fds(argc, argv, &fds);
	if (nb_fds != 1) {
		if (nb_fds > 1) {
			p_err("several maps match this handle");
			while (nb_fds--)
				close(fds[nb_fds]);
		}
		fd = -1;
		goto exit_free;
	}

	fd = fds[0];
exit_free:
	free(fds);
	return fd;
}

int mount_bpffs_for_pin(const char *name)
{
	char err_str[ERR_MAX_LEN];
	char *file;
	char *dir;
	int err = 0;

	file = malloc(strlen(name) + 1);
	if (!file) {
		p_err("mem alloc failed");
		return -1;
	}

	strcpy(file, name);
	dir = dirname(file);

	if (is_bpffs(dir))
		/* nothing to do if already mounted */
		goto out_free;

	if (block_mount) {
		p_err("no BPF file system found, not mounting it due to --nomount option");
		err = -1;
		goto out_free;
	}

	err = mnt_fs(dir, "bpf", err_str, ERR_MAX_LEN);
	if (err) {
		err_str[ERR_MAX_LEN - 1] = '\0';
		p_err("can't mount BPF file system to pin the object (%s): %s",
		      name, err_str);
	}

out_free:
	free(file);
	return err;
}

int do_pin_fd(int fd, const char *name)
{
	int err;

	err = mount_bpffs_for_pin(name);
	if (err)
		return err;

	err = bpf_obj_pin(fd, name);
	if (err)
		p_err("can't pin the object (%s): %s", name, strerror(errno));

	return err;
}

int do_pin_any(int argc, char **argv, int (*get_fd)(int *, char ***))
{
	int err;
	int fd;

	if (!REQ_ARGS(3))
		return -EINVAL;

	fd = get_fd(&argc, &argv);
	if (fd < 0)
		return fd;

	err = do_pin_fd(fd, *argv);

	close(fd);
	return err;
}

int prog_parse_fds(int *argc, char ***argv, int **fds)
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

		(*fds)[0] = bpf_prog_get_fd_by_id(id);
		if ((*fds)[0] < 0) {
			p_err("get by id (%u): %s", id, strerror(errno));
			return -1;
		}
		return 1;
	} else if (is_prefix(**argv, "tag")) {
		unsigned char tag[BPF_TAG_SIZE];

		NEXT_ARGP();

		if (sscanf(**argv, BPF_TAG_FMT, tag, tag + 1, tag + 2,
			   tag + 3, tag + 4, tag + 5, tag + 6, tag + 7)
		    != BPF_TAG_SIZE) {
			p_err("can't parse tag");
			return -1;
		}
		NEXT_ARGP();

		return prog_fd_by_nametag(tag, fds, true);
	} else if (is_prefix(**argv, "name")) {
		char *name;

		NEXT_ARGP();

		name = **argv;
		if (strlen(name) > MAX_PROG_FULL_NAME - 1) {
			p_err("can't parse name");
			return -1;
		}
		NEXT_ARGP();

		return prog_fd_by_nametag(name, fds, false);
	} else if (is_prefix(**argv, "pinned")) {
		char *path;

		NEXT_ARGP();

		path = **argv;
		NEXT_ARGP();

		(*fds)[0] = open_obj_pinned_any(path, BPF_OBJ_PROG);
		if ((*fds)[0] < 0)
			return -1;
		return 1;
	}

	p_err("expected 'id', 'tag', 'name' or 'pinned', got: '%s'?", **argv);
	return -1;
}

int prog_parse_fd(int *argc, char ***argv)
{
	int *fds = NULL;
	int nb_fds, fd;

	fds = malloc(sizeof(int));
	if (!fds) {
		p_err("mem alloc failed");
		return -1;
	}
	nb_fds = prog_parse_fds(argc, argv, &fds);
	if (nb_fds != 1) {
		if (nb_fds > 1) {
			p_err("several programs match this handle");
			while (nb_fds--)
				close(fds[nb_fds]);
		}
		fd = -1;
		goto exit_free;
	}

	fd = fds[0];
exit_free:
	free(fds);
	return fd;
}