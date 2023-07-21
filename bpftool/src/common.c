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