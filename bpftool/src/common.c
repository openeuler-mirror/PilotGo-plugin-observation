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

int build_pinned_obj_table(struct hashmap *tab,
			   enum bpf_obj_type type)
{
	struct mntent *mntent = NULL;
	FILE *mntfile = NULL;
	int flags = FTW_PHYS;
	int nopenfd = 16;
	int err = 0;

	mntfile = setmntent("/proc/mounts", "r");
	if (!mntfile)
		return -1;

	build_fn_table = tab;
	build_fn_type = type;

	while ((mntent = getmntent(mntfile))) {
		char *path = mntent->mnt_dir;

		if (strncmp(mntent->mnt_type, "bpf", 3) != 0)
			continue;
		err = nftw(path, do_build_table_cb, nopenfd, flags);
		if (err)
			break;
	}
	fclose(mntfile);
	return err;
}

size_t hash_fn_for_key_as_id(long key, void *ctx)
{
	return key;
}

bool equal_fn_for_key_as_id(long k1, long k2, void *ctx)
{
	return k1 == k2;
}

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

int build_pinned_obj_table(struct hashmap *tab,
			   enum bpf_obj_type type)
{
	struct mntent *mntent = NULL;
	FILE *mntfile = NULL;
	int flags = FTW_PHYS;
	int nopenfd = 16;
	int err = 0;

	mntfile = setmntent("/proc/mounts", "r");
	if (!mntfile)
		return -1;

	build_fn_table = tab;
	build_fn_type = type;

	while ((mntent = getmntent(mntfile))) {
		char *path = mntent->mnt_dir;

		if (strncmp(mntent->mnt_type, "bpf", 3) != 0)
			continue;
		err = nftw(path, do_build_table_cb, nopenfd, flags);
		if (err)
			break;
	}
	fclose(mntfile);
	return err;
}

bool equal_fn_for_key_as_id(long k1, long k2, void *ctx)
{
	return k1 == k2;
}