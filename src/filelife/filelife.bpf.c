// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "filelife.h"
#include "core_fixes.bpf.h"

/* linux: include/linux/fs.h */
#define FMODE_CREATED	0x100000

const volatile pid_t target_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dentry *);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool tgid_filtered(void)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;

	return target_tgid && target_tgid != tgid;
}

static __always_inline int probe_create(struct dentry *dentry)
{
	u64 ts;

	if (tgid_filtered())
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &dentry, &ts, BPF_ANY);

	return 0;
}

/*
 * In different kernel versions, function vfs_create() has two declarations,
 * and their parameter lists are as follows:
 *
 * int vfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
 *		  bool want_excl);
 * int vfs_create(struct user_namespace *mnt_userns, struct inode *dir,
 *		  struct dentry *dentry, umode_t mode, bool want_excl);
 */
SEC("kprobe/vfs_create")
int BPF_KPROBE(vfs_create, void *arg0, void *arg1, void *arg2)
{
	if (renamedata_has_old_mnt_userns_field())
		return probe_create(arg2);
	else
		return probe_create(arg1);
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, struct path *path, struct file *file)
{
	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	int fmode = BPF_CORE_READ(file, f_mode);

	if (!(fmode & FMODE_CREATED))
		return 0;

	return probe_create(dentry);
}

SEC("kprobe/security_inode_create")
int BPF_KPROBE(security_inode_create, struct inode *dir,
	       struct dentry *dentry)
{
	return probe_create(dentry);
}

static __always_inline struct dentry *unlink_dentry(void *arg1, void *arg2,
						    bool has_mnt_userns)
{
	return has_mnt_userns ? arg2 : arg1;
}

static __always_inline void fill_unlink_event(struct event *event,
					      struct dentry *dentry, u64 delta_ns)
{
	const u8 *qs_name_ptr;
	u64 id = bpf_get_current_pid_tgid();

	qs_name_ptr = BPF_CORE_READ(dentry, d_name.name);
	bpf_core_read_str(&event->file, sizeof(event->file), qs_name_ptr);
	bpf_get_current_comm(&event->task, sizeof(event->task));
	event->delta_ns = delta_ns;
	event->tgid = id >> 32;
}

/*
 * In different kernel versions, function vfs_unlink() has two declarations,
 * and their parameter lists are as follows:
 *
 * int vfs_unlink(struct inode *dir, struct dentry *dentry,
 *		  struct inode **delegated_inode);
 * int vfs_unlink(struct user_namespace *mnt_userns, struct inode *dir,
 *		  struct dentry *dentry, struct inode **delegated_inode);
 */
SEC("kprobe/vfs_unlink")
int BPF_KPROBE(vfs_unlink, void *arg0, void *arg1, void *arg2)
{
	bool has_mnt_userns = renamedata_has_old_mnt_userns_field();
	struct dentry *dentry = unlink_dentry(arg1, arg2, has_mnt_userns);
	struct event event = {};
	u64 *tsp, delta_ns;

	tsp = bpf_map_lookup_elem(&start, &dentry);
	if (!tsp)
		return 0;

	delta_ns = bpf_ktime_get_ns() - *tsp;
	bpf_map_delete_elem(&start, &dentry);

	fill_unlink_event(&event, dentry, delta_ns);

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
