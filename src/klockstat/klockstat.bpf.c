// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "klockstat.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

const volatile pid_t target_pid = 0;
const volatile pid_t target_tgid = 0;
void *const volatile target_lock = NULL;


struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, MAX_ENTRIES);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
} stack_map SEC(".maps");

/*
 * Uniquely identifies a task grabbing a particular lock; a task can only hold
 * the same lock once (non-recursive mutexes).
 */
struct task_lock {
	u64 task_id;
	u64 lock_ptr;
};

struct lockholder_info {
	s32 stack_id;
	u64 task_id;
	u64 try_at;
	u64 acq_at;
	u64 rel_at;
	u64 lock_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct task_lock);
	__type(value, struct lockholder_info);
} lockholder_map SEC(".maps");

/*
 * keyed by stack_id
 *
 * Multiple call sites may have the same underlying lock, but we only know the
 * stats for a particular stack frame. multiple tasks may have the same
 * stackframe.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, s32);
	__type(value, struct lock_stat);
} stat_map SEC(".maps");

static bool tracing_task(u64 task_id)
{
	u32 tgid = task_id >> 32;
	u32 pid = task_id;

	if (target_tgid && target_tgid != tgid)
		return false;
	if (target_pid && target_pid != pid)
		return false;
	return true;
}

static void lock_contended(void *ctx, void *lock)
{
	u64 task_id;
	struct lockholder_info li = {};
	struct task_lock tl = {};

	if (target_lock && target_lock != lock)
		return;

	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;

	li.task_id = task_id;
	li.lock_ptr = (u64)lock;

	/*
	 * Skip 4 frames, e.g.:
	 *	__this_module+0x34ef
	 *	__this_module+0x34ef
	 *	__this_module+0x34ef
	 *	      mutex_lock+0x5
	 *
	 * Note: If you make major changes to this bpf program, double check
	 * that you aren't skipping too many frames.
	 */
	li.stack_id = bpf_get_stackid(ctx, &stack_map, 0 | BPF_F_FAST_STACK_CMP);

	/* legit failures include EEXIST */
	if (li.stack_id < 0)
		return;
	li.try_at = bpf_ktime_get_ns();

	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	bpf_map_update_elem(&lockholder_map, &tl, &li, BPF_ANY);
}

static void lock_aborted(void *lock)
{
	u64 task_id;
	struct task_lock tl = {};

	if (target_lock && target_lock != lock)
		return;

	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;
	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	bpf_map_delete_elem(&lockholder_map, &tl);
}

static void lock_acquired(void *lock)
{
	u64 task_id;
	struct lockholder_info *li;
	struct task_lock tl = {};

	if (target_lock && target_lock != lock)
		return;

	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;
	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	li = bpf_map_lookup_elem(&lockholder_map, &tl);
	if (!li)
		return;

	li->acq_at = bpf_ktime_get_ns();
}
