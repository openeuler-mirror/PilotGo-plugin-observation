// SPDX-License-Identifier: GPL-3.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "wakeuptime.h"
#include "maps.bpf.h"

#define PF_KTHREAD	0x00200000 /* kernel thread */

const volatile pid_t target_pid = 0;
const volatile __u64 max_block_ns = -1;
const volatile __u64 min_block_ns = 1;
const volatile bool user_threads_only = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, u64);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

static int offcpu_sched_switch(struct task_struct *prev)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid >> 32;
	pid_t tid = (pid_t)pid_tgid;
	u64 ts;

	if (target_pid && target_pid != pid)
		return 0;

	if (user_threads_only && BPF_CORE_READ(prev, flags) & PF_KTHREAD)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);

	return 0;
}

static int wakeup(void *ctx, struct task_struct *p)
{
	u32 pid = BPF_CORE_READ(p, tgid);
	u32 tid = BPF_CORE_READ(p, pid);
	u64 delta, *count_key, *tsp;
	static const u64 zero;
	struct key_t key = {};

	if (target_pid && target_pid != pid)
		return 0;

	tsp = bpf_map_lookup_elem(&start, &tid);
	if (!tsp)
		return 0;
	bpf_map_delete_elem(&start, &tid);
	delta = bpf_ktime_get_ns() - *tsp;
	if ((delta < min_block_ns) || (delta > max_block_ns))
		return 0;

	key.wake_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
	BPF_CORE_READ_STR_INTO(&key.target, p, comm);
	bpf_get_current_comm(&key.waker, sizeof(key.waker));

	count_key = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (count_key)
		__atomic_add_fetch(count_key, delta, __ATOMIC_RELAXED);

	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_btf, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return offcpu_sched_switch(prev);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch_raw, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return offcpu_sched_switch(prev);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup_btf, struct task_struct *p)
{
	return wakeup(ctx, p);
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(sched_wakeup_raw, struct task_struct *p)
{
	return wakeup(ctx, p);
}

char LICENSE[] SEC("license") = "GPL";

