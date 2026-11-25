// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

const volatile pid_t target_tgid = 0;
const volatile int units = 0;
const volatile bool filter_memcg = false;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

/* key: pid. value: start time */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PIDS);
	__type(key, u32);
	__type(value, u64);
} starts SEC(".maps");

__u32 hists[MAX_SLOTS] = {};

static __always_inline bool trace_filtered(u32 tgid)
{
	if (filter_memcg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return true;

	if (target_tgid && target_tgid != tgid)
		return true;

	return false;
}

static __always_inline bool exit_filtered(void)
{
	if (filter_memcg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return true;

	return false;
}

static int entry(void)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 pid = (pid_t)id;
	u64 nsec;

	if (trace_filtered(tgid))
		return 0;

	nsec = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);

	return 0;
}

SEC("fentry/dummy_fentry")
int BPF_PROG(dummy_fentry)
{
	return entry();
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{
	return entry();
}

static __always_inline u64 normalize_delta(u64 delta)
{
	switch (units) {
	case USEC:
		return delta / 1000;
	case MSEC:
		return delta / 1000000;
	default:
		return delta;
	}
}

static __always_inline void record_slot(u64 delta)
{
	u64 slot = log2l(delta);

	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hists[slot], 1);
}

static int exit(void)
{
	u64 *start;
	u64 nsec = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = (pid_t)id;
	u64 delta;

	if (exit_filtered())
		return 0;

	start = bpf_map_lookup_elem(&starts, &pid);
	if (!start)
		return 0;

	delta = nsec - *start;

	record_slot(normalize_delta(delta));

	return 0;
}

SEC("fexit/dummy_fexit")
int BPF_PROG(dummy_fexit)
{
	return exit();
}

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe)
{
	return exit();
}

char LICENSE[] SEC("license") = "GPL";
