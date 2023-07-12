// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "core_fixes.bpf.h"
#include "runqslower.h"

#define TASK_RUNNING 0
#define BPF_F_CURRENT_CPU 0xffffffffULL

const volatile __u64 min_us = 0;
const volatile pid_t target_pid = 0;
const volatile pid_t target_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/* record enqueue timestamp */
__always_inline
static int trace_enqueue(struct task_struct *p)
{
	u32 pid = BPF_CORE_READ(p, pid);
	u32 tgid = BPF_CORE_READ(p, tgid);
	u64 ts;

	if (!pid)
		return 0;
	if (target_pid && target_pid != pid)
		return 0;
	if (target_tgid && target_tgid != tgid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid, &ts, 0);
	return 0;
}