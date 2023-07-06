// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "syscount.h"
#include "maps.bpf.h"

const volatile bool filter_cg = false;
const volatile bool count_by_process = false;
const volatile bool measure_latency = false;
const volatile bool filter_failed = false;
const volatile bool filter_errno = false;
const volatile pid_t filter_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct data_t);
} data SEC(".maps");

static __always_inline void save_proc_name(struct data_t *val)
{
	struct task_struct *current = (void *)bpf_get_current_task();

	BPF_CORE_READ_STR_INTO(&val->comm, current, group_leader, comm);
}