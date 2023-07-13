// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hardirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	256

const volatile bool filter_memcg = false;
const volatile bool target_dist = false;
const volatile bool target_ns = false;
const volatile bool do_count = false;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, irq_key_t);
	__type(value, info_t);
} infos SEC(".maps");

static info_t zero;

static int handle_entry(int irq, struct irqaction *action)
{
	if (filter_memcg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (do_count) {
		irq_key_t key = {};
		info_t *info;

		bpf_probe_read_kernel_str(&key.name, sizeof(key.name), BPF_CORE_READ(action, name));
		info = bpf_map_lookup_or_try_init(&infos, &key, &zero);
		if (!info)
			return 0;
		info->count += 1;
	} else {
		u64 ts = bpf_ktime_get_ns();
		u32 key = 0;

		bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
	}

	return 0;
}