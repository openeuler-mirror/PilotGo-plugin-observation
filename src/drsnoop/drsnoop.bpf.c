// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "drsnoop.h"

const volatile pid_t target_pid = 0;
const volatile pid_t target_tgid = 0;
const volatile __u64 vm_zone_stat_kaddr = 0;

struct piddata {
	u64 ts;
	u64 nr_free_pages;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct piddata);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static int handle_direct_reclaim_begin()
{
	u64 *vm_zone_stat_kaddrp = (u64 *)vm_zone_stat_kaddr;
	u64 id = bpf_get_current_pid_tgid();
	struct piddata piddata = {};
	u32 tgid = id >> 32;
	u32 pid = id;

	if (target_tgid && target_tgid != tgid)
		return 0;
	if (target_pid && target_pid != pid)
		return 0;

	piddata.ts = bpf_ktime_get_ns();
	if (vm_zone_stat_kaddrp) {
		bpf_core_read(&piddata.nr_free_pages, sizeof(u64),
			      &vm_zone_stat_kaddrp[NR_FREE_PAGES]);
	}

	bpf_map_update_elem(&start, &pid, &piddata, BPF_ANY);
	return 0;
}
