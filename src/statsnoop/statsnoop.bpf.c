// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "statsnoop.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "compat.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;
const volatile bool trace_failed_only = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, const char *);
} values SEC(".maps");

static __always_inline int probe_entry(void *ctx, const char *pathname)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;
	__u32 tid = (__u32)id;

	if (!pathname)
		return 0;

	if (target_pid && target_pid != pid)
		return 0;

	bpf_map_update_elem(&values, &tid, &pathname, BPF_ANY);
	return 0;
}

