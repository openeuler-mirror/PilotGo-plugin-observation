// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>
#include <bpf/bpf_core_read.h>
#include "javagc.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100);
	__type(key, uint32_t);
	__type(value, struct data_t);
} data_map SEC(".maps");

__u64 time = 0;

static __always_inline int gc_start(void)
{
	struct data_t data = {};

	data.cpu = bpf_get_smp_processor_id();
	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&data_map, &data.pid, &data, BPF_ANY);

	return 0;
}