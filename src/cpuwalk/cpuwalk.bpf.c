// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "cpuwalk.h"

struct hist hist = {};

static __always_inline void account_cpu(void)
{
	u64 cpu = bpf_get_smp_processor_id();

	if (cpu >= MAX_CPU_NR)
		cpu = MAX_CPU_NR - 1;

	__sync_fetch_and_add(&hist.slots[cpu], 1);
}

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) == 0)
		return 0;

	account_cpu();

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
