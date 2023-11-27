// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (c) 2020 Facebook
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* map of perf event fds, num_cpu * num_metric entries */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

/* readings at fentry */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct bpf_perf_event_value));
} fentry_readings SEC(".maps");

/* accumulated readings */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct bpf_perf_event_value));
} accum_readings SEC(".maps");

/* sample counts, one per cpu */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
} counts SEC(".maps");

const volatile __u32 num_cpu = 1;
const volatile __u32 num_metric = 1;
#define MAX_NUM_MATRICS 4

SEC("fentry/XXX")
int BPF_PROG(fentry_XXX)
{
	struct bpf_perf_event_value *ptrs[MAX_NUM_MATRICS];
	u32 key = bpf_get_smp_processor_id();
	u32 i;

	/* look up before reading, to reduce error */
	for (i = 0; i < num_metric && i < MAX_NUM_MATRICS; i++) {
		u32 flag = i;

		ptrs[i] = bpf_map_lookup_elem(&fentry_readings, &flag);
		if (!ptrs[i])
			return 0;
	}

	for (i = 0; i < num_metric && i < MAX_NUM_MATRICS; i++) {
		struct bpf_perf_event_value reading;
		int err;

		err = bpf_perf_event_read_value(&events, key, &reading,
						sizeof(reading));
		if (err)
			return 0;
		*(ptrs[i]) = reading;
		key += num_cpu;
	}

	return 0;
}
