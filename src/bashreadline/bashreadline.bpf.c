// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bashreadline.h"

#define TASK_COMM_LEN	16

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline bool current_comm_is_bash(void)
{
	char comm[TASK_COMM_LEN];

	bpf_get_current_comm(&comm, sizeof(comm));
	return comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' &&
	       comm[3] == 'h' && comm[4] == 0;
}

SEC("uretprobe/readline")
int BPF_KRETPROBE(printret, const void *ret)
{
	readline_str_t data;

	if (!ret)
		return 0;

	if (!current_comm_is_bash())
		return 0;

	data.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_core_read_user_str(&data.str, sizeof(data.str), ret);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
