// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "swapin.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, u64);
} counts SEC(".maps");

SEC("kprobe/swap_readpage")
int BPF_KPROBE(swap_readpage_kprobe)
{
	return handle_swap_readpage();
}

SEC("fentry/swap_readpage")
int BPF_PROG(swap_readpage_fentry)
{
	return handle_swap_readpage();
}

char LICENSE[] SEC("license") = "GPL";

