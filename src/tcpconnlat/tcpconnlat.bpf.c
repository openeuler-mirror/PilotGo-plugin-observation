// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "tcpconnlat.h"

#include "compat.bpf.h"
#include "maps.bpf.h"

#define AF_INET		2
#define AF_INET6	10

const volatile __u64 target_min_us = 0;
const volatile pid_t target_tgid = 0;

struct piddata {
	char comm[TASK_COMM_LEN];
	u64 ts;
	u32 tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sock *);
	__type(value, struct piddata);
} start SEC(".maps");

static int trace_connect(struct sock *sock)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct piddata piddata = {};

	if (target_tgid && target_tgid != tgid)
		return 0;

	bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
	piddata.ts = bpf_ktime_get_ns();
	piddata.tgid = tgid;
	bpf_map_update_elem(&start, &sock, &piddata, BPF_ANY);
	return 0;
}

static int cleanup_sock(struct sock *sock)
{
	bpf_map_delete_elem(&start, &sock);
	return 0;
}
