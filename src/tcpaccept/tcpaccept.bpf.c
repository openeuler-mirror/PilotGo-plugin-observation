// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: weirongguang <weirongguang@kylinos.cn>
//
// Based on tcpaccept.py - 2015 Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tcpaccept.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

#define MAX_PORTS	1024

const volatile pid_t trace_pid = 0;
const volatile bool filter_by_port = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PORTS);
	__type(key, __u16);
	__type(value, __u16);
} ports SEC(".maps");

static __always_inline void
tcp_ipv4_trace(void *ctx, struct sock *sk, __u32 pid, __u16 lport, __u16 dport)
{
	struct data_t *data4;

	data4 = reserve_buf(sizeof(*data4));
	if (!data4)
		return;

	data4->af = AF_INET;
	data4->pid = pid;
	data4->ip = 4;
	BPF_CORE_READ_INTO(&data4->saddr_v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&data4->daddr_v4, sk, __sk_common.skc_daddr);
	data4->lport = lport;
	data4->dport = dport;
	bpf_get_current_comm(&data4->task, sizeof(data4->task));

	submit_buf(ctx, data4, sizeof(*data4));
}
