// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: weirongguang <weirongguang@kylinos.cn>
//
// Based on tcpretrans.py - Brendan Gregg and Matthias Tafelmeier

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tcpretrans.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

const volatile bool do_count = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv4_flow_key_t);
	__type(value, u64);
} ipv4_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv6_flow_key_t);
	__type(value, u64);
} ipv6_count SEC(".maps");

static __always_inline void
tcp_ipv4_count(struct sock *sk, __u16 lport, __u16 dport)
{
	struct ipv4_flow_key_t flow_key = {};
	static __u64 zero;
	__u64 *val;

	BPF_CORE_READ_INTO(&flow_key.saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&flow_key.daddr, sk, __sk_common.skc_daddr);
	flow_key.lport = lport;
	flow_key.dport = dport;
	val = bpf_map_lookup_or_try_init(&ipv4_count, &flow_key, &zero);
	if (!val)
		return;
	__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline void
tcp_ipv4_trace(void *ctx, struct sock *sk, __u32 pid, __u16 lport,
	       __u16 dport, __u8 state, __u64 type)
{
	struct event *data4;

	data4 = reserve_buf(sizeof(*data4));
	if (!data4)
		return;

	data4->af = AF_INET;
	data4->pid = pid;
	data4->ip = 4;
	data4->type = type;
	BPF_CORE_READ_INTO(&data4->saddr_v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&data4->daddr_v4, sk, __sk_common.skc_daddr);
	data4->lport = lport;
	data4->dport = dport;
	data4->state = state;

	submit_buf(ctx, data4, sizeof(*data4));
}
