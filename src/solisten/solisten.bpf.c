// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "solisten.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240
#define AF_INET		2
#define AF_INET6	10

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct event);
} values SEC(".maps");

static void fill_event(struct event *event, struct socket *sock)
{
	__u16 family, type;
	struct sock *sk;
	struct inet_sock *inet;

	sk = BPF_CORE_READ(sock, sk);
	inet = (struct inet_sock *)sk;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	type = BPF_CORE_READ(sock, type);

	event->proto = ((__u32)family << 16) | type;
	event->port = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
	if (family == AF_INET)
		event->addr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	else if (family == AF_INET6)
		BPF_CORE_READ_INTO(event->addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	bpf_get_current_comm(event->task, sizeof(event->task));
}
