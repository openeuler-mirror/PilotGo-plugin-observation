// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "tcpsynbl.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	65536

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

static int do_entry(struct sock *sk)
{
	u64 max_backlog, backlog, slot;
	struct hist *histp;

	max_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);
	backlog = BPF_CORE_READ(sk, sk_ack_backlog);
	histp = bpf_map_lookup_or_try_init(&hists, &max_backlog, &zero);
	if (!histp)
		return 0;

	slot = log2l(backlog);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	__sync_fetch_and_add(&histp->slots[slot], 1);
	return 0;
}

