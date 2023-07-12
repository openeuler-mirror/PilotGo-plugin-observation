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