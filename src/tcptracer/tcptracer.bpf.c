// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tcptracer.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

const volatile uid_t filter_uid = -1;
const volatile pid_t filter_pid = 0;

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

/*
 * tcp_set_state doesn't run in the context of the process that initiated the
 * connection so we need to store a map TUPLE -> PID to send the right PID on
 * the event.
 */
struct tuple_key_t {
	union {
		__u32 saddr_v4;
		unsigned __int128 saddr_v6;
	};
	union {
		__u32 daddr_v4;
		unsigned __int128 daddr_v6;
	};
	u16 sport;
	u16 dport;
	u32 netns;
};

struct pid_comm_t {
	u64 pid;
	char comm[TASK_COMM_LEN];
	u32 uid;
};

