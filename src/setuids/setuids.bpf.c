// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "setuids.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

struct data1_t {
	uid_t prev_uid;
	uid_t uid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);
	__type(value, struct data1_t);
} birth_setuid SEC(".maps");

struct data2_t {
	uid_t prev_uid;
	uid_t ruid;
	uid_t euid;
	uid_t suid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);
	__type(value, struct data2_t);
} birth_setreuid SEC(".maps");

static __always_inline int
handle_syscall_enter_uid_fsuid(struct trace_event_raw_sys_enter *ctx)
{
	pid_t tid = bpf_get_current_pid_tgid();
	struct data1_t data = {};

	data.prev_uid = bpf_get_current_uid_gid();
	data.uid = (uid_t)ctx->args[0];

	bpf_map_update_elem(&birth_setuid, &tid, &data, BPF_ANY);

	return 0;
}
