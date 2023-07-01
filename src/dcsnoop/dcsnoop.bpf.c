// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "dcsnoop.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

const volatile pid_t target_pid = 0;
const volatile pid_t target_tid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct entry_t);
} entrys SEC(".maps");

static __always_inline int
trace_fast(void *ctx, struct nameidata *nd, struct path *path)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32, tid = pid_tgid;
	struct event *event;

	if (target_pid && target_pid != pid)
		return 0;
	if (target_tid && target_tid != tid)
		return 0;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->pid = pid;
	event->tid = tid;
	event->type = LOOKUP_REFERENCE;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	const unsigned char *name = BPF_CORE_READ(nd, last.name);
	bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), name);

	submit_buf(ctx, event, sizeof(*event));
	return 0;
}