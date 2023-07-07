// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syncsnoop.h"
#include "compat.bpf.h"

static __always_inline int handle_enter_sync(void *ctx, const char *funcname)
{
	struct event *event;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_core_read_str(&event->funcname, sizeof(event->funcname), funcname);

	submit_buf(ctx, event, sizeof(*event));

	return 0;
}