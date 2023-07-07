// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Based on funcslower.py - Copyright 2017, Sasha Goldshtein

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "compat.bpf.h"
#include "funcslower.h"

const volatile pid_t target_pid = 0;
const volatile bool need_grab_args = false;
const volatile bool need_user_stack = false;
const volatile bool need_kernel_stack = false;
const volatile __u64 duration_ns = 0;

struct entry_t {
	__u64 id;
	__u64 start_ns;
	__u64 args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct entry_t);
} entryinfo SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, __u32);
} stack_trace SEC(".maps");

static __always_inline int trace_entry(struct pt_regs *ctx, int id)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid >> 32;

	if (target_pid && target_pid != pid)
		return 0;

	struct entry_t entry = {};
	entry.start_ns = bpf_ktime_get_ns();
	entry.id = id;

	if (need_grab_args) {
		entry.args[0] = PT_REGS_PARM1(ctx);
		entry.args[1] = PT_REGS_PARM2(ctx);
		entry.args[2] = PT_REGS_PARM3(ctx);
		entry.args[3] = PT_REGS_PARM4(ctx);
		entry.args[4] = PT_REGS_PARM5(ctx);
	}

	bpf_map_update_elem(&entryinfo, &pid_tgid, &entry, BPF_ANY);
	return 0;
}
