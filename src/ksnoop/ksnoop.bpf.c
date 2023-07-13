// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "ksnoop.h"
#include "maps.bpf.h"

/* For kretprobes, the instruction pointer in the struct pt_regs context
 * is the kretprobe_trampoline. we derive the instruction pointer
 * by pushing it onto a function stack on entry and popping it on return.
 *
 * We could use bpf_get_func_ip(), but "stack mode" - where we
 * specify functions "a", "b" and "c" and only want to see a trace if "a"
 * calls "b" and "b" calls "c" - utilizes this stack to determine if trace
 * data should be collected.
 */
#define FUNC_MAX_STACK_DEPTH	16
/* Used to convince verifier we do not stray outside of array bounds */
#define FUNC_STACK_DEPTH_MASK	(FUNC_MAX_STACK_DEPTH - 1)

#ifndef ENOSPC
#define ENOSPC			28
#endif

struct func_stack {
	__u64 task;
	__u64 ips[FUNC_MAX_STACK_DEPTH];
	__u8 stack_depth;
};

#define MAX_TASKS		2048

/* function call stack hashed on a per-task key */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TASKS);
	__type(key, __u64);
	__type(value, struct func_stack);
} ksnoop_func_stack SEC(".maps");

/* per-cpu trace info hashed on function address */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_FUNC_TRACES);
	__type(key, __u64);
	__type(value, struct trace);
} ksnoop_func_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(value_size, sizeof(u32));
	__uint(key_size, sizeof(u32));
} ksnoop_perf_map SEC(".maps");

static void clear_trace(struct trace *trace)
{
	__builtin_memset(&trace->trace_data, 0, sizeof(trace->trace_data));
	trace->data_flags = 0;
	trace->buf_len = 0;
}
