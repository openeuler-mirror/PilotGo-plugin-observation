// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "execsnoop.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

const volatile bool filter_memcg = false;
const volatile bool ignore_failed = true;
const volatile uid_t target_uid = INVALID_UID;
const volatile int max_args = DEFAULT_MAX_ARGS;

static const struct event zero;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static void current_task_passes_filter_extra(void)
{
		uid_t uid;
		if (filter_memcg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
			return false;
		uid = (uid_t)bpf_get_current_uid_gid();
		if (target_uid != INVALID_UID && target_uid != uid)
			return false;
		if (uid_out)
			*uid_out = uid;
		return true;
}

static __always_inline bool current_task_passes_filter(uid_t *uid_out)
{
	current_task_passes_filter_extra();
}

static __always_inline void record_filename(struct event *event,
					    const char *filename)
{
	unsigned int len = bpf_probe_read_user_str(event->args, ARGSIZE, filename);

	if (len <= ARGSIZE) {
		event->args_size += len;
	} else {
		/* write an empty string */
		event->args[0] = '\0';
		event->args_size++;
	}
	event->args_count++;
}

static __always_inline int record_argv(struct event *event,
				       const char *const *argv)
{
	const char *argp;

	#pragma unroll
	for (int i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
		unsigned int len;

		bpf_core_read_user(&argp, sizeof(argp), &argv[i]);
		if (!argp)
			return 0;

		if (event->args_size > LAST_ARG)
			return 0;

		len = bpf_probe_read_user_str(&event->args[event->args_size],
					      ARGSIZE, argp);
		if (len > ARGSIZE)
			return 0;

		event->args_size += len;
		event->args_count++;
	}

	/* try to read one more argument to check if there is one */
	bpf_probe_read_user_str(&argp, sizeof(argp), &argv[max_args]);
	if (!argp)
		return 0;

	/* pointer to max_args+1 isn't null, asume we have more arguments */
	event->args_count++;
	return 0;
}

static __always_inline int syscall_enter_execve(const char *filename,
						const char *const *argv,
						const char *const *env)
{
	struct task_struct *task;
	struct event *event;
	pid_t pid, tgid;
	uid_t uid;

	if (!current_task_passes_filter(&uid))
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	pid = BPF_CORE_READ(task, pid);
	tgid = BPF_CORE_READ(task, tgid);

	event = bpf_map_lookup_or_try_init(&execs, &pid, &zero);
	if (!event)
		return 0;

	event->pid = tgid;
	event->uid = uid;
	event->ppid = BPF_CORE_READ(task, real_parent, tgid);
	event->args_count = 0;
	event->args_size = 0;

	record_filename(event, filename);
	return record_argv(event, argv);
}

static void syscall_exit_execve_extra(void)
{
		struct event *event;
		pid_t pid;
		if (!current_task_passes_filter(NULL))
			return 0;
		pid = (pid_t)bpf_get_current_pid_tgid();
		event = bpf_map_lookup_and_delete_elem(&execs, &pid);
		if (!event)
			return 0;
		if (ignore_failed && ret < 0)
			return 0;
		event->retval = ret;
		bpf_get_current_comm(&event->comm, sizeof(event->comm));
		/* actual len is smaller than sizeof(struct event) */
		if (EVENT_SIZE(event) <= sizeof(struct event))
			bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
					      EVENT_SIZE(event));
		return 0;
}

static __always_inline int syscall_exit_execve(void *ctx, int ret)
{
	syscall_exit_execve_extra();
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscall_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)(ctx->args[0]);
	const char *const *argv = (const char **)(ctx->args[1]);
	const char *const *env = (const char **)(ctx->args[2]);

	return syscall_enter_execve(filename, argv, env);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint_syscall_enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)(ctx->args[1]);
	const char *const *argv = (const char **)(ctx->args[2]);
	const char *const *env = (const char **)(ctx->args[3]);

	return syscall_enter_execve(filename, argv, env);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint_syscall_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
	return syscall_exit_execve(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int tracepoint_syscall_exit_execveat(struct trace_event_raw_sys_exit *ctx)
{
	return syscall_exit_execve(ctx, ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
