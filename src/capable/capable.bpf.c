// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "capable.h"

#define MAX_ENTRIES	10240

extern int LINUX_KERNEL_VERSION	__kconfig;

struct myinfo myinfo = {};

const volatile enum uniqueness unique_type = UNQ_OFF;
const volatile bool kernel_stack = false;
const volatile bool user_stack = false;
const volatile bool filter_cg = false;
const volatile pid_t target_pid = -1;

struct args_t {
	int cap;
	int cap_out;
};

struct unique_key {
	int cap;
	u32 tgid;
	u64 cgroupid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct args_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, struct cap_event);
} info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct unique_key);
	__type(value, u64);
} seen SEC(".maps");

static __always_inline bool cgroup_filtered(void)
{
	return filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0);
}

static __always_inline int current_ns_pid_tgid(__u64 *pid_tgid)
{
	struct bpf_pidns_info nsdata;

	if (bpf_get_ns_current_pid_tgid(myinfo.dev, myinfo.ino, &nsdata,
					sizeof(struct bpf_pidns_info)))
		return -1;

	*pid_tgid = (__u64)nsdata.tgid << 32 | nsdata.pid;
	return 0;
}

static __always_inline bool is_traced_task(__u64 pid_tgid)
{
	if (myinfo.pid_tgid == pid_tgid)
		return false;

	if (target_pid != -1 && target_pid != (pid_t)(pid_tgid >> 32))
		return false;

	return true;
}

static __always_inline bool already_seen(struct args_t *argsp, __u64 pid_tgid)
{
	struct unique_key key = { .cap = argsp->cap };
	u64 zero = 0;

	if (!unique_type)
		return false;

	if (unique_type == UNQ_CGROUP)
		key.cgroupid = bpf_get_current_cgroup_id();
	else
		key.tgid = pid_tgid;

	if (bpf_map_lookup_elem(&seen, &key))
		return true;

	bpf_map_update_elem(&seen, &key, &zero, BPF_ANY);
	return false;
}

static __always_inline void fill_event(struct cap_event *event,
				       struct args_t *argsp, __u64 pid_tgid)
{
	event->pid = pid_tgid >> 32;
	event->tgid = pid_tgid;
	event->cap = argsp->cap;
	event->uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event->task, sizeof(event->task));

	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 1, 0)) {
		/* @opts: bitmask of options defined in include/linux/security.h */
		event->audit = (argsp->cap_out & 0b10) == 0;
		event->insetid = (argsp->cap_out & 0b100) != 0;
	} else {
		event->audit = argsp->cap_out;
		event->insetid = -1;
	}
}

static __always_inline void record_stack_info(void *ctx, struct cap_event *event,
					      __u64 pid_tgid)
{
	struct key_t i_key;

	if (!kernel_stack && !user_stack)
		return;

	i_key.pid = pid_tgid >> 32;
	i_key.tgid = pid_tgid;

	i_key.kernel_stack_id = i_key.user_stack_id = -1;
	if (user_stack)
		i_key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
	if (kernel_stack)
		i_key.kernel_stack_id = bpf_get_stackid(ctx, &stackmap, 0);

	bpf_map_update_elem(&info, &i_key, event, BPF_NOEXIST);
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(kprobe__cap_capable_entry, const struct cred *cred,
	       struct user_namespace *target_ns, int cap, int cap_out)
{
	__u64 pid_tgid;
	struct args_t args = {};

	if (cgroup_filtered())
		return 0;

	if (current_ns_pid_tgid(&pid_tgid))
		return 0;

	if (!is_traced_task(pid_tgid))
		return 0;

	args.cap = cap;
	args.cap_out = cap_out;

	bpf_map_update_elem(&start, &pid_tgid, &args, BPF_ANY);

	return 0;
}

SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(kretprobe__cap_capable_exit)
{
	__u64 pid_tgid;
	struct args_t *argsp;
	struct cap_event event = {};

	if (current_ns_pid_tgid(&pid_tgid))
		return 0;

	argsp = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!argsp)
		return 0;

	bpf_map_delete_elem(&start, &pid_tgid);

	fill_event(&event, argsp, pid_tgid);
	event.ret = PT_REGS_RC(ctx);

	if (already_seen(argsp, pid_tgid))
		return 0;

	record_stack_info(ctx, &event, pid_tgid);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
