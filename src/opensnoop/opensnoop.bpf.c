// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "opensnoop.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "compat.bpf.h"
#include "maps.bpf.h"

const volatile pid_t target_pid = 0;
const volatile pid_t target_tgid = 0;
const volatile uid_t target_uid = 0;
const volatile bool target_failed = false;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct args_t);
} start SEC(".maps");

static __always_inline bool valid_uid(uid_t uid)
{
    return uid != INVALID_UID;
}

static __always_inline bool trace_allowed(u32 tgid, u32 pid)
{
    if (target_pid && target_pid != pid)
        return false;
    if (target_tgid && target_tgid != tgid)
        return false;
    if (valid_uid(target_uid))
    {
        uid_t uid = (u32)bpf_get_current_uid_gid();

        if (target_uid != uid)
            return false;
    }
    return true;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    pid_t tgid = id >> 32;
    pid_t pid = (pid_t)id;

    if (trace_allowed(tgid, pid))
    {
        struct args_t args = {};

        args.fname = (const char *)ctx->args[0];
        args.flags = (int)ctx->args[1];
        args.modes = (umode_t)ctx->args[2];

        bpf_map_update_elem(&start, &pid, &args, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    pid_t tgid = id >> 32;
    pid_t pid = (pid_t)id;

    if (trace_allowed(tgid, pid))
    {
        struct args_t args = {};

        args.fname = (const char *)ctx->args[1];
        args.flags = (int)ctx->args[2];
        args.modes = (umode_t)ctx->args[3];

        bpf_map_update_elem(&start, &pid, &args, BPF_ANY);
    }

    return 0;
}
