// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "mountsnoop.h"
#include "compat.bpf.h"

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct arg);
} args SEC(".maps");

static __always_inline int probe_entry(const char *src, const char *dest,
                                       const char *fs, __u64 flags,
                                       const char *data, enum op op)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    struct arg arg = {};

    if (target_pid && target_pid != pid)
        return 0;

    arg.ts = bpf_ktime_get_ns();
    arg.flags = flags;
    arg.src = src;
    arg.dest = dest;
    arg.fs = fs;
    arg.data = data;
    arg.op = op;

    bpf_map_update_elem(&args, &tid, &arg, BPF_ANY);
    return 0;
}