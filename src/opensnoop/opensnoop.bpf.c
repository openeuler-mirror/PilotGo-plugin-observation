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
