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
