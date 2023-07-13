// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "runqueue-latency.h"
#include "bits.bpf.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

#define MAX_ENTRIES	10240
#define TASK_RUNNING	0

const volatile bool filter_memcg = false;
const volatile bool target_per_process = false;
const volatile bool target_per_thread = false;
const volatile bool target_per_pidns = false;
const volatile bool target_ms = false;
const volatile pid_t target_tgid = 0;