// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "pid_iter.h"

/* keep in sync with the definition in main.h */
enum bpf_obj_type {
	BPF_OBJ_UNKNOWN,
	BPF_OBJ_PROG,
	BPF_OBJ_MAP,
	BPF_OBJ_LINK,
	BPF_OBJ_BTF,
};

extern const void bpf_link_fops __ksym;
extern const void bpf_map_fops __ksym;
extern const void bpf_prog_fops __ksym;
extern const void btf_fops __ksym;

const volatile enum bpf_obj_type obj_type = BPF_OBJ_UNKNOWN;
