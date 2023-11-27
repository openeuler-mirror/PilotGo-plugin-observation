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

static __always_inline __u32 get_obj_id(void *ent, enum bpf_obj_type type)
{
	switch (type) {
	case BPF_OBJ_PROG:
		return BPF_CORE_READ((struct bpf_prog *)ent, aux, id);
	case BPF_OBJ_MAP:
		return BPF_CORE_READ((struct bpf_map *)ent, id);
	case BPF_OBJ_BTF:
		return BPF_CORE_READ((struct btf *)ent, id);
	case BPF_OBJ_LINK:
		return BPF_CORE_READ((struct bpf_link *)ent, id);
	default:
		return 0;
	}
}

/* could be used only with BPF_LINK_TYPE_PERF_EVENT links */
static __u64 get_bpf_cookie(struct bpf_link *link)
{
	struct bpf_perf_link *perf_link;
	struct perf_event *event;

	perf_link = container_of(link, struct bpf_perf_link, link);
	event = BPF_CORE_READ(perf_link, perf_file, private_data);
	return BPF_CORE_READ(event, bpf_cookie);
}
