/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#ifndef __USDT_BPF_H__
#define __USDT_BPF_H__

#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Below types and maps are internal implementation details of libbpf's USDT
 * support and are subjects to change. Also, bpf_usdt_xxx() API helpers should
 * be considered an unstable API as well and might be adjusted based on user
 * feedback from using libbpf's USDT support in production.
 */

/* User can override BPF_USDT_MAX_SPEC_CNT to change default size of internal
 * map that keeps track of USDT argument specifications. This might be
 * necessary if there are a lot of USDT attachments.
 */
#ifndef BPF_USDT_MAX_SPEC_CNT
#define BPF_USDT_MAX_SPEC_CNT 256
#endif
/* User can override BPF_USDT_MAX_IP_CNT to change default size of internal
 * map that keeps track of IP (memory address) mapping to USDT argument
 * specification.
 * Note, if kernel supports BPF cookies, this map is not used and could be
 * resized all the way to 1 to save a bit of memory.
 */
#ifndef BPF_USDT_MAX_IP_CNT
#define BPF_USDT_MAX_IP_CNT (4 * BPF_USDT_MAX_SPEC_CNT)
#endif

enum __bpf_usdt_arg_type {
	BPF_USDT_ARG_CONST,
	BPF_USDT_ARG_REG,
	BPF_USDT_ARG_REG_DEREF,
};

struct __bpf_usdt_arg_spec {
	/* u64 scalar interpreted depending on arg_type, see below */
	__u64 val_off;
	/* arg location case, see bpf_udst_arg() for details */
	enum __bpf_usdt_arg_type arg_type;
	/* offset of referenced register within struct pt_regs */
	short reg_off;
	/* whether arg should be interpreted as signed value */
	bool arg_signed;
	/* number of bits that need to be cleared and, optionally,
	 * sign-extended to cast arguments that are 1, 2, or 4 bytes
	 * long into final 8-byte u64/s64 value returned to user
	 */
	char arg_bitshift;
};
