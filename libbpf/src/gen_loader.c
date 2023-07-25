// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Facebook */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/filter.h>
#include <sys/param.h>
#include "btf.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"
#include "hashmap.h"
#include "bpf_gen_internal.h"
#include "skel_internal.h"
#include <asm/byteorder.h>

#define MAX_USED_MAPS 64
#define MAX_USED_PROGS 32
#define MAX_KFUNC_DESCS 256
#define MAX_FD_ARRAY_SZ (MAX_USED_MAPS + MAX_KFUNC_DESCS)

struct loader_stack
{
	__u32 btf_fd;
	__u32 inner_map_fd;
	__u32 prog_fd[MAX_USED_PROGS];
};

#define stack_off(field) \
	(__s16)(-sizeof(struct loader_stack) + offsetof(struct loader_stack, field))

#define attr_field(attr, field) (attr + offsetof(union bpf_attr, field))

static int blob_fd_array_off(struct bpf_gen *gen, int index)
{
	return gen->fd_array + index * sizeof(int);
}

static int realloc_insn_buf(struct bpf_gen *gen, __u32 size)
{
	size_t off = gen->insn_cur - gen->insn_start;
	void *insn_start;

	if (gen->error)
		return gen->error;
	if (size > INT32_MAX || off + size > INT32_MAX)
	{
		gen->error = -ERANGE;
		return -ERANGE;
	}
	insn_start = realloc(gen->insn_start, off + size);
	if (!insn_start)
	{
		gen->error = -ENOMEM;
		free(gen->insn_start);
		gen->insn_start = NULL;
		return -ENOMEM;
	}
	gen->insn_start = insn_start;
	gen->insn_cur = insn_start + off;
	return 0;
}

static int realloc_data_buf(struct bpf_gen *gen, __u32 size)
{
	size_t off = gen->data_cur - gen->data_start;
	void *data_start;

	if (gen->error)
		return gen->error;
	if (size > INT32_MAX || off + size > INT32_MAX)
	{
		gen->error = -ERANGE;
		return -ERANGE;
	}
	data_start = realloc(gen->data_start, off + size);
	if (!data_start)
	{
		gen->error = -ENOMEM;
		free(gen->data_start);
		gen->data_start = NULL;
		return -ENOMEM;
	}
	gen->data_start = data_start;
	gen->data_cur = data_start + off;
	return 0;
}

static void emit(struct bpf_gen *gen, struct bpf_insn insn)
{
	if (realloc_insn_buf(gen, sizeof(insn)))
		return;
	memcpy(gen->insn_cur, &insn, sizeof(insn));
	gen->insn_cur += sizeof(insn);
}

static void emit2(struct bpf_gen *gen, struct bpf_insn insn1, struct bpf_insn insn2)
{
	emit(gen, insn1);
	emit(gen, insn2);
}

static int add_data(struct bpf_gen *gen, const void *data, __u32 size);
static void emit_sys_close_blob(struct bpf_gen *gen, int blob_off);

void bpf_gen__init(struct bpf_gen *gen, int log_level, int nr_progs, int nr_maps)
{
	size_t stack_sz = sizeof(struct loader_stack), nr_progs_sz;
	int i;

	gen->fd_array = add_data(gen, NULL, MAX_FD_ARRAY_SZ * sizeof(int));
	gen->log_level = log_level;
	/* save ctx pointer into R6 */
	emit(gen, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));

	/* bzero stack */
	emit(gen, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
	emit(gen, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -stack_sz));
	emit(gen, BPF_MOV64_IMM(BPF_REG_2, stack_sz));
	emit(gen, BPF_MOV64_IMM(BPF_REG_3, 0));
	emit(gen, BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel));

	/* amount of stack actually used, only used to calculate iterations, not stack offset */
	nr_progs_sz = offsetof(struct loader_stack, prog_fd[nr_progs]);
	emit(gen, BPF_JMP_IMM(BPF_JA, 0, 0,
						  (nr_progs_sz / 4) * 3 + 2 +
							  nr_maps * (6 + (gen->log_level ? 6 : 0))));

	gen->cleanup_label = gen->insn_cur - gen->insn_start;
	for (i = 0; i < nr_progs_sz; i += 4)
	{
		emit(gen, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -stack_sz + i));
		emit(gen, BPF_JMP_IMM(BPF_JSLE, BPF_REG_1, 0, 1));
		emit(gen, BPF_EMIT_CALL(BPF_FUNC_sys_close));
	}
	for (i = 0; i < nr_maps; i++)
		emit_sys_close_blob(gen, blob_fd_array_off(gen, i));
	emit(gen, BPF_MOV64_REG(BPF_REG_0, BPF_REG_7));
	emit(gen, BPF_EXIT_INSN());
}

static int add_data(struct bpf_gen *gen, const void *data, __u32 size)
{
	__u32 size8 = roundup(size, 8);
	__u64 zero = 0;
	void *prev;

	if (realloc_data_buf(gen, size8))
		return 0;
	prev = gen->data_cur;
	if (data)
	{
		memcpy(gen->data_cur, data, size);
		memcpy(gen->data_cur + size, &zero, size8 - size);
	}
	else
	{
		memset(gen->data_cur, 0, size8);
	}
	gen->data_cur += size8;
	return prev - gen->data_start;
}

static int add_map_fd(struct bpf_gen *gen)
{
	if (gen->nr_maps == MAX_USED_MAPS)
	{
		pr_warn("Total maps exceeds %d\n", MAX_USED_MAPS);
		gen->error = -E2BIG;
		return 0;
	}
	return gen->nr_maps++;
}

static int add_kfunc_btf_fd(struct bpf_gen *gen)
{
	int cur;

	if (gen->nr_fd_array == MAX_KFUNC_DESCS)
	{
		cur = add_data(gen, NULL, sizeof(int));
		return (cur - gen->fd_array) / sizeof(int);
	}
	return MAX_USED_MAPS + gen->nr_fd_array++;
}

static int insn_bytes_to_bpf_size(__u32 sz)
{
	switch (sz)
	{
	case 8:
		return BPF_DW;
	case 4:
		return BPF_W;
	case 2:
		return BPF_H;
	case 1:
		return BPF_B;
	default:
		return -1;
	}
}

/* *(u64 *)(blob + off) = (u64)(void *)(blob + data) */
static void emit_rel_store(struct bpf_gen *gen, int off, int data)
{
	emit2(gen, BPF_LD_IMM64_RAW_FULL(BPF_REG_0, BPF_PSEUDO_MAP_IDX_VALUE,
									 0, 0, 0, data));
	emit2(gen, BPF_LD_IMM64_RAW_FULL(BPF_REG_1, BPF_PSEUDO_MAP_IDX_VALUE,
									 0, 0, 0, off));
	emit(gen, BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0));
}

static void move_blob2blob(struct bpf_gen *gen, int off, int size, int blob_off)
{
	emit2(gen, BPF_LD_IMM64_RAW_FULL(BPF_REG_2, BPF_PSEUDO_MAP_IDX_VALUE,
									 0, 0, 0, blob_off));
	emit(gen, BPF_LDX_MEM(insn_bytes_to_bpf_size(size), BPF_REG_0, BPF_REG_2, 0));
	emit2(gen, BPF_LD_IMM64_RAW_FULL(BPF_REG_1, BPF_PSEUDO_MAP_IDX_VALUE,
									 0, 0, 0, off));
	emit(gen, BPF_STX_MEM(insn_bytes_to_bpf_size(size), BPF_REG_1, BPF_REG_0, 0));
}

static void move_blob2ctx(struct bpf_gen *gen, int ctx_off, int size, int blob_off)
{
	emit2(gen, BPF_LD_IMM64_RAW_FULL(BPF_REG_1, BPF_PSEUDO_MAP_IDX_VALUE,
									 0, 0, 0, blob_off));
	emit(gen, BPF_LDX_MEM(insn_bytes_to_bpf_size(size), BPF_REG_0, BPF_REG_1, 0));
	emit(gen, BPF_STX_MEM(insn_bytes_to_bpf_size(size), BPF_REG_6, BPF_REG_0, ctx_off));
}

static void move_ctx2blob(struct bpf_gen *gen, int off, int size, int ctx_off,
						  bool check_non_zero)
{
	emit(gen, BPF_LDX_MEM(insn_bytes_to_bpf_size(size), BPF_REG_0, BPF_REG_6, ctx_off));
	if (check_non_zero)
		/* If value in ctx is zero don't update the blob.
		 * For example: when ctx->map.max_entries == 0, keep default max_entries from bpf.c
		 */
		emit(gen, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 3));
	emit2(gen, BPF_LD_IMM64_RAW_FULL(BPF_REG_1, BPF_PSEUDO_MAP_IDX_VALUE,
									 0, 0, 0, off));
	emit(gen, BPF_STX_MEM(insn_bytes_to_bpf_size(size), BPF_REG_1, BPF_REG_0, 0));
}

static void move_stack2blob(struct bpf_gen *gen, int off, int size, int stack_off)
{
	emit(gen, BPF_LDX_MEM(insn_bytes_to_bpf_size(size), BPF_REG_0, BPF_REG_10, stack_off));
	emit2(gen, BPF_LD_IMM64_RAW_FULL(BPF_REG_1, BPF_PSEUDO_MAP_IDX_VALUE,
									 0, 0, 0, off));
	emit(gen, BPF_STX_MEM(insn_bytes_to_bpf_size(size), BPF_REG_1, BPF_REG_0, 0));
}

static void move_stack2ctx(struct bpf_gen *gen, int ctx_off, int size, int stack_off)
{
	emit(gen, BPF_LDX_MEM(insn_bytes_to_bpf_size(size), BPF_REG_0, BPF_REG_10, stack_off));
	emit(gen, BPF_STX_MEM(insn_bytes_to_bpf_size(size), BPF_REG_6, BPF_REG_0, ctx_off));
}

static void emit_sys_bpf(struct bpf_gen *gen, int cmd, int attr, int attr_size)
{
	emit(gen, BPF_MOV64_IMM(BPF_REG_1, cmd));
	emit2(gen, BPF_LD_IMM64_RAW_FULL(BPF_REG_2, BPF_PSEUDO_MAP_IDX_VALUE,
									 0, 0, 0, attr));
	emit(gen, BPF_MOV64_IMM(BPF_REG_3, attr_size));
	emit(gen, BPF_EMIT_CALL(BPF_FUNC_sys_bpf));
	/* remember the result in R7 */
	emit(gen, BPF_MOV64_REG(BPF_REG_7, BPF_REG_0));
}

static bool is_simm16(__s64 value)
{
	return value == (__s64)(__s16)value;
}

static void emit_check_err(struct bpf_gen *gen)
{
	__s64 off = -(gen->insn_cur - gen->insn_start - gen->cleanup_label) / 8 - 1;

	/* R7 contains result of last sys_bpf command.
	 * if (R7 < 0) goto cleanup;
	 */
	if (is_simm16(off))
	{
		emit(gen, BPF_JMP_IMM(BPF_JSLT, BPF_REG_7, 0, off));
	}
	else
	{
		gen->error = -ERANGE;
		emit(gen, BPF_JMP_IMM(BPF_JA, 0, 0, -1));
	}
}