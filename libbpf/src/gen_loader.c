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
