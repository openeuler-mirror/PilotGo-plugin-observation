// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <linux/ptrace.h>
#include <linux/kernel.h>

/* s8 will be marked as poison while it's a reg of riscv */
#if defined(__riscv)
#define rv_s8 s8
#endif

#include "bpf.h"
#include "libbpf.h"
#include "libbpf_common.h"
#include "libbpf_internal.h"
#include "hashmap.h"

#define USDT_BASE_SEC ".stapsdt.base"
#define USDT_SEMA_SEC ".probes"
#define USDT_NOTE_SEC  ".note.stapsdt"
#define USDT_NOTE_TYPE 3
#define USDT_NOTE_NAME "stapsdt"

/* should match exactly enum __bpf_usdt_arg_type from usdt.bpf.h */
enum usdt_arg_type {
	USDT_ARG_CONST,
	USDT_ARG_REG,
	USDT_ARG_REG_DEREF,
};

/* should match exactly struct __bpf_usdt_arg_spec from usdt.bpf.h */
struct usdt_arg_spec {
	__u64 val_off;
	enum usdt_arg_type arg_type;
	short reg_off;
	bool arg_signed;
	char arg_bitshift;
};

/* should match BPF_USDT_MAX_ARG_CNT in usdt.bpf.h */
#define USDT_MAX_ARG_CNT 12

/* should match struct __bpf_usdt_spec from usdt.bpf.h */
struct usdt_spec {
	struct usdt_arg_spec args[USDT_MAX_ARG_CNT];
	__u64 usdt_cookie;
	short arg_cnt;
};

struct usdt_note {
	const char *provider;
	const char *name;
	/* USDT args specification string, e.g.:
	 * "-4@%esi -4@-24(%rbp) -4@%ecx 2@%ax 8@%rdx"
	 */
	const char *args;
	long loc_addr;
	long base_addr;
	long sema_addr;
};

struct usdt_target {
	long abs_ip;
	long rel_ip;
	long sema_off;
	struct usdt_spec spec;
	const char *spec_str;
};

struct usdt_manager {
	struct bpf_map *specs_map;
	struct bpf_map *ip_to_spec_id_map;

	int *free_spec_ids;
	size_t free_spec_cnt;
	size_t next_free_spec_id;

	bool has_bpf_cookie;
	bool has_sema_refcnt;
};

/*Architecture specific logic for parsing USDT parameter location specifications*/

#if defined(__x86_64__) || defined(__i386__)

static int calc_pt_regs_off(const char *reg_name)
{
	static struct {
		const char *names[4];
		size_t pt_regs_off;
	} reg_map[] = {
#ifdef __x86_64__
#define reg_off(reg64, reg32) offsetof(struct pt_regs, reg64)
#else
#define reg_off(reg64, reg32) offsetof(struct pt_regs, reg32)
#endif
		{ {"rip", "eip", "", ""}, reg_off(rip, eip) },
		{ {"rax", "eax", "ax", "al"}, reg_off(rax, eax) },
		{ {"rbx", "ebx", "bx", "bl"}, reg_off(rbx, ebx) },
		{ {"rcx", "ecx", "cx", "cl"}, reg_off(rcx, ecx) },
		{ {"rdx", "edx", "dx", "dl"}, reg_off(rdx, edx) },
		{ {"rsi", "esi", "si", "sil"}, reg_off(rsi, esi) },
		{ {"rdi", "edi", "di", "dil"}, reg_off(rdi, edi) },
		{ {"rbp", "ebp", "bp", "bpl"}, reg_off(rbp, ebp) },
		{ {"rsp", "esp", "sp", "spl"}, reg_off(rsp, esp) },
#undef reg_off
#ifdef __x86_64__
		{ {"r8", "r8d", "r8w", "r8b"}, offsetof(struct pt_regs, r8) },
		{ {"r9", "r9d", "r9w", "r9b"}, offsetof(struct pt_regs, r9) },
		{ {"r10", "r10d", "r10w", "r10b"}, offsetof(struct pt_regs, r10) },
		{ {"r11", "r11d", "r11w", "r11b"}, offsetof(struct pt_regs, r11) },
		{ {"r12", "r12d", "r12w", "r12b"}, offsetof(struct pt_regs, r12) },
		{ {"r13", "r13d", "r13w", "r13b"}, offsetof(struct pt_regs, r13) },
		{ {"r14", "r14d", "r14w", "r14b"}, offsetof(struct pt_regs, r14) },
		{ {"r15", "r15d", "r15w", "r15b"}, offsetof(struct pt_regs, r15) },
#endif
	};
	int i, j;

	for (i = 0; i < ARRAY_SIZE(reg_map); i++) {
		for (j = 0; j < ARRAY_SIZE(reg_map[i].names); j++) {
			if (strcmp(reg_name, reg_map[i].names[j]) == 0)
				return reg_map[i].pt_regs_off;
		}
	}

	pr_warn("usdt: unrecognized register '%s'\n", reg_name);
	return -ENOENT;
}

static int parse_usdt_arg(const char *arg_str, int arg_num, struct usdt_arg_spec *arg, int *arg_sz)
{
	char reg_name[16];
	int len, reg_off;
	long off;

	if (sscanf(arg_str, " %d @ %ld ( %%%15[^)] ) %n", arg_sz, &off, reg_name, &len) == 3) {
		/* Memory dereference case, e.g., -4@-20(%rbp) */
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off = off;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ ( %%%15[^)] ) %n", arg_sz, reg_name, &len) == 2) {
		/* Memory dereference case without offset, e.g., 8@(%rsp) */
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off = 0;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ %%%15s %n", arg_sz, reg_name, &len) == 2) {
		/* Register read case, e.g., -4@%eax */
		arg->arg_type = USDT_ARG_REG;
		arg->val_off = 0;

		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ $%ld %n", arg_sz, &off, &len) == 2) {
		/* Constant value case, e.g., 4@$71 */
		arg->arg_type = USDT_ARG_CONST;
		arg->val_off = off;
		arg->reg_off = 0;
	} else {
		pr_warn("usdt: unrecognized arg #%d spec '%s'\n", arg_num, arg_str);
		return -EINVAL;
	}

	return len;
}

#elif defined(__s390x__)

/* Do not support __s390__ for now, since user_pt_regs is broken with -m31. */

static int parse_usdt_arg(const char *arg_str, int arg_num, struct usdt_arg_spec *arg, int *arg_sz)
{
	unsigned int reg;
	int len;
	long off;

	if (sscanf(arg_str, " %d @ %ld ( %%r%u ) %n", arg_sz, &off, &reg, &len) == 3) {
		/* Memory dereference case, e.g., -2@-28(%r15) */
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off = off;
		if (reg > 15) {
			pr_warn("usdt: unrecognized register '%%r%u'\n", reg);
			return -EINVAL;
		}
		arg->reg_off = offsetof(user_pt_regs, gprs[reg]);
	} else if (sscanf(arg_str, " %d @ %%r%u %n", arg_sz, &reg, &len) == 2) {
		/* Register read case, e.g., -8@%r0 */
		arg->arg_type = USDT_ARG_REG;
		arg->val_off = 0;
		if (reg > 15) {
			pr_warn("usdt: unrecognized register '%%r%u'\n", reg);
			return -EINVAL;
		}
		arg->reg_off = offsetof(user_pt_regs, gprs[reg]);
	} else if (sscanf(arg_str, " %d @ %ld %n", arg_sz, &off, &len) == 2) {
		/* Constant value case, e.g., 4@71 */
		arg->arg_type = USDT_ARG_CONST;
		arg->val_off = off;
		arg->reg_off = 0;
	} else {
		pr_warn("usdt: unrecognized arg #%d spec '%s'\n", arg_num, arg_str);
		return -EINVAL;
	}

	return len;
}

#elif defined(__aarch64__)

static int calc_pt_regs_off(const char *reg_name)
{
	int reg_num;

	if (sscanf(reg_name, "x%d", &reg_num) == 1) {
		if (reg_num >= 0 && reg_num < 31)
			return offsetof(struct user_pt_regs, regs[reg_num]);
	} else if (strcmp(reg_name, "sp") == 0) {
		return offsetof(struct user_pt_regs, sp);
	}
	pr_warn("usdt: unrecognized register '%s'\n", reg_name);
	return -ENOENT;
}

static int parse_usdt_arg(const char *arg_str, int arg_num, struct usdt_arg_spec *arg, int *arg_sz)
{
	char reg_name[16];
	int len, reg_off;
	long off;

	if (sscanf(arg_str, " %d @ \[ %15[a-z0-9] , %ld ] %n", arg_sz, reg_name, &off, &len) == 3) {
		/* Memory dereference case, e.g., -4@[sp, 96] */
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off = off;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ \[ %15[a-z0-9] ] %n", arg_sz, reg_name, &len) == 2) {
		/* Memory dereference case, e.g., -4@[sp] */
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off = 0;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ %ld %n", arg_sz, &off, &len) == 2) {
		/* Constant value case, e.g., 4@5 */
		arg->arg_type = USDT_ARG_CONST;
		arg->val_off = off;
		arg->reg_off = 0;
	} else if (sscanf(arg_str, " %d @ %15[a-z0-9] %n", arg_sz, reg_name, &len) == 2) {
		/* Register read case, e.g., -8@x4 */
		arg->arg_type = USDT_ARG_REG;
		arg->val_off = 0;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else {
		pr_warn("usdt: unrecognized arg #%d spec '%s'\n", arg_num, arg_str);
		return -EINVAL;
	}

	return len;
}

#elif defined(__riscv)

static int calc_pt_regs_off(const char *reg_name)
{
	static struct {
		const char *name;
		size_t pt_regs_off;
	} reg_map[] = {
		{ "ra", offsetof(struct user_regs_struct, ra) },
		{ "sp", offsetof(struct user_regs_struct, sp) },
		{ "gp", offsetof(struct user_regs_struct, gp) },
		{ "tp", offsetof(struct user_regs_struct, tp) },
		{ "a0", offsetof(struct user_regs_struct, a0) },
		{ "a1", offsetof(struct user_regs_struct, a1) },
		{ "a2", offsetof(struct user_regs_struct, a2) },
		{ "a3", offsetof(struct user_regs_struct, a3) },
		{ "a4", offsetof(struct user_regs_struct, a4) },
		{ "a5", offsetof(struct user_regs_struct, a5) },
		{ "a6", offsetof(struct user_regs_struct, a6) },
		{ "a7", offsetof(struct user_regs_struct, a7) },
		{ "s0", offsetof(struct user_regs_struct, s0) },
		{ "s1", offsetof(struct user_regs_struct, s1) },
		{ "s2", offsetof(struct user_regs_struct, s2) },
		{ "s3", offsetof(struct user_regs_struct, s3) },
		{ "s4", offsetof(struct user_regs_struct, s4) },
		{ "s5", offsetof(struct user_regs_struct, s5) },
		{ "s6", offsetof(struct user_regs_struct, s6) },
		{ "s7", offsetof(struct user_regs_struct, s7) },
		{ "s8", offsetof(struct user_regs_struct, rv_s8) },
		{ "s9", offsetof(struct user_regs_struct, s9) },
		{ "s10", offsetof(struct user_regs_struct, s10) },
		{ "s11", offsetof(struct user_regs_struct, s11) },
		{ "t0", offsetof(struct user_regs_struct, t0) },
		{ "t1", offsetof(struct user_regs_struct, t1) },
		{ "t2", offsetof(struct user_regs_struct, t2) },
		{ "t3", offsetof(struct user_regs_struct, t3) },
		{ "t4", offsetof(struct user_regs_struct, t4) },
		{ "t5", offsetof(struct user_regs_struct, t5) },
		{ "t6", offsetof(struct user_regs_struct, t6) },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(reg_map); i++) {
		if (strcmp(reg_name, reg_map[i].name) == 0)
			return reg_map[i].pt_regs_off;
	}

	pr_warn("usdt: unrecognized register '%s'\n", reg_name);
	return -ENOENT;
}

static int parse_usdt_arg(const char *arg_str, int arg_num, struct usdt_arg_spec *arg, int *arg_sz)
{
	char reg_name[16];
	int len, reg_off;
	long off;

	if (sscanf(arg_str, " %d @ %ld ( %15[a-z0-9] ) %n", arg_sz, &off, reg_name, &len) == 3) {
		/* Memory dereference case, e.g., -8@-88(s0) */
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off = off;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ %ld %n", arg_sz, &off, &len) == 2) {
		/* Constant value case, e.g., 4@5 */
		arg->arg_type = USDT_ARG_CONST;
		arg->val_off = off;
		arg->reg_off = 0;
	} else if (sscanf(arg_str, " %d @ %15[a-z0-9] %n", arg_sz, reg_name, &len) == 2) {
		/* Register read case, e.g., -8@a1 */
		arg->arg_type = USDT_ARG_REG;
		arg->val_off = 0;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else {
		pr_warn("usdt: unrecognized arg #%d spec '%s'\n", arg_num, arg_str);
		return -EINVAL;
	}

	return len;
}

#elif defined(__arm__)

static int calc_pt_regs_off(const char *reg_name)
{
	static struct {
		const char *name;
		size_t pt_regs_off;
	} reg_map[] = {
		{ "r0", offsetof(struct pt_regs, uregs[0]) },
		{ "r1", offsetof(struct pt_regs, uregs[1]) },
		{ "r2", offsetof(struct pt_regs, uregs[2]) },
		{ "r3", offsetof(struct pt_regs, uregs[3]) },
		{ "r4", offsetof(struct pt_regs, uregs[4]) },
		{ "r5", offsetof(struct pt_regs, uregs[5]) },
		{ "r6", offsetof(struct pt_regs, uregs[6]) },
		{ "r7", offsetof(struct pt_regs, uregs[7]) },
		{ "r8", offsetof(struct pt_regs, uregs[8]) },
		{ "r9", offsetof(struct pt_regs, uregs[9]) },
		{ "r10", offsetof(struct pt_regs, uregs[10]) },
		{ "fp", offsetof(struct pt_regs, uregs[11]) },
		{ "ip", offsetof(struct pt_regs, uregs[12]) },
		{ "sp", offsetof(struct pt_regs, uregs[13]) },
		{ "lr", offsetof(struct pt_regs, uregs[14]) },
		{ "pc", offsetof(struct pt_regs, uregs[15]) },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(reg_map); i++) {
		if (strcmp(reg_name, reg_map[i].name) == 0)
			return reg_map[i].pt_regs_off;
	}

	pr_warn("usdt: unrecognized register '%s'\n", reg_name);
	return -ENOENT;
}

static int parse_usdt_arg(const char *arg_str, int arg_num, struct usdt_arg_spec *arg, int *arg_sz)
{
	char reg_name[16];
	int len, reg_off;
	long off;

	if (sscanf(arg_str, " %d @ \[ %15[a-z0-9] , #%ld ] %n",
		   arg_sz, reg_name, &off, &len) == 3) {
		/* Memory dereference case, e.g., -4@[fp, #96] */
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off = off;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ \[ %15[a-z0-9] ] %n", arg_sz, reg_name, &len) == 2) {
		/* Memory dereference case, e.g., -4@[sp] */
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off = 0;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ #%ld %n", arg_sz, &off, &len) == 2) {
		/* Constant value case, e.g., 4@#5 */
		arg->arg_type = USDT_ARG_CONST;
		arg->val_off = off;
		arg->reg_off = 0;
	} else if (sscanf(arg_str, " %d @ %15[a-z0-9] %n", arg_sz, reg_name, &len) == 2) {
		/* Register read case, e.g., -8@r4 */
		arg->arg_type = USDT_ARG_REG;
		arg->val_off = 0;
		reg_off = calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else {
		pr_warn("usdt: unrecognized arg #%d spec '%s'\n", arg_num, arg_str);
		return -EINVAL;
	}

	return len;
}

#else

static int parse_usdt_arg(const char *arg_str, int arg_num, struct usdt_arg_spec *arg, int *arg_sz)
{
	pr_warn("usdt: libbpf doesn't support USDTs on current architecture\n");
	return -ENOTSUP;
}

#endif

