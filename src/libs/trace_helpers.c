/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// Copyright (c) 2020 Wenbo Zhang
//
// Based on ksyms improvements from Andrii Nakryiko, add more helpers.
// 28-Feb-2020   Wenbo Zhang   Created this.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define DISK_NAME_LEN	32

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MKDEV(ma, mi)	(((ma) << MINORBITS) | (mi))

struct ksyms {
	struct ksym *syms;
	int syms_sz;
	int syms_cap;
	char *strs;
	int strs_sz;
	int strs_cap;
	char *modules;
	int modules_sz;
	int modules_cap;
};

static int ksyms__add_symbol(struct ksyms *ksyms, const char *name, unsigned long addr,
			     const char *module)
{
	size_t new_cap, name_len = strlen(name) + 1, module_len;
	struct ksym *ksym;
	void *tmp;

	if (ksyms->strs_sz + name_len > ksyms->strs_cap) {
		new_cap = ksyms->strs_cap * 4 / 3;
		if (new_cap < ksyms->strs_sz + name_len)
			new_cap = ksyms->strs_sz + name_len;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(ksyms->strs, new_cap);
		if (!tmp)
			return -1;
		ksyms->strs = tmp;
		ksyms->strs_cap = new_cap;
	}
	if (ksyms->syms_sz + 1 > ksyms->syms_cap) {
		new_cap = ksyms->syms_cap * 4 / 3;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(ksyms->syms, sizeof(*ksyms->syms) * new_cap);
		if (!tmp)
			return -1;
		ksyms->syms = tmp;
		ksyms->syms_cap = new_cap;
	}

	if (module) {
		module_len = strlen(module) + 1;
		if (ksyms->modules_sz + module_len > ksyms->modules_cap) {
			new_cap = ksyms->modules_cap * 4 / 3;
			if (new_cap < 1024)
				new_cap = 1024;
			tmp = realloc(ksyms->modules, sizeof(*ksyms->modules) * new_cap);
			if (!tmp)
				return -1;
			ksyms->modules = tmp;
			ksyms->modules_cap = new_cap;
		}
	}

	ksym = &ksyms->syms[ksyms->syms_sz];
	/* while constructing, re-use pointer as just a plain offset */
	ksym->name = (void *)(unsigned long)ksyms->strs_sz;
	ksym->addr = addr;

	memcpy(ksyms->strs + ksyms->strs_sz, name, name_len);
	ksyms->strs_sz += name_len;
	ksyms->syms_sz++;

	if (module) {
		ksym->module = (void *)(unsigned long)ksyms->modules_sz;
		memcpy(ksyms->modules + ksyms->modules_sz, module, module_len);
		ksyms->modules_sz += module_len;
	} else {
		/* Not module, init to invalid pointer */
		ksym->module = (void *)-1;
	}

	return 0;
}

static int ksym_cmp(const void *p1, const void *p2)
{
	const struct ksym *s1 = p1, *s2 = p2;

	if (s1->addr == s2->addr)
		return strcmp(s1->name, s2->name);
	return s1->addr < s2->addr ? -1 : 1;
}

struct ksyms *ksyms__load(void)
{
	char sym_type, sym_name[256], module_name[256];
	struct ksyms *ksyms;
	unsigned long sym_addr;
	int i, ret;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return NULL;

	ksyms = calloc(1, sizeof(*ksyms));
	if (!ksyms)
		goto err_out;

	while (true) {
		char mod_info[256];
		const char *module_info;

		ret = fscanf(f, "%lx %c %s%[^\n]\n",
			     &sym_addr, &sym_type, sym_name, mod_info);
		if (ret == EOF && feof(f))
			break;
		if (ret < 3)
			goto err_out;
		if (ret == 4) {
			if (sscanf(mod_info, "%*[\t ][%[^]]", module_name) < 1)
				goto err_out;
			module_info = module_name;
		} else {
			module_info = NULL;
		}

		if (ksyms__add_symbol(ksyms, sym_name, sym_addr, module_info))
			goto err_out;
	}

	/* now when strings are finalized, adjust pointers properly */
	for (i = 0; i < ksyms->syms_sz; i++) {
		ksyms->syms[i].name += (unsigned long)ksyms->strs;

		/* -1 mean not module */
		if (ksyms->syms[i].module != (void *)-1)
			ksyms->syms[i].module += (unsigned long)ksyms->modules;
		else
			/* reset to NULL, if it isn't module */
			ksyms->syms[i].module = NULL;
	}

	qsort(ksyms->syms, ksyms->syms_sz, sizeof(*ksyms->syms), ksym_cmp);

	fclose(f);
	return ksyms;

err_out:
	ksyms__free(ksyms);
	fclose(f);
	return NULL;
}

void ksyms__free(struct ksyms *ksyms)
{
	if (!ksyms)
		return;

	free(ksyms->syms);
	free(ksyms->strs);
	free(ksyms->modules);
	free(ksyms);
}

const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr)
{
	int start = 0, end = ksyms->syms_sz - 1, mid;
	unsigned long sym_addr;

	/* find largest sym_addr <= addr using binary search */
	while (start < end) {
		mid = start + (end - start + 1) / 2;
		sym_addr = ksyms->syms[mid].addr;

		if (sym_addr <= addr)
			start = mid;
		else
			end = mid - 1;
	}

	if (start == end && ksyms->syms[start].addr <= addr)
		return &ksyms->syms[start];
	return NULL;
}

const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name)
{
	int i;

	for (i = 0; i < ksyms->syms_sz; i++) {
		if (strcmp(ksyms->syms[i].name, name) == 0)
			return &ksyms->syms[i];
	}

	return NULL;
}
