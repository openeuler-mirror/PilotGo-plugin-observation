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

struct load_range {
	uint64_t start;
	uint64_t end;
	uint64_t file_off;
};

enum elf_type {
	EXEC,
	DYN,
	PERF_MAP,
	VDSO,
	UNKNOWN,
};

struct dso {
	char *name;
	struct load_range *ranges;
	int range_sz;
	/* Dyn's first text section virtual addr at execution */
	uint64_t sh_addr;
	/* Dyn's first text section file offset */
	uint64_t sh_offset;
	enum elf_type type;

	struct sym *syms;
	int syms_sz;
	int syms_cap;

	/*
	 * libbpf's struct btf is actually a pretty efficient
	 * "set of strings" data structure, so we create an
	 * empty one and use it to store symbol names.
	 */
	struct btf *btf;
};

struct map {
	uint64_t start_addr;
	uint64_t end_addr;
	uint64_t file_off;
	uint64_t dev_major;
	uint64_t dev_minor;
	uint64_t inode;
};

struct syms {
	struct dso *dsos;
	int dso_sz;
};

static bool is_file_backed(const char *mapname)
{
#define STARTS_WITH(mapname, prefix) \
	(!strncmp(mapname, prefix, sizeof(prefix) - 1))

	return mapname[0] && !(
		STARTS_WITH(mapname, "//anon") ||
		STARTS_WITH(mapname, "/dev/zero") ||
		STARTS_WITH(mapname, "/anon_hugepage") ||
		STARTS_WITH(mapname, "[stack") ||
		STARTS_WITH(mapname, "/SYSV") ||
		STARTS_WITH(mapname, "[heap]") ||
		STARTS_WITH(mapname, "[uprobes]") ||
		STARTS_WITH(mapname, "[vsyscall]"));
}

static bool is_perf_map(const char *path)
{
	return false;
}

static bool is_vdso(const char *path)
{
	return !strcmp(path, "[vdso]");
}

static int get_elf_type(const char *path)
{
	GElf_Ehdr hdr;
	void *res;
	Elf *e;
	int fd;

	if (is_vdso(path))
		return -1;
	e = open_elf(path, &fd);
	if (!e)
		return -1;
	res = gelf_getehdr(e, &hdr);
	close_elf(e, fd);
	if (!res)
		return -1;
	return hdr.e_type;
}

static int get_elf_text_scn_info(const char *path, uint64_t *addr,
				 uint64_t *offset)
{
	Elf_Scn *section = NULL;
	int fd = -1, err = -1;
	GElf_Shdr header;
	size_t stridx;
	Elf *e = NULL;
	char *name;

	e = open_elf(path, &fd);
	if (!e)
		goto err_out;
	err = elf_getshdrstrndx(e, &stridx);
	if (err < 0)
		goto err_out;

	err = -1;
	while ((section = elf_nextscn(e, section)) != 0) {
		if (!gelf_getshdr(section, &header))
			continue;

		name = elf_strptr(e, stridx, header.sh_name);
		if (name && !strcmp(name, ".text")) {
			*addr = (uint64_t)header.sh_addr;
			*offset = (uint64_t)header.sh_offset;
			err = 0;
			break;
		}
	}

err_out:
	close_elf(e, fd);
	return err;
}

static int syms__add_dso(struct syms *syms, struct map *map, const char *name)
{
	struct dso *dso = NULL;
	int i, type;
	void *tmp;

	for (i = 0; i < syms->dso_sz; i++) {
		if (!strcmp(syms->dsos[i].name, name)) {
			dso = &syms->dsos[i];
			break;
		}
	}

	if (!dso) {
		tmp = realloc(syms->dsos, (syms->dso_sz + 1) *
			      sizeof(*syms->dsos));
		if (!tmp)
			return -1;
		syms->dsos = tmp;
		dso = &syms->dsos[syms->dso_sz++];
		memset(dso, 0, sizeof(*dso));
		dso->name = strdup(name);
		dso->btf = btf__new_empty();
	}

	tmp = realloc(dso->ranges, (dso->range_sz + 1) * sizeof(*dso->ranges));
	if (!tmp)
		return -1;
	dso->ranges = tmp;
	dso->ranges[dso->range_sz].start = map->start_addr;
	dso->ranges[dso->range_sz].end = map->end_addr;
	dso->ranges[dso->range_sz].file_off = map->file_off;
	dso->range_sz++;
	type = get_elf_type(name);
	if (type == ET_EXEC) {
		dso->type = EXEC;
	} else if (type == ET_DYN) {
		dso->type = DYN;
		if (get_elf_text_scn_info(name, &dso->sh_addr, &dso->sh_offset) < 0)
			return -1;
	} else if (is_perf_map(name)) {
		dso->type = PERF_MAP;
	} else if (is_vdso(name)) {
		dso->type = VDSO;
	} else {
		dso->type = UNKNOWN;
	}
	return 0;
}

static struct dso *syms__find_dso(const struct syms *syms, unsigned long addr,
				  uint64_t *offset)
{
	struct load_range *range;
	struct dso *dso;
	int i, j;

	for (i = 0; i < syms->dso_sz; i++) {
		dso = &syms->dsos[i];
		for (j = 0; j < dso->range_sz; j++) {
			range = &dso->ranges[j];
			if (addr <= range->start || addr >= range->end)
				continue;
			if (dso->type == DYN || dso->type == VDSO) {
				/* Offset within the mmap */
				*offset = addr - range->start + range->file_off;
				/* Offset within the ELF for dyn symbol lookup */
				*offset += dso->sh_addr - dso->sh_offset;
			} else {
				*offset = addr;
			}

			return dso;
		}
	}

	return NULL;
}

static int dso__load_sym_table_from_perf_map(struct dso *dso)
{
	return -1;
}

static int dso__add_sym(struct dso *dso, const char *name, uint64_t start,
			uint64_t size)
{
	struct sym *sym;
	size_t new_cap;
	void *tmp;
	int off;

	off = btf__add_str(dso->btf, name);
	if (off < 0)
		return off;

	if (dso->syms_sz + 1 > dso->syms_cap) {
		new_cap = dso->syms_cap * 4 / 3;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(dso->syms, sizeof(*dso->syms) * new_cap);
		if (!tmp)
			return -1;
		dso->syms = tmp;
		dso->syms_cap = new_cap;
	}

	sym = &dso->syms[dso->syms_sz++];
	/* while constructing, re-use pointer as just a plain offset */
	sym->name = (void*)(unsigned long)off;
	sym->start = start;
	sym->size = size;
	sym->offset = 0;

	return 0;
}

static int sym_cmp(const void *p1, const void *p2)
{
	const struct sym *s1 = p1, *s2 = p2;

	if (s1->start == s2->start)
		return strcmp(s1->name, s2->name);
	return s1->start < s2->start ? -1 : 1;
}
