/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TRACE_HELPERS_H
#define __TRACE_HELPERS_H

#include <stdbool.h>

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC		1000000000ULL
#endif

struct ksym {
	const char *name;
	unsigned long addr;
	const char *module;
};

struct ksyms;

struct ksyms *ksyms__load(void);
void ksyms__free(struct ksyms *ksyms);
const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr);
const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name);

struct sym {
	const char *name;
	unsigned long start;
	unsigned long size;
	unsigned long offset;
};

struct syms;

struct syms *syms__load_pid(int tgid);
struct syms *syms__load_file(const char *fname);
void syms__free(struct syms *syms);
const struct sym *syms__map_addr(const struct syms *syms, unsigned long addr);
const struct sym *syms__map_addr_dso(const struct syms *syms, unsigned long addr,
				     char **dso_name, unsigned long *dso_offset);

struct syms_cache;

struct syms_cache *syms_cache__new(int nr);
struct syms *syms_cache__get_syms(struct syms_cache *syms_cache, int tgid);
void syms_cache__free(struct syms_cache *syms_cache);

#endif /* __TRACE_HELPERS_H */