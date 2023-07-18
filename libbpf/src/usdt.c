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

struct usdt_manager *usdt_manager_new(struct bpf_object *obj)
{
	static const char *ref_ctr_sysfs_path = "/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset";
	struct usdt_manager *man;
	struct bpf_map *specs_map, *ip_to_spec_id_map;

	specs_map = bpf_object__find_map_by_name(obj, "__bpf_usdt_specs");
	ip_to_spec_id_map = bpf_object__find_map_by_name(obj, "__bpf_usdt_ip_to_spec_id");
	if (!specs_map || !ip_to_spec_id_map) {
		pr_warn("usdt: failed to find USDT support BPF maps, did you forget to include bpf/usdt.bpf.h?\n");
		return ERR_PTR(-ESRCH);
	}

	man = calloc(1, sizeof(*man));
	if (!man)
		return ERR_PTR(-ENOMEM);

	man->specs_map = specs_map;
	man->ip_to_spec_id_map = ip_to_spec_id_map;

	/* Detect if BPF cookie is supported for kprobes.
	 * We don't need IP-to-ID mapping if we can use BPF cookies.
	 * Added in: 7adfc6c9b315 ("bpf: Add bpf_get_attach_cookie() BPF helper to access bpf_cookie value")
	 */
	man->has_bpf_cookie = kernel_supports(obj, FEAT_BPF_COOKIE);

	/* Detect kernel support for automatic refcounting of USDT semaphore.
	 * If this is not supported, USDTs with semaphores will not be supported.
	 * Added in: a6ca88b241d5 ("trace_uprobe: support reference counter in fd-based uprobe")
	 */
	man->has_sema_refcnt = faccessat(AT_FDCWD, ref_ctr_sysfs_path, F_OK, AT_EACCESS) == 0;

	return man;
}

void usdt_manager_free(struct usdt_manager *man)
{
	if (IS_ERR_OR_NULL(man))
		return;

	free(man->free_spec_ids);
	free(man);
}

static int sanity_check_usdt_elf(Elf *elf, const char *path)
{
	GElf_Ehdr ehdr;
	int endianness;

	if (elf_kind(elf) != ELF_K_ELF) {
		pr_warn("usdt: unrecognized ELF kind %d for '%s'\n", elf_kind(elf), path);
		return -EBADF;
	}

	switch (gelf_getclass(elf)) {
	case ELFCLASS64:
		if (sizeof(void *) != 8) {
			pr_warn("usdt: attaching to 64-bit ELF binary '%s' is not supported\n", path);
			return -EBADF;
		}
		break;
	case ELFCLASS32:
		if (sizeof(void *) != 4) {
			pr_warn("usdt: attaching to 32-bit ELF binary '%s' is not supported\n", path);
			return -EBADF;
		}
		break;
	default:
		pr_warn("usdt: unsupported ELF class for '%s'\n", path);
		return -EBADF;
	}

	if (!gelf_getehdr(elf, &ehdr))
		return -EINVAL;

	if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
		pr_warn("usdt: unsupported type of ELF binary '%s' (%d), only ET_EXEC and ET_DYN are supported\n",
			path, ehdr.e_type);
		return -EBADF;
	}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	endianness = ELFDATA2LSB;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	endianness = ELFDATA2MSB;
#else
# error "Unrecognized __BYTE_ORDER__"
#endif
	if (endianness != ehdr.e_ident[EI_DATA]) {
		pr_warn("usdt: ELF endianness mismatch for '%s'\n", path);
		return -EBADF;
	}

	return 0;
}

static int find_elf_sec_by_name(Elf *elf, const char *sec_name, GElf_Shdr *shdr, Elf_Scn **scn)
{
	Elf_Scn *sec = NULL;
	size_t shstrndx;

	if (elf_getshdrstrndx(elf, &shstrndx))
		return -EINVAL;

	/* check if ELF is corrupted and avoid calling elf_strptr if yes */
	if (!elf_rawdata(elf_getscn(elf, shstrndx), NULL))
		return -EINVAL;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *name;

		if (!gelf_getshdr(sec, shdr))
			return -EINVAL;

		name = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (name && strcmp(sec_name, name) == 0) {
			*scn = sec;
			return 0;
		}
	}

	return -ENOENT;
}

struct elf_seg {
	long start;
	long end;
	long offset;
	bool is_exec;
};

static int cmp_elf_segs(const void *_a, const void *_b)
{
	const struct elf_seg *a = _a;
	const struct elf_seg *b = _b;

	return a->start < b->start ? -1 : 1;
}

static int parse_elf_segs(Elf *elf, const char *path, struct elf_seg **segs, size_t *seg_cnt)
{
	GElf_Phdr phdr;
	size_t n;
	int i, err;
	struct elf_seg *seg;
	void *tmp;

	*seg_cnt = 0;

	if (elf_getphdrnum(elf, &n)) {
		err = -errno;
		return err;
	}

	for (i = 0; i < n; i++) {
		if (!gelf_getphdr(elf, i, &phdr)) {
			err = -errno;
			return err;
		}

		pr_debug("usdt: discovered PHDR #%d in '%s': vaddr 0x%lx memsz 0x%lx offset 0x%lx type 0x%lx flags 0x%lx\n",
			 i, path, (long)phdr.p_vaddr, (long)phdr.p_memsz, (long)phdr.p_offset,
			 (long)phdr.p_type, (long)phdr.p_flags);
		if (phdr.p_type != PT_LOAD)
			continue;

		tmp = libbpf_reallocarray(*segs, *seg_cnt + 1, sizeof(**segs));
		if (!tmp)
			return -ENOMEM;

		*segs = tmp;
		seg = *segs + *seg_cnt;
		(*seg_cnt)++;

		seg->start = phdr.p_vaddr;
		seg->end = phdr.p_vaddr + phdr.p_memsz;
		seg->offset = phdr.p_offset;
		seg->is_exec = phdr.p_flags & PF_X;
	}

	if (*seg_cnt == 0) {
		pr_warn("usdt: failed to find PT_LOAD program headers in '%s'\n", path);
		return -ESRCH;
	}

	qsort(*segs, *seg_cnt, sizeof(**segs), cmp_elf_segs);
	return 0;
}

static int parse_vma_segs(int pid, const char *lib_path, struct elf_seg **segs, size_t *seg_cnt)
{
	char path[PATH_MAX], line[PATH_MAX], mode[16];
	size_t seg_start, seg_end, seg_off;
	struct elf_seg *seg;
	int tmp_pid, i, err;
	FILE *f;

	*seg_cnt = 0;

	/* Handle containerized binaries only accessible from
	 * /proc/<pid>/root/<path>. They will be reported as just /<path> in
	 * /proc/<pid>/maps.
	 */
	if (sscanf(lib_path, "/proc/%d/root%s", &tmp_pid, path) == 2 && pid == tmp_pid)
		goto proceed;

	if (!realpath(lib_path, path)) {
		pr_warn("usdt: failed to get absolute path of '%s' (err %d), using path as is...\n",
			lib_path, -errno);
		libbpf_strlcpy(path, lib_path, sizeof(path));
	}

proceed:
	sprintf(line, "/proc/%d/maps", pid);
	f = fopen(line, "r");
	if (!f) {
		err = -errno;
		pr_warn("usdt: failed to open '%s' to get base addr of '%s': %d\n",
			line, lib_path, err);
		return err;
	}

	/* We need to handle lines with no path at the end:
	 *
	 * 7f5c6f5d1000-7f5c6f5d3000 rw-p 001c7000 08:04 21238613      /usr/lib64/libc-2.17.so
	 * 7f5c6f5d3000-7f5c6f5d8000 rw-p 00000000 00:00 0
	 * 7f5c6f5d8000-7f5c6f5d9000 r-xp 00000000 103:01 362990598    /data/users/andriin/linux/tools/bpf/usdt/libhello_usdt.so
	 */
	while (fscanf(f, "%zx-%zx %s %zx %*s %*d%[^\n]\n",
		      &seg_start, &seg_end, mode, &seg_off, line) == 5) {
		void *tmp;

		/* to handle no path case (see above) we need to capture line
		 * without skipping any whitespaces. So we need to strip
		 * leading whitespaces manually here
		 */
		i = 0;
		while (isblank(line[i]))
			i++;
		if (strcmp(line + i, path) != 0)
			continue;

		pr_debug("usdt: discovered segment for lib '%s': addrs %zx-%zx mode %s offset %zx\n",
			 path, seg_start, seg_end, mode, seg_off);

		/* ignore non-executable sections for shared libs */
		if (mode[2] != 'x')
			continue;

		tmp = libbpf_reallocarray(*segs, *seg_cnt + 1, sizeof(**segs));
		if (!tmp) {
			err = -ENOMEM;
			goto err_out;
		}

		*segs = tmp;
		seg = *segs + *seg_cnt;
		*seg_cnt += 1;

		seg->start = seg_start;
		seg->end = seg_end;
		seg->offset = seg_off;
		seg->is_exec = true;
	}

	if (*seg_cnt == 0) {
		pr_warn("usdt: failed to find '%s' (resolved to '%s') within PID %d memory mappings\n",
			lib_path, path, pid);
		err = -ESRCH;
		goto err_out;
	}

	qsort(*segs, *seg_cnt, sizeof(**segs), cmp_elf_segs);
	err = 0;
err_out:
	fclose(f);
	return err;
}

static struct elf_seg *find_elf_seg(struct elf_seg *segs, size_t seg_cnt, long virtaddr)
{
	struct elf_seg *seg;
	int i;

	/* for ELF binaries (both executables and shared libraries), we are
	 * given virtual address (absolute for executables, relative for
	 * libraries) which should match address range of [seg_start, seg_end)
	 */
	for (i = 0, seg = segs; i < seg_cnt; i++, seg++) {
		if (seg->start <= virtaddr && virtaddr < seg->end)
			return seg;
	}
	return NULL;
}

static struct elf_seg *find_vma_seg(struct elf_seg *segs, size_t seg_cnt, long offset)
{
	struct elf_seg *seg;
	int i;

	/* for VMA segments from /proc/<pid>/maps file, provided "address" is
	 * actually a file offset, so should be fall within logical
	 * offset-based range of [offset_start, offset_end)
	 */
	for (i = 0, seg = segs; i < seg_cnt; i++, seg++) {
		if (seg->offset <= offset && offset < seg->offset + (seg->end - seg->start))
			return seg;
	}
	return NULL;
}

static int parse_usdt_note(Elf *elf, const char *path, GElf_Nhdr *nhdr,
			   const char *data, size_t name_off, size_t desc_off,
			   struct usdt_note *usdt_note);

static int parse_usdt_spec(struct usdt_spec *spec, const struct usdt_note *note, __u64 usdt_cookie);

static int collect_usdt_targets(struct usdt_manager *man, Elf *elf, const char *path, pid_t pid,
				const char *usdt_provider, const char *usdt_name, __u64 usdt_cookie,
				struct usdt_target **out_targets, size_t *out_target_cnt)
{
	size_t off, name_off, desc_off, seg_cnt = 0, vma_seg_cnt = 0, target_cnt = 0;
	struct elf_seg *segs = NULL, *vma_segs = NULL;
	struct usdt_target *targets = NULL, *target;
	long base_addr = 0;
	Elf_Scn *notes_scn, *base_scn;
	GElf_Shdr base_shdr, notes_shdr;
	GElf_Ehdr ehdr;
	GElf_Nhdr nhdr;
	Elf_Data *data;
	int err;

	*out_targets = NULL;
	*out_target_cnt = 0;

	err = find_elf_sec_by_name(elf, USDT_NOTE_SEC, &notes_shdr, &notes_scn);
	if (err) {
		pr_warn("usdt: no USDT notes section (%s) found in '%s'\n", USDT_NOTE_SEC, path);
		return err;
	}

	if (notes_shdr.sh_type != SHT_NOTE || !gelf_getehdr(elf, &ehdr)) {
		pr_warn("usdt: invalid USDT notes section (%s) in '%s'\n", USDT_NOTE_SEC, path);
		return -EINVAL;
	}

	err = parse_elf_segs(elf, path, &segs, &seg_cnt);
	if (err) {
		pr_warn("usdt: failed to process ELF program segments for '%s': %d\n", path, err);
		goto err_out;
	}

	/* .stapsdt.base ELF section is optional, but is used for prelink
	 * offset compensation (see a big comment further below)
	 */
	if (find_elf_sec_by_name(elf, USDT_BASE_SEC, &base_shdr, &base_scn) == 0)
		base_addr = base_shdr.sh_addr;

	data = elf_getdata(notes_scn, 0);
	off = 0;
	while ((off = gelf_getnote(data, off, &nhdr, &name_off, &desc_off)) > 0) {
		long usdt_abs_ip, usdt_rel_ip, usdt_sema_off = 0;
		struct usdt_note note;
		struct elf_seg *seg = NULL;
		void *tmp;

		err = parse_usdt_note(elf, path, &nhdr, data->d_buf, name_off, desc_off, &note);
		if (err)
			goto err_out;

		if (strcmp(note.provider, usdt_provider) != 0 || strcmp(note.name, usdt_name) != 0)
			continue;

		usdt_abs_ip = note.loc_addr;
		if (base_addr)
			usdt_abs_ip += base_addr - note.base_addr;

		/* When attaching uprobes (which is what USDTs basically are)
		 * kernel expects file offset to be specified, not a relative
		 * virtual address, so we need to translate virtual address to
		 * file offset, for both ET_EXEC and ET_DYN binaries.
		 */
		seg = find_elf_seg(segs, seg_cnt, usdt_abs_ip);
		if (!seg) {
			err = -ESRCH;
			pr_warn("usdt: failed to find ELF program segment for '%s:%s' in '%s' at IP 0x%lx\n",
				usdt_provider, usdt_name, path, usdt_abs_ip);
			goto err_out;
		}
		if (!seg->is_exec) {
			err = -ESRCH;
			pr_warn("usdt: matched ELF binary '%s' segment [0x%lx, 0x%lx) for '%s:%s' at IP 0x%lx is not executable\n",
				path, seg->start, seg->end, usdt_provider, usdt_name,
				usdt_abs_ip);
			goto err_out;
		}
		/* translate from virtual address to file offset */
		usdt_rel_ip = usdt_abs_ip - seg->start + seg->offset;

		if (ehdr.e_type == ET_DYN && !man->has_bpf_cookie) {
			if (pid < 0) {
				pr_warn("usdt: attaching to shared libraries without specific PID is not supported on current kernel\n");
				err = -ENOTSUP;
				goto err_out;
			}

			/* vma_segs are lazily initialized only if necessary */
			if (vma_seg_cnt == 0) {
				err = parse_vma_segs(pid, path, &vma_segs, &vma_seg_cnt);
				if (err) {
					pr_warn("usdt: failed to get memory segments in PID %d for shared library '%s': %d\n",
						pid, path, err);
					goto err_out;
				}
			}

			seg = find_vma_seg(vma_segs, vma_seg_cnt, usdt_rel_ip);
			if (!seg) {
				err = -ESRCH;
				pr_warn("usdt: failed to find shared lib memory segment for '%s:%s' in '%s' at relative IP 0x%lx\n",
					usdt_provider, usdt_name, path, usdt_rel_ip);
				goto err_out;
			}

			usdt_abs_ip = seg->start - seg->offset + usdt_rel_ip;
		}

		pr_debug("usdt: probe for '%s:%s' in %s '%s': addr 0x%lx base 0x%lx (resolved abs_ip 0x%lx rel_ip 0x%lx) args '%s' in segment [0x%lx, 0x%lx) at offset 0x%lx\n",
			 usdt_provider, usdt_name, ehdr.e_type == ET_EXEC ? "exec" : "lib ", path,
			 note.loc_addr, note.base_addr, usdt_abs_ip, usdt_rel_ip, note.args,
			 seg ? seg->start : 0, seg ? seg->end : 0, seg ? seg->offset : 0);

		/* Adjust semaphore address to be a file offset */
		if (note.sema_addr) {
			if (!man->has_sema_refcnt) {
				pr_warn("usdt: kernel doesn't support USDT semaphore refcounting for '%s:%s' in '%s'\n",
					usdt_provider, usdt_name, path);
				err = -ENOTSUP;
				goto err_out;
			}

			seg = find_elf_seg(segs, seg_cnt, note.sema_addr);
			if (!seg) {
				err = -ESRCH;
				pr_warn("usdt: failed to find ELF loadable segment with semaphore of '%s:%s' in '%s' at 0x%lx\n",
					usdt_provider, usdt_name, path, note.sema_addr);
				goto err_out;
			}
			if (seg->is_exec) {
				err = -ESRCH;
				pr_warn("usdt: matched ELF binary '%s' segment [0x%lx, 0x%lx] for semaphore of '%s:%s' at 0x%lx is executable\n",
					path, seg->start, seg->end, usdt_provider, usdt_name,
					note.sema_addr);
				goto err_out;
			}

			usdt_sema_off = note.sema_addr - seg->start + seg->offset;

			pr_debug("usdt: sema  for '%s:%s' in %s '%s': addr 0x%lx base 0x%lx (resolved 0x%lx) in segment [0x%lx, 0x%lx] at offset 0x%lx\n",
				 usdt_provider, usdt_name, ehdr.e_type == ET_EXEC ? "exec" : "lib ",
				 path, note.sema_addr, note.base_addr, usdt_sema_off,
				 seg->start, seg->end, seg->offset);
		}

		/* Record adjusted addresses and offsets and parse USDT spec */
		tmp = libbpf_reallocarray(targets, target_cnt + 1, sizeof(*targets));
		if (!tmp) {
			err = -ENOMEM;
			goto err_out;
		}
		targets = tmp;

		target = &targets[target_cnt];
		memset(target, 0, sizeof(*target));

		target->abs_ip = usdt_abs_ip;
		target->rel_ip = usdt_rel_ip;
		target->sema_off = usdt_sema_off;

		/* notes.args references strings from Elf itself, so they can
		 * be referenced safely until elf_end() call
		 */
		target->spec_str = note.args;

		err = parse_usdt_spec(&target->spec, &note, usdt_cookie);
		if (err)
			goto err_out;

		target_cnt++;
	}

	*out_targets = targets;
	*out_target_cnt = target_cnt;
	err = target_cnt;

err_out:
	free(segs);
	free(vma_segs);
	if (err < 0)
		free(targets);
	return err;
}

struct bpf_link_usdt {
	struct bpf_link link;

	struct usdt_manager *usdt_man;

	size_t spec_cnt;
	int *spec_ids;

	size_t uprobe_cnt;
	struct {
		long abs_ip;
		struct bpf_link *link;
	} *uprobes;
};

static int bpf_link_usdt_detach(struct bpf_link *link)
{
	struct bpf_link_usdt *usdt_link = container_of(link, struct bpf_link_usdt, link);
	struct usdt_manager *man = usdt_link->usdt_man;
	int i;

	for (i = 0; i < usdt_link->uprobe_cnt; i++) {
		/* detach underlying uprobe link */
		bpf_link__destroy(usdt_link->uprobes[i].link);
		/* there is no need to update specs map because it will be
		 * unconditionally overwritten on subsequent USDT attaches,
		 * but if BPF cookies are not used we need to remove entry
		 * from ip_to_spec_id map, otherwise we'll run into false
		 * conflicting IP errors
		 */
		if (!man->has_bpf_cookie) {
			/* not much we can do about errors here */
			(void)bpf_map_delete_elem(bpf_map__fd(man->ip_to_spec_id_map),
						  &usdt_link->uprobes[i].abs_ip);
		}
	}

	/* try to return the list of previously used spec IDs to usdt_manager
	 * for future reuse for subsequent USDT attaches
	 */
	if (!man->free_spec_ids) {
		/* if there were no free spec IDs yet, just transfer our IDs */
		man->free_spec_ids = usdt_link->spec_ids;
		man->free_spec_cnt = usdt_link->spec_cnt;
		usdt_link->spec_ids = NULL;
	} else {
		/* otherwise concat IDs */
		size_t new_cnt = man->free_spec_cnt + usdt_link->spec_cnt;
		int *new_free_ids;

		new_free_ids = libbpf_reallocarray(man->free_spec_ids, new_cnt,
						   sizeof(*new_free_ids));
		/* If we couldn't resize free_spec_ids, we'll just leak
		 * a bunch of free IDs; this is very unlikely to happen and if
		 * system is so exhausted on memory, it's the least of user's
		 * concerns, probably.
		 * So just do our best here to return those IDs to usdt_manager.
		 */
		if (new_free_ids) {
			memcpy(new_free_ids + man->free_spec_cnt, usdt_link->spec_ids,
			       usdt_link->spec_cnt * sizeof(*usdt_link->spec_ids));
			man->free_spec_ids = new_free_ids;
			man->free_spec_cnt = new_cnt;
		}
	}

	return 0;
}

static void bpf_link_usdt_dealloc(struct bpf_link *link)
{
	struct bpf_link_usdt *usdt_link = container_of(link, struct bpf_link_usdt, link);

	free(usdt_link->spec_ids);
	free(usdt_link->uprobes);
	free(usdt_link);
}

static size_t specs_hash_fn(long key, void *ctx)
{
	return str_hash((char *)key);
}

static bool specs_equal_fn(long key1, long key2, void *ctx)
{
	return strcmp((char *)key1, (char *)key2) == 0;
}

static int allocate_spec_id(struct usdt_manager *man, struct hashmap *specs_hash,
			    struct bpf_link_usdt *link, struct usdt_target *target,
			    int *spec_id, bool *is_new)
{
	long tmp;
	void *new_ids;
	int err;

	/* check if we already allocated spec ID for this spec string */
	if (hashmap__find(specs_hash, target->spec_str, &tmp)) {
		*spec_id = tmp;
		*is_new = false;
		return 0;
	}

	/* otherwise it's a new ID that needs to be set up in specs map and
	 * returned back to usdt_manager when USDT link is detached
	 */
	new_ids = libbpf_reallocarray(link->spec_ids, link->spec_cnt + 1, sizeof(*link->spec_ids));
	if (!new_ids)
		return -ENOMEM;
	link->spec_ids = new_ids;

	/* get next free spec ID, giving preference to free list, if not empty */
	if (man->free_spec_cnt) {
		*spec_id = man->free_spec_ids[man->free_spec_cnt - 1];

		/* cache spec ID for current spec string for future lookups */
		err = hashmap__add(specs_hash, target->spec_str, *spec_id);
		if (err)
			 return err;

		man->free_spec_cnt--;
	} else {
		/* don't allocate spec ID bigger than what fits in specs map */
		if (man->next_free_spec_id >= bpf_map__max_entries(man->specs_map))
			return -E2BIG;

		*spec_id = man->next_free_spec_id;

		/* cache spec ID for current spec string for future lookups */
		err = hashmap__add(specs_hash, target->spec_str, *spec_id);
		if (err)
			 return err;

		man->next_free_spec_id++;
	}

	/* remember new spec ID in the link for later return back to free list on detach */
	link->spec_ids[link->spec_cnt] = *spec_id;
	link->spec_cnt++;
	*is_new = true;
	return 0;
}

struct bpf_link *usdt_manager_attach_usdt(struct usdt_manager *man, const struct bpf_program *prog,
					  pid_t pid, const char *path,
					  const char *usdt_provider, const char *usdt_name,
					  __u64 usdt_cookie)
{
	int i, fd, err, spec_map_fd, ip_map_fd;
	LIBBPF_OPTS(bpf_uprobe_opts, opts);
	struct hashmap *specs_hash = NULL;
	struct bpf_link_usdt *link = NULL;
	struct usdt_target *targets = NULL;
	size_t target_cnt;
	Elf *elf;

	spec_map_fd = bpf_map__fd(man->specs_map);
	ip_map_fd = bpf_map__fd(man->ip_to_spec_id_map);

	/* TODO: perform path resolution similar to uprobe's */
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		pr_warn("usdt: failed to open ELF binary '%s': %d\n", path, err);
		return libbpf_err_ptr(err);
	}

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
		err = -EBADF;
		pr_warn("usdt: failed to parse ELF binary '%s': %s\n", path, elf_errmsg(-1));
		goto err_out;
	}

	err = sanity_check_usdt_elf(elf, path);
	if (err)
		goto err_out;

	/* normalize PID filter */
	if (pid < 0)
		pid = -1;
	else if (pid == 0)
		pid = getpid();

	/* discover USDT in given binary, optionally limiting
	 * activations to a given PID, if pid > 0
	 */
	err = collect_usdt_targets(man, elf, path, pid, usdt_provider, usdt_name,
				   usdt_cookie, &targets, &target_cnt);
	if (err <= 0) {
		err = (err == 0) ? -ENOENT : err;
		goto err_out;
	}

	specs_hash = hashmap__new(specs_hash_fn, specs_equal_fn, NULL);
	if (IS_ERR(specs_hash)) {
		err = PTR_ERR(specs_hash);
		goto err_out;
	}

	link = calloc(1, sizeof(*link));
	if (!link) {
		err = -ENOMEM;
		goto err_out;
	}

	link->usdt_man = man;
	link->link.detach = &bpf_link_usdt_detach;
	link->link.dealloc = &bpf_link_usdt_dealloc;

	link->uprobes = calloc(target_cnt, sizeof(*link->uprobes));
	if (!link->uprobes) {
		err = -ENOMEM;
		goto err_out;
	}

	for (i = 0; i < target_cnt; i++) {
		struct usdt_target *target = &targets[i];
		struct bpf_link *uprobe_link;
		bool is_new;
		int spec_id;

		/* Spec ID can be either reused or newly allocated. If it is
		 * newly allocated, we'll need to fill out spec map, otherwise
		 * entire spec should be valid and can be just used by a new
		 * uprobe. We reuse spec when USDT arg spec is identical. We
		 * also never share specs between two different USDT
		 * attachments ("links"), so all the reused specs already
		 * share USDT cookie value implicitly.
		 */
		err = allocate_spec_id(man, specs_hash, link, target, &spec_id, &is_new);
		if (err)
			goto err_out;

		if (is_new && bpf_map_update_elem(spec_map_fd, &spec_id, &target->spec, BPF_ANY)) {
			err = -errno;
			pr_warn("usdt: failed to set USDT spec #%d for '%s:%s' in '%s': %d\n",
				spec_id, usdt_provider, usdt_name, path, err);
			goto err_out;
		}
		if (!man->has_bpf_cookie &&
		    bpf_map_update_elem(ip_map_fd, &target->abs_ip, &spec_id, BPF_NOEXIST)) {
			err = -errno;
			if (err == -EEXIST) {
				pr_warn("usdt: IP collision detected for spec #%d for '%s:%s' in '%s'\n",
				        spec_id, usdt_provider, usdt_name, path);
			} else {
				pr_warn("usdt: failed to map IP 0x%lx to spec #%d for '%s:%s' in '%s': %d\n",
					target->abs_ip, spec_id, usdt_provider, usdt_name,
					path, err);
			}
			goto err_out;
		}

		opts.ref_ctr_offset = target->sema_off;
		opts.bpf_cookie = man->has_bpf_cookie ? spec_id : 0;
		uprobe_link = bpf_program__attach_uprobe_opts(prog, pid, path,
							      target->rel_ip, &opts);
		err = libbpf_get_error(uprobe_link);
		if (err) {
			pr_warn("usdt: failed to attach uprobe #%d for '%s:%s' in '%s': %d\n",
				i, usdt_provider, usdt_name, path, err);
			goto err_out;
		}

		link->uprobes[i].link = uprobe_link;
		link->uprobes[i].abs_ip = target->abs_ip;
		link->uprobe_cnt++;
	}

	free(targets);
	hashmap__free(specs_hash);
	elf_end(elf);
	close(fd);

	return &link->link;

err_out:
	if (link)
		bpf_link__destroy(&link->link);
	free(targets);
	hashmap__free(specs_hash);
	if (elf)
		elf_end(elf);
	close(fd);
	return libbpf_err_ptr(err);
}

/* Parse out USDT ELF note from '.note.stapsdt' section.
 * Logic inspired by perf's code.
 */
static int parse_usdt_note(Elf *elf, const char *path, GElf_Nhdr *nhdr,
			   const char *data, size_t name_off, size_t desc_off,
			   struct usdt_note *note)
{
	const char *provider, *name, *args;
	long addrs[3];
	size_t len;

	/* sanity check USDT note name and type first */
	if (strncmp(data + name_off, USDT_NOTE_NAME, nhdr->n_namesz) != 0)
		return -EINVAL;
	if (nhdr->n_type != USDT_NOTE_TYPE)
		return -EINVAL;

	/* sanity check USDT note contents ("description" in ELF terminology) */
	len = nhdr->n_descsz;
	data = data + desc_off;

	/* +3 is the very minimum required to store three empty strings */
	if (len < sizeof(addrs) + 3)
		return -EINVAL;

	/* get location, base, and semaphore addrs */
	memcpy(&addrs, data, sizeof(addrs));

	/* parse string fields: provider, name, args */
	provider = data + sizeof(addrs);

	name = (const char *)memchr(provider, '\0', data + len - provider);
	if (!name) /* non-zero-terminated provider */
		return -EINVAL;
	name++;
	if (name >= data + len || *name == '\0') /* missing or empty name */
		return -EINVAL;

	args = memchr(name, '\0', data + len - name);
	if (!args) /* non-zero-terminated name */
		return -EINVAL;
	++args;
	if (args >= data + len) /* missing arguments spec */
		return -EINVAL;

	note->provider = provider;
	note->name = name;
	if (*args == '\0' || *args == ':')
		note->args = "";
	else
		note->args = args;
	note->loc_addr = addrs[0];
	note->base_addr = addrs[1];
	note->sema_addr = addrs[2];

	return 0;
}

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

