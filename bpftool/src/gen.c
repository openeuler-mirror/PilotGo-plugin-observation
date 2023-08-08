#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/err.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_internal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <bpf/btf.h>

#include "json_writer.h"
#include "main.h"

#define MAX_OBJ_NAME_LEN 64

static void sanitize_identifier(char *name)
{
	int i;

	for (i = 0; name[i]; i++)
		if (!isalnum(name[i]) && name[i] != '_')
			name[i] = '_';
}

static bool str_has_prefix(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

static bool str_has_suffix(const char *str, const char *suffix)
{
	size_t i, n1 = strlen(str), n2 = strlen(suffix);

	if (n1 < n2)
		return false;

	for (i = 0; i < n2; i++) {
		if (str[n1 - i - 1] != suffix[n2 - i - 1])
			return false;
	}

	return true;
}

static void get_obj_name(char *name, const char *file)
{
	strncpy(name, basename(file), MAX_OBJ_NAME_LEN - 1);
	name[MAX_OBJ_NAME_LEN - 1] = '\0';
	if (str_has_suffix(name, ".o"))
		name[strlen(name) - 2] = '\0';
	sanitize_identifier(name);
}

static void get_header_guard(char *guard, const char *obj_name, const char *suffix)
{
	int i;

	sprintf(guard, "__%s_%s__", obj_name, suffix);
	for (i = 0; guard[i]; i++)
		guard[i] = toupper(guard[i]);
}

static bool get_map_ident(const struct bpf_map *map, char *buf, size_t buf_sz)
{
	static const char *sfxs[] = { ".data", ".rodata", ".bss", ".kconfig" };
	const char *name = bpf_map__name(map);
	int i, n;

	if (!bpf_map__is_internal(map)) {
		snprintf(buf, buf_sz, "%s", name);
		return true;
	}

	for  (i = 0, n = ARRAY_SIZE(sfxs); i < n; i++) {
		const char *sfx = sfxs[i], *p;

		p = strstr(name, sfx);
		if (p) {
			snprintf(buf, buf_sz, "%s", p + 1);
			sanitize_identifier(buf);
			return true;
		}
	}

	return false;
}

static bool get_datasec_ident(const char *sec_name, char *buf, size_t buf_sz)
{
	static const char *pfxs[] = { ".data", ".rodata", ".bss", ".kconfig" };
	int i, n;

	for  (i = 0, n = ARRAY_SIZE(pfxs); i < n; i++) {
		const char *pfx = pfxs[i];

		if (str_has_prefix(sec_name, pfx)) {
			snprintf(buf, buf_sz, "%s", sec_name + 1);
			sanitize_identifier(buf);
			return true;
		}
	}

	return false;
}

static void codegen_btf_dump_printf(void *ctx, const char *fmt, va_list args)
{
	vprintf(fmt, args);
}

static int codegen_datasec_def(struct bpf_object *obj,
			       struct btf *btf,
			       struct btf_dump *d,
			       const struct btf_type *sec,
			       const char *obj_name)
{
	const char *sec_name = btf__name_by_offset(btf, sec->name_off);
	const struct btf_var_secinfo *sec_var = btf_var_secinfos(sec);
	int i, err, off = 0, pad_cnt = 0, vlen = btf_vlen(sec);
	char var_ident[256], sec_ident[256];
	bool strip_mods = false;

	if (!get_datasec_ident(sec_name, sec_ident, sizeof(sec_ident)))
		return 0;

	if (strcmp(sec_name, ".kconfig") != 0)
		strip_mods = true;

	printf("	struct %s__%s {\n", obj_name, sec_ident);
	for (i = 0; i < vlen; i++, sec_var++) {
		const struct btf_type *var = btf__type_by_id(btf, sec_var->type);
		const char *var_name = btf__name_by_offset(btf, var->name_off);
		DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts,
			.field_name = var_ident,
			.indent_level = 2,
			.strip_mods = strip_mods,
		);
		int need_off = sec_var->offset, align_off, align;
		__u32 var_type_id = var->type;

		if (btf_var(var)->linkage == BTF_VAR_STATIC)
			continue;

		if (off > need_off) {
			p_err("Something is wrong for %s's variable #%d: need offset %d, already at %d.\n",
			      sec_name, i, need_off, off);
			return -EINVAL;
		}

		align = btf__align_of(btf, var->type);
		if (align <= 0) {
			p_err("Failed to determine alignment of variable '%s': %d",
			      var_name, align);
			return -EINVAL;
		}
		if (align > 4)
			align = 4;

		align_off = (off + align - 1) / align * align;
		if (align_off != need_off) {
			printf("\t\tchar __pad%d[%d];\n",
			       pad_cnt, need_off - off);
			pad_cnt++;
		}

		var_ident[0] = '\0';
		strncat(var_ident, var_name, sizeof(var_ident) - 1);
		sanitize_identifier(var_ident);

		printf("\t\t");
		err = btf_dump__emit_type_decl(d, var_type_id, &opts);
		if (err)
			return err;
		printf(";\n");

		off = sec_var->offset + sec_var->size;
	}
	printf("	} *%s;\n", sec_ident);
	return 0;
}

static const struct btf_type *find_type_for_map(struct btf *btf, const char *map_ident)
{
	int n = btf__type_cnt(btf), i;
	char sec_ident[256];

	for (i = 1; i < n; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		const char *name;

		if (!btf_is_datasec(t))
			continue;

		name = btf__str_by_offset(btf, t->name_off);
		if (!get_datasec_ident(name, sec_ident, sizeof(sec_ident)))
			continue;

		if (strcmp(sec_ident, map_ident) == 0)
			return t;
	}
	return NULL;
}

static bool is_internal_mmapable_map(const struct bpf_map *map, char *buf, size_t sz)
{
	if (!bpf_map__is_internal(map) || !(bpf_map__map_flags(map) & BPF_F_MMAPABLE))
		return false;

	if (!get_map_ident(map, buf, sz))
		return false;

	return true;
}

static int codegen_datasecs(struct bpf_object *obj, const char *obj_name)
{
	struct btf *btf = bpf_object__btf(obj);
	struct btf_dump *d;
	struct bpf_map *map;
	const struct btf_type *sec;
	char map_ident[256];
	int err = 0;

	d = btf_dump__new(btf, codegen_btf_dump_printf, NULL, NULL);
	if (!d)
		return -errno;

	bpf_object__for_each_map(map, obj) {
		if (!is_internal_mmapable_map(map, map_ident, sizeof(map_ident)))
			continue;

		sec = find_type_for_map(btf, map_ident);

		if (!sec) {
			printf("	struct %s__%s {\n", obj_name, map_ident);
			printf("	} *%s;\n", map_ident);
		} else {
			err = codegen_datasec_def(obj, btf, d, sec, obj_name);
			if (err)
				goto out;
		}
	}


out:
	btf_dump__free(d);
	return err;
}

static bool btf_is_ptr_to_func_proto(const struct btf *btf,
				     const struct btf_type *v)
{
	return btf_is_ptr(v) && btf_is_func_proto(btf__type_by_id(btf, v->type));
}

static int codegen_subskel_datasecs(struct bpf_object *obj, const char *obj_name)
{
	struct btf *btf = bpf_object__btf(obj);
	struct btf_dump *d;
	struct bpf_map *map;
	const struct btf_type *sec, *var;
	const struct btf_var_secinfo *sec_var;
	int i, err = 0, vlen;
	char map_ident[256], sec_ident[256];
	bool strip_mods = false, needs_typeof = false;
	const char *sec_name, *var_name;
	__u32 var_type_id;

	d = btf_dump__new(btf, codegen_btf_dump_printf, NULL, NULL);
	if (!d)
		return -errno;

	bpf_object__for_each_map(map, obj) {
		if (!is_internal_mmapable_map(map, map_ident, sizeof(map_ident)))
			continue;

		sec = find_type_for_map(btf, map_ident);
		if (!sec)
			continue;

		sec_name = btf__name_by_offset(btf, sec->name_off);
		if (!get_datasec_ident(sec_name, sec_ident, sizeof(sec_ident)))
			continue;

		strip_mods = strcmp(sec_name, ".kconfig") != 0;
		printf("	struct %s__%s {\n", obj_name, sec_ident);

		sec_var = btf_var_secinfos(sec);
		vlen = btf_vlen(sec);
		for (i = 0; i < vlen; i++, sec_var++) {
			DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts,
				.indent_level = 2,
				.strip_mods = strip_mods,
				.field_name = "",
			);

			var = btf__type_by_id(btf, sec_var->type);
			var_name = btf__name_by_offset(btf, var->name_off);
			var_type_id = var->type;

			if (btf_var(var)->linkage == BTF_VAR_STATIC)
				continue;

			var = skip_mods_and_typedefs(btf, var->type, NULL);

			printf("\t\t");
			needs_typeof = btf_is_array(var) || btf_is_ptr_to_func_proto(btf, var);
			if (needs_typeof)
				printf("typeof(");

			err = btf_dump__emit_type_decl(d, var_type_id, &opts);
			if (err)
				goto out;

			if (needs_typeof)
				printf(")");

			printf(" *%s;\n", var_name);
		}
		printf("	} %s;\n", sec_ident);
	}

out:
	btf_dump__free(d);
	return err;
}

static void codegen(const char *template, ...)
{
	const char *src, *end;
	int skip_tabs = 0, n;
	char *s, *dst;
	va_list args;
	char c;

	n = strlen(template);
	s = malloc(n + 1);
	if (!s)
		exit(-1);
	src = template;
	dst = s;

	while ((c = *src++)) {
		if (c == '\t') {
			skip_tabs++;
		} else if (c == '\n') {
			break;
		} else {
			p_err("unrecognized character at pos %td in template '%s': '%c'",
			      src - template - 1, template, c);
			free(s);
			exit(-1);
		}
	}

	while (*src) {
		for (n = skip_tabs; n > 0; n--, src++) {
			if (*src != '\t') {
				p_err("not enough tabs at pos %td in template '%s'",
				      src - template - 1, template);
				free(s);
				exit(-1);
			}
		}
		end = strchrnul(src, '\n');
		for (n = end - src; n > 0 && isspace(src[n - 1]); n--)
			;
		memcpy(dst, src, n);
		dst += n;
		if (*end)
			*dst++ = '\n';
		src = *end ? end + 1 : end;
	}
	*dst++ = '\0';

	va_start(args, template);
	n = vprintf(s, args);
	va_end(args);

	free(s);
}

static void print_hex(const char *data, int data_sz)
{
	int i, len;

	for (i = 0, len = 0; i < data_sz; i++) {
		int w = data[i] ? 4 : 2;

		len += w;
		if (len > 78) {
			printf("\\\n");
			len = w;
		}
		if (!data[i])
			printf("\\0");
		else
			printf("\\x%02x", (unsigned char)data[i]);
	}
}

static size_t bpf_map_mmap_sz(const struct bpf_map *map)
{
	long page_sz = sysconf(_SC_PAGE_SIZE);
	size_t map_sz;

	map_sz = (size_t)roundup(bpf_map__value_size(map), 8) * bpf_map__max_entries(map);
	map_sz = roundup(map_sz, page_sz);
	return map_sz;
}

static void codegen_asserts(struct bpf_object *obj, const char *obj_name)
{
	struct btf *btf = bpf_object__btf(obj);
	struct bpf_map *map;
	struct btf_var_secinfo *sec_var;
	int i, vlen;
	const struct btf_type *sec;
	char map_ident[256], var_ident[256];

	if (!btf)
		return;

	codegen("\
		\n\
		__attribute__((unused)) static void			    \n\
		%1$s__assert(struct %1$s *s __attribute__((unused)))	    \n\
		{							    \n\
		#ifdef __cplusplus					    \n\
		#define _Static_assert static_assert			    \n\
		#endif							    \n\
		", obj_name);

	bpf_object__for_each_map(map, obj) {
		if (!is_internal_mmapable_map(map, map_ident, sizeof(map_ident)))
			continue;

		sec = find_type_for_map(btf, map_ident);
		if (!sec) {
			continue;
		}

		sec_var = btf_var_secinfos(sec);
		vlen =  btf_vlen(sec);

		for (i = 0; i < vlen; i++, sec_var++) {
			const struct btf_type *var = btf__type_by_id(btf, sec_var->type);
			const char *var_name = btf__name_by_offset(btf, var->name_off);
			long var_size;

			if (btf_var(var)->linkage == BTF_VAR_STATIC)
				continue;

			var_size = btf__resolve_size(btf, var->type);
			if (var_size < 0)
				continue;

			var_ident[0] = '\0';
			strncat(var_ident, var_name, sizeof(var_ident) - 1);
			sanitize_identifier(var_ident);

			printf("\t_Static_assert(sizeof(s->%s->%s) == %ld, \"unexpected size of '%s'\");\n",
			       map_ident, var_ident, var_size, var_ident);
		}
	}
	codegen("\
		\n\
		#ifdef __cplusplus					    \n\
		#undef _Static_assert					    \n\
		#endif							    \n\
		}							    \n\
		");
}

static void codegen_attach_detach(struct bpf_object *obj, const char *obj_name)
{
	struct bpf_program *prog;

	bpf_object__for_each_program(prog, obj) {
		const char *tp_name;

		codegen("\
			\n\
			\n\
			static inline int					    \n\
			%1$s__%2$s__attach(struct %1$s *skel)			    \n\
			{							    \n\
				int prog_fd = skel->progs.%2$s.prog_fd;		    \n\
			", obj_name, bpf_program__name(prog));

		switch (bpf_program__type(prog)) {
		case BPF_PROG_TYPE_RAW_TRACEPOINT:
			tp_name = strchr(bpf_program__section_name(prog), '/') + 1;
			printf("\tint fd = skel_raw_tracepoint_open(\"%s\", prog_fd);\n", tp_name);
			break;
		case BPF_PROG_TYPE_TRACING:
		case BPF_PROG_TYPE_LSM:
			if (bpf_program__expected_attach_type(prog) == BPF_TRACE_ITER)
				printf("\tint fd = skel_link_create(prog_fd, 0, BPF_TRACE_ITER);\n");
			else
				printf("\tint fd = skel_raw_tracepoint_open(NULL, prog_fd);\n");
			break;
		default:
			printf("\tint fd = ((void)prog_fd, 0); /* auto-attach not supported */\n");
			break;
		}
		codegen("\
			\n\
										    \n\
				if (fd > 0)					    \n\
					skel->links.%1$s_fd = fd;		    \n\
				return fd;					    \n\
			}							    \n\
			", bpf_program__name(prog));
	}

	codegen("\
		\n\
									    \n\
		static inline int					    \n\
		%1$s__attach(struct %1$s *skel)				    \n\
		{							    \n\
			int ret = 0;					    \n\
									    \n\
		", obj_name);

	bpf_object__for_each_program(prog, obj) {
		codegen("\
			\n\
				ret = ret < 0 ? ret : %1$s__%2$s__attach(skel);   \n\
			", obj_name, bpf_program__name(prog));
	}

	codegen("\
		\n\
			return ret < 0 ? ret : 0;			    \n\
		}							    \n\
									    \n\
		static inline void					    \n\
		%1$s__detach(struct %1$s *skel)				    \n\
		{							    \n\
		", obj_name);

	bpf_object__for_each_program(prog, obj) {
		codegen("\
			\n\
				skel_closenz(skel->links.%1$s_fd);	    \n\
			", bpf_program__name(prog));
	}

	codegen("\
		\n\
		}							    \n\
		");
}

static void codegen_destroy(struct bpf_object *obj, const char *obj_name)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	char ident[256];

	codegen("\
		\n\
		static void						    \n\
		%1$s__destroy(struct %1$s *skel)			    \n\
		{							    \n\
			if (!skel)					    \n\
				return;					    \n\
			%1$s__detach(skel);				    \n\
		",
		obj_name);

	bpf_object__for_each_program(prog, obj) {
		codegen("\
			\n\
				skel_closenz(skel->progs.%1$s.prog_fd);	    \n\
			", bpf_program__name(prog));
	}

	bpf_object__for_each_map(map, obj) {
		if (!get_map_ident(map, ident, sizeof(ident)))
			continue;
		if (bpf_map__is_internal(map) &&
		    (bpf_map__map_flags(map) & BPF_F_MMAPABLE))
			printf("\tskel_free_map_data(skel->%1$s, skel->maps.%1$s.initial_value, %2$zd);\n",
			       ident, bpf_map_mmap_sz(map));
		codegen("\
			\n\
				skel_closenz(skel->maps.%1$s.map_fd);	    \n\
			", ident);
	}
	codegen("\
		\n\
			skel_free(skel);				    \n\
		}							    \n\
		",
		obj_name);
}

static int gen_trace(struct bpf_object *obj, const char *obj_name, const char *header_guard)
{
	DECLARE_LIBBPF_OPTS(gen_loader_opts, opts);
	struct bpf_map *map;
	char ident[256];
	int err = 0;

	err = bpf_object__gen_loader(obj, &opts);
	if (err)
		return err;

	err = bpf_object__load(obj);
	if (err) {
		p_err("failed to load object file");
		goto out;
	}
	codegen("\
		\n\
		};							    \n\
		", obj_name);


	codegen_attach_detach(obj, obj_name);

	codegen_destroy(obj, obj_name);

	codegen("\
		\n\
		static inline struct %1$s *				    \n\
		%1$s__open(void)					    \n\
		{							    \n\
			struct %1$s *skel;				    \n\
									    \n\
			skel = skel_alloc(sizeof(*skel));		    \n\
			if (!skel)					    \n\
				goto cleanup;				    \n\
			skel->ctx.sz = (void *)&skel->links - (void *)skel; \n\
		",
		obj_name, opts.data_sz);
	bpf_object__for_each_map(map, obj) {
		const void *mmap_data = NULL;
		size_t mmap_size = 0;

		if (!is_internal_mmapable_map(map, ident, sizeof(ident)))
			continue;

		codegen("\
		\n\
			skel->%1$s = skel_prep_map_data((void *)\"\\	    \n\
		", ident);
		mmap_data = bpf_map__initial_value(map, &mmap_size);
		print_hex(mmap_data, mmap_size);
		codegen("\
		\n\
		\", %1$zd, %2$zd);					    \n\
			if (!skel->%3$s)				    \n\
				goto cleanup;				    \n\
			skel->maps.%3$s.initial_value = (__u64) (long) skel->%3$s;\n\
		", bpf_map_mmap_sz(map), mmap_size, ident);
	}
	codegen("\
		\n\
			return skel;					    \n\
		cleanup:						    \n\
			%1$s__destroy(skel);				    \n\
			return NULL;					    \n\
		}							    \n\
									    \n\
		static inline int					    \n\
		%1$s__load(struct %1$s *skel)				    \n\
		{							    \n\
			struct bpf_load_and_run_opts opts = {};		    \n\
			int err;					    \n\
									    \n\
			opts.ctx = (struct bpf_loader_ctx *)skel;	    \n\
			opts.data_sz = %2$d;				    \n\
			opts.data = (void *)\"\\			    \n\
		",
		obj_name, opts.data_sz);
	print_hex(opts.data, opts.data_sz);
	codegen("\
		\n\
		\";							    \n\
		");

	codegen("\
		\n\
			opts.insns_sz = %d;				    \n\
			opts.insns = (void *)\"\\			    \n\
		",
		opts.insns_sz);
	print_hex(opts.insns, opts.insns_sz);
	codegen("\
		\n\
		\";							    \n\
			err = bpf_load_and_run(&opts);			    \n\
			if (err < 0)					    \n\
				return err;				    \n\
		", obj_name);
	bpf_object__for_each_map(map, obj) {
		const char *mmap_flags;

		if (!is_internal_mmapable_map(map, ident, sizeof(ident)))
			continue;

		if (bpf_map__map_flags(map) & BPF_F_RDONLY_PROG)
			mmap_flags = "PROT_READ";
		else
			mmap_flags = "PROT_READ | PROT_WRITE";

		codegen("\
		\n\
			skel->%1$s = skel_finalize_map_data(&skel->maps.%1$s.initial_value,  \n\
							%2$zd, %3$s, skel->maps.%1$s.map_fd);\n\
			if (!skel->%1$s)				    \n\
				return -ENOMEM;				    \n\
			",
		       ident, bpf_map_mmap_sz(map), mmap_flags);
	}
	codegen("\
		\n\
			return 0;					    \n\
		}							    \n\
									    \n\
		static inline struct %1$s *				    \n\
		%1$s__open_and_load(void)				    \n\
		{							    \n\
			struct %1$s *skel;				    \n\
									    \n\
			skel = %1$s__open();				    \n\
			if (!skel)					    \n\
				return NULL;				    \n\
			if (%1$s__load(skel)) {				    \n\
				%1$s__destroy(skel);			    \n\
				return NULL;				    \n\
			}						    \n\
			return skel;					    \n\
		}							    \n\
									    \n\
		", obj_name);

	codegen_asserts(obj, obj_name);

	codegen("\
		\n\
									    \n\
		#endif /* %s */						    \n\
		",
		header_guard);
	err = 0;
out:
	return err;
}

static void
codegen_maps_skeleton(struct bpf_object *obj, size_t map_cnt, bool mmaped)
{
	struct bpf_map *map;
	char ident[256];
	size_t i;

	if (!map_cnt)
		return;

	codegen("\
		\n\
									\n\
			/* maps */				    \n\
			s->map_cnt = %zu;			    \n\
			s->map_skel_sz = sizeof(*s->maps);	    \n\
			s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);\n\
			if (!s->maps) {				    \n\
				err = -ENOMEM;			    \n\
				goto err;			    \n\
			}					    \n\
		",
		map_cnt
	);
	i = 0;
	bpf_object__for_each_map(map, obj) {
		if (!get_map_ident(map, ident, sizeof(ident)))
			continue;

		codegen("\
			\n\
									\n\
				s->maps[%zu].name = \"%s\";	    \n\
				s->maps[%zu].map = &obj->maps.%s;   \n\
			",
			i, bpf_map__name(map), i, ident);
		if (mmaped && is_internal_mmapable_map(map, ident, sizeof(ident))) {
			printf("\ts->maps[%zu].mmaped = (void **)&obj->%s;\n",
				i, ident);
		}
		i++;
	}
}

static void
codegen_progs_skeleton(struct bpf_object *obj, size_t prog_cnt, bool populate_links)
{
	struct bpf_program *prog;
	int i;

	if (!prog_cnt)
		return;

	codegen("\
		\n\
									\n\
			/* programs */				    \n\
			s->prog_cnt = %zu;			    \n\
			s->prog_skel_sz = sizeof(*s->progs);	    \n\
			s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);\n\
			if (!s->progs) {			    \n\
				err = -ENOMEM;			    \n\
				goto err;			    \n\
			}					    \n\
		",
		prog_cnt
	);
	i = 0;
	bpf_object__for_each_program(prog, obj) {
		codegen("\
			\n\
									\n\
				s->progs[%1$zu].name = \"%2$s\";    \n\
				s->progs[%1$zu].prog = &obj->progs.%2$s;\n\
			",
			i, bpf_program__name(prog));

		if (populate_links) {
			codegen("\
				\n\
					s->progs[%1$zu].link = &obj->links.%2$s;\n\
				",
				i, bpf_program__name(prog));
		}
		i++;
	}
}

static int do_skeleton(int argc, char **argv)
{
	char header_guard[MAX_OBJ_NAME_LEN + sizeof("__SKEL_H__")];
	size_t map_cnt = 0, prog_cnt = 0, file_sz, mmap_sz;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	char obj_name[MAX_OBJ_NAME_LEN] = "", *obj_data;
	struct bpf_object *obj = NULL;
	const char *file;
	char ident[256];
	struct bpf_program *prog;
	int fd, err = -1;
	struct bpf_map *map;
	struct btf *btf;
	struct stat st;

	if (!REQ_ARGS(1)) {
		usage();
		return -1;
	}
	file = GET_ARG();

	while (argc) {
		if (!REQ_ARGS(2))
			return -1;

		if (is_prefix(*argv, "name")) {
			NEXT_ARG();

			if (obj_name[0] != '\0') {
				p_err("object name already specified");
				return -1;
			}

			strncpy(obj_name, *argv, MAX_OBJ_NAME_LEN - 1);
			obj_name[MAX_OBJ_NAME_LEN - 1] = '\0';
		} else {
			p_err("unknown arg %s", *argv);
			return -1;
		}

		NEXT_ARG();
	}

	if (argc) {
		p_err("extra unknown arguments");
		return -1;
	}

	if (stat(file, &st)) {
		p_err("failed to stat() %s: %s", file, strerror(errno));
		return -1;
	}
	file_sz = st.st_size;
	mmap_sz = roundup(file_sz, sysconf(_SC_PAGE_SIZE));
	fd = open(file, O_RDONLY);
	if (fd < 0) {
		p_err("failed to open() %s: %s", file, strerror(errno));
		return -1;
	}
	obj_data = mmap(NULL, mmap_sz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (obj_data == MAP_FAILED) {
		obj_data = NULL;
		p_err("failed to mmap() %s: %s", file, strerror(errno));
		goto out;
	}
	if (obj_name[0] == '\0')
		get_obj_name(obj_name, file);
	opts.object_name = obj_name;
	if (verifier_logs)
		opts.kernel_log_level = 1 + 2 + 4;
	obj = bpf_object__open_mem(obj_data, file_sz, &opts);
	if (!obj) {
		char err_buf[256];

		err = -errno;
		libbpf_strerror(err, err_buf, sizeof(err_buf));
		p_err("failed to open BPF object file: %s", err_buf);
		goto out;
	}

	bpf_object__for_each_map(map, obj) {
		if (!get_map_ident(map, ident, sizeof(ident))) {
			p_err("ignoring unrecognized internal map '%s'...",
			      bpf_map__name(map));
			continue;
		}
		map_cnt++;
	}
	bpf_object__for_each_program(prog, obj) {
		prog_cnt++;
	}

	get_header_guard(header_guard, obj_name, "SKEL_H");
	if (use_loader) {
		codegen("\
		\n\
		/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */   \n\
		/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */		    \n\
		#ifndef %2$s						    \n\
		#define %2$s						    \n\
									    \n\
		#include <bpf/skel_internal.h>				    \n\
									    \n\
		struct %1$s {						    \n\
			struct bpf_loader_ctx ctx;			    \n\
		",
		obj_name, header_guard
		);
	} else {
		codegen("\
		\n\
		/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */   \n\
									    \n\
		/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */		    \n\
		#ifndef %2$s						    \n\
		#define %2$s						    \n\
									    \n\
		#include <errno.h>					    \n\
		#include <stdlib.h>					    \n\
		#include <bpf/libbpf.h>					    \n\
									    \n\
		struct %1$s {						    \n\
			struct bpf_object_skeleton *skeleton;		    \n\
			struct bpf_object *obj;				    \n\
		",
		obj_name, header_guard
		);
	}

	if (map_cnt) {
		printf("\tstruct {\n");
		bpf_object__for_each_map(map, obj) {
			if (!get_map_ident(map, ident, sizeof(ident)))
				continue;
			if (use_loader)
				printf("\t\tstruct bpf_map_desc %s;\n", ident);
			else
				printf("\t\tstruct bpf_map *%s;\n", ident);
		}
		printf("\t} maps;\n");
	}

	if (prog_cnt) {
		printf("\tstruct {\n");
		bpf_object__for_each_program(prog, obj) {
			if (use_loader)
				printf("\t\tstruct bpf_prog_desc %s;\n",
				       bpf_program__name(prog));
			else
				printf("\t\tstruct bpf_program *%s;\n",
				       bpf_program__name(prog));
		}
		printf("\t} progs;\n");
		printf("\tstruct {\n");
		bpf_object__for_each_program(prog, obj) {
			if (use_loader)
				printf("\t\tint %s_fd;\n",
				       bpf_program__name(prog));
			else
				printf("\t\tstruct bpf_link *%s;\n",
				       bpf_program__name(prog));
		}
		printf("\t} links;\n");
	}

	btf = bpf_object__btf(obj);
	if (btf) {
		err = codegen_datasecs(obj, obj_name);
		if (err)
			goto out;
	}
	if (use_loader) {
		err = gen_trace(obj, obj_name, header_guard);
		goto out;
	}

	codegen("\
		\n\
									    \n\
		#ifdef __cplusplus					    \n\
			static inline struct %1$s *open(const struct bpf_object_open_opts *opts = nullptr);\n\
			static inline struct %1$s *open_and_load();	    \n\
			static inline int load(struct %1$s *skel);	    \n\
			static inline int attach(struct %1$s *skel);	    \n\
			static inline void detach(struct %1$s *skel);	    \n\
			static inline void destroy(struct %1$s *skel);	    \n\
			static inline const void *elf_bytes(size_t *sz);    \n\
		#endif /* __cplusplus */				    \n\
		};							    \n\
									    \n\
		static void						    \n\
		%1$s__destroy(struct %1$s *obj)				    \n\
		{							    \n\
			if (!obj)					    \n\
				return;					    \n\
			if (obj->skeleton)				    \n\
				bpf_object__destroy_skeleton(obj->skeleton);\n\
			free(obj);					    \n\
		}							    \n\
									    \n\
		static inline int					    \n\
		%1$s__create_skeleton(struct %1$s *obj);		    \n\
									    \n\
		static inline struct %1$s *				    \n\
		%1$s__open_opts(const struct bpf_object_open_opts *opts)    \n\
		{							    \n\
			struct %1$s *obj;				    \n\
			int err;					    \n\
									    \n\
			obj = (struct %1$s *)calloc(1, sizeof(*obj));	    \n\
			if (!obj) {					    \n\
				errno = ENOMEM;				    \n\
				return NULL;				    \n\
			}						    \n\
									    \n\
			err = %1$s__create_skeleton(obj);		    \n\
			if (err)					    \n\
				goto err_out;				    \n\
									    \n\
			err = bpf_object__open_skeleton(obj->skeleton, opts);\n\
			if (err)					    \n\
				goto err_out;				    \n\
									    \n\
			return obj;					    \n\
		err_out:						    \n\
			%1$s__destroy(obj);				    \n\
			errno = -err;					    \n\
			return NULL;					    \n\
		}							    \n\
									    \n\
		static inline struct %1$s *				    \n\
		%1$s__open(void)					    \n\
		{							    \n\
			return %1$s__open_opts(NULL);			    \n\
		}							    \n\
									    \n\
		static inline int					    \n\
		%1$s__load(struct %1$s *obj)				    \n\
		{							    \n\
			return bpf_object__load_skeleton(obj->skeleton);    \n\
		}							    \n\
									    \n\
		static inline struct %1$s *				    \n\
		%1$s__open_and_load(void)				    \n\
		{							    \n\
			struct %1$s *obj;				    \n\
			int err;					    \n\
									    \n\
			obj = %1$s__open();				    \n\
			if (!obj)					    \n\
				return NULL;				    \n\
			err = %1$s__load(obj);				    \n\
			if (err) {					    \n\
				%1$s__destroy(obj);			    \n\
				errno = -err;				    \n\
				return NULL;				    \n\
			}						    \n\
			return obj;					    \n\
		}							    \n\
									    \n\
		static inline int					    \n\
		%1$s__attach(struct %1$s *obj)				    \n\
		{							    \n\
			return bpf_object__attach_skeleton(obj->skeleton);  \n\
		}							    \n\
									    \n\
		static inline void					    \n\
		%1$s__detach(struct %1$s *obj)				    \n\
		{							    \n\
			bpf_object__detach_skeleton(obj->skeleton);	    \n\
		}							    \n\
		",
		obj_name
	);

	codegen("\
		\n\
									    \n\
		static inline const void *%1$s__elf_bytes(size_t *sz);	    \n\
									    \n\
		static inline int					    \n\
		%1$s__create_skeleton(struct %1$s *obj)			    \n\
		{							    \n\
			struct bpf_object_skeleton *s;			    \n\
			int err;					    \n\
									    \n\
			s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));\n\
			if (!s)	{					    \n\
				err = -ENOMEM;				    \n\
				goto err;				    \n\
			}						    \n\
									    \n\
			s->sz = sizeof(*s);				    \n\
			s->name = \"%1$s\";				    \n\
			s->obj = &obj->obj;				    \n\
		",
		obj_name
	);

	codegen_maps_skeleton(obj, map_cnt, true /*mmaped*/);
	codegen_progs_skeleton(obj, prog_cnt, true /*populate_links*/);

	codegen("\
		\n\
									    \n\
			s->data = (void *)%2$s__elf_bytes(&s->data_sz);	    \n\
									    \n\
			obj->skeleton = s;				    \n\
			return 0;					    \n\
		err:							    \n\
			bpf_object__destroy_skeleton(s);		    \n\
			return err;					    \n\
		}							    \n\
									    \n\
		static inline const void *%2$s__elf_bytes(size_t *sz)	    \n\
		{							    \n\
			*sz = %1$d;					    \n\
			return (const void *)\"\\			    \n\
		"
		, file_sz, obj_name);

	print_hex(obj_data, file_sz);

	codegen("\
		\n\
		\";							    \n\
		}							    \n\
									    \n\
		#ifdef __cplusplus					    \n\
		struct %1$s *%1$s::open(const struct bpf_object_open_opts *opts) { return %1$s__open_opts(opts); }\n\
		struct %1$s *%1$s::open_and_load() { return %1$s__open_and_load(); }	\n\
		int %1$s::load(struct %1$s *skel) { return %1$s__load(skel); }		\n\
		int %1$s::attach(struct %1$s *skel) { return %1$s__attach(skel); }	\n\
		void %1$s::detach(struct %1$s *skel) { %1$s__detach(skel); }		\n\
		void %1$s::destroy(struct %1$s *skel) { %1$s__destroy(skel); }		\n\
		const void *%1$s::elf_bytes(size_t *sz) { return %1$s__elf_bytes(sz); } \n\
		#endif /* __cplusplus */				    \n\
									    \n\
		",
		obj_name);

	codegen_asserts(obj, obj_name);

	codegen("\
		\n\
									    \n\
		#endif /* %1$s */					    \n\
		",
		header_guard);
	err = 0;
out:
	bpf_object__close(obj);
	if (obj_data)
		munmap(obj_data, mmap_sz);
	close(fd);
	return err;
}

static int do_subskeleton(int argc, char **argv)
{
	char header_guard[MAX_OBJ_NAME_LEN + sizeof("__SUBSKEL_H__")];
	size_t i, len, file_sz, map_cnt = 0, prog_cnt = 0, mmap_sz, var_cnt = 0, var_idx = 0;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	char obj_name[MAX_OBJ_NAME_LEN] = "", *obj_data;
	struct bpf_object *obj = NULL;
	const char *file, *var_name;
	char ident[256];
	int fd, err = -1, map_type_id;
	const struct bpf_map *map;
	struct bpf_program *prog;
	struct btf *btf;
	const struct btf_type *map_type, *var_type;
	const struct btf_var_secinfo *var;
	struct stat st;

	if (!REQ_ARGS(1)) {
		usage();
		return -1;
	}
	file = GET_ARG();

	while (argc) {
		if (!REQ_ARGS(2))
			return -1;

		if (is_prefix(*argv, "name")) {
			NEXT_ARG();

			if (obj_name[0] != '\0') {
				p_err("object name already specified");
				return -1;
			}

			strncpy(obj_name, *argv, MAX_OBJ_NAME_LEN - 1);
			obj_name[MAX_OBJ_NAME_LEN - 1] = '\0';
		} else {
			p_err("unknown arg %s", *argv);
			return -1;
		}

		NEXT_ARG();
	}

	if (argc) {
		p_err("extra unknown arguments");
		return -1;
	}

	if (use_loader) {
		p_err("cannot use loader for subskeletons");
		return -1;
	}

	if (stat(file, &st)) {
		p_err("failed to stat() %s: %s", file, strerror(errno));
		return -1;
	}
	file_sz = st.st_size;
	mmap_sz = roundup(file_sz, sysconf(_SC_PAGE_SIZE));
	fd = open(file, O_RDONLY);
	if (fd < 0) {
		p_err("failed to open() %s: %s", file, strerror(errno));
		return -1;
	}
	obj_data = mmap(NULL, mmap_sz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (obj_data == MAP_FAILED) {
		obj_data = NULL;
		p_err("failed to mmap() %s: %s", file, strerror(errno));
		goto out;
	}
	if (obj_name[0] == '\0')
		get_obj_name(obj_name, file);

	opts.object_name = "";
	obj = bpf_object__open_mem(obj_data, file_sz, &opts);
	if (!obj) {
		char err_buf[256];

		libbpf_strerror(errno, err_buf, sizeof(err_buf));
		p_err("failed to open BPF object file: %s", err_buf);
		obj = NULL;
		goto out;
	}

	btf = bpf_object__btf(obj);
	if (!btf) {
		err = -1;
		p_err("need btf type information for %s", obj_name);
		goto out;
	}

	bpf_object__for_each_program(prog, obj) {
		prog_cnt++;
	}

	bpf_object__for_each_map(map, obj) {
		if (!get_map_ident(map, ident, sizeof(ident)))
			continue;

		map_cnt++;

		if (!is_internal_mmapable_map(map, ident, sizeof(ident)))
			continue;

		map_type_id = bpf_map__btf_value_type_id(map);
		if (map_type_id <= 0) {
			err = map_type_id;
			goto out;
		}
		map_type = btf__type_by_id(btf, map_type_id);

		var = btf_var_secinfos(map_type);
		len = btf_vlen(map_type);
		for (i = 0; i < len; i++, var++) {
			var_type = btf__type_by_id(btf, var->type);

			if (btf_var(var_type)->linkage == BTF_VAR_STATIC)
				continue;

			var_cnt++;
		}
	}

	get_header_guard(header_guard, obj_name, "SUBSKEL_H");
	codegen("\
	\n\
	/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */	    \n\
									    \n\
	/* THIS FILE IS AUTOGENERATED! */				    \n\
	#ifndef %2$s							    \n\
	#define %2$s							    \n\
									    \n\
	#include <errno.h>						    \n\
	#include <stdlib.h>						    \n\
	#include <bpf/libbpf.h>						    \n\
									    \n\
	struct %1$s {							    \n\
		struct bpf_object *obj;					    \n\
		struct bpf_object_subskeleton *subskel;			    \n\
	", obj_name, header_guard);

	if (map_cnt) {
		printf("\tstruct {\n");
		bpf_object__for_each_map(map, obj) {
			if (!get_map_ident(map, ident, sizeof(ident)))
				continue;
			printf("\t\tstruct bpf_map *%s;\n", ident);
		}
		printf("\t} maps;\n");
	}

	if (prog_cnt) {
		printf("\tstruct {\n");
		bpf_object__for_each_program(prog, obj) {
			printf("\t\tstruct bpf_program *%s;\n",
				bpf_program__name(prog));
		}
		printf("\t} progs;\n");
	}

	err = codegen_subskel_datasecs(obj, obj_name);
	if (err)
		goto out;

	codegen("\
		\n\
									    \n\
		#ifdef __cplusplus					    \n\
			static inline struct %1$s *open(const struct bpf_object *src);\n\
			static inline void destroy(struct %1$s *skel);	    \n\
		#endif /* __cplusplus */				    \n\
		};							    \n\
									    \n\
		static inline void					    \n\
		%1$s__destroy(struct %1$s *skel)			    \n\
		{							    \n\
			if (!skel)					    \n\
				return;					    \n\
			if (skel->subskel)				    \n\
				bpf_object__destroy_subskeleton(skel->subskel);\n\
			free(skel);					    \n\
		}							    \n\
									    \n\
		static inline struct %1$s *				    \n\
		%1$s__open(const struct bpf_object *src)		    \n\
		{							    \n\
			struct %1$s *obj;				    \n\
			struct bpf_object_subskeleton *s;		    \n\
			int err;					    \n\
									    \n\
			obj = (struct %1$s *)calloc(1, sizeof(*obj));	    \n\
			if (!obj) {					    \n\
				err = -ENOMEM;				    \n\
				goto err;				    \n\
			}						    \n\
			s = (struct bpf_object_subskeleton *)calloc(1, sizeof(*s));\n\
			if (!s) {					    \n\
				err = -ENOMEM;				    \n\
				goto err;				    \n\
			}						    \n\
			s->sz = sizeof(*s);				    \n\
			s->obj = src;					    \n\
			s->var_skel_sz = sizeof(*s->vars);		    \n\
			obj->subskel = s;				    \n\
									    \n\
			/* vars */					    \n\
			s->var_cnt = %2$d;				    \n\
			s->vars = (struct bpf_var_skeleton *)calloc(%2$d, sizeof(*s->vars));\n\
			if (!s->vars) {					    \n\
				err = -ENOMEM;				    \n\
				goto err;				    \n\
			}						    \n\
		",
		obj_name, var_cnt
	);

	bpf_object__for_each_map(map, obj) {
		if (!is_internal_mmapable_map(map, ident, sizeof(ident)))
			continue;

		map_type_id = bpf_map__btf_value_type_id(map);
		if (map_type_id <= 0)
			continue;

		map_type = btf__type_by_id(btf, map_type_id);
		var = btf_var_secinfos(map_type);
		len = btf_vlen(map_type);
		for (i = 0; i < len; i++, var++) {
			var_type = btf__type_by_id(btf, var->type);
			var_name = btf__name_by_offset(btf, var_type->name_off);

			if (btf_var(var_type)->linkage == BTF_VAR_STATIC)
				continue;

			codegen("\
			\n\
									    \n\
				s->vars[%3$d].name = \"%1$s\";		    \n\
				s->vars[%3$d].map = &obj->maps.%2$s;	    \n\
				s->vars[%3$d].addr = (void **) &obj->%2$s.%1$s;\n\
			", var_name, ident, var_idx);

			var_idx++;
		}
	}

	codegen_maps_skeleton(obj, map_cnt, false /*mmaped*/);
	codegen_progs_skeleton(obj, prog_cnt, false /*links*/);

	codegen("\
		\n\
									    \n\
			err = bpf_object__open_subskeleton(s);		    \n\
			if (err)					    \n\
				goto err;				    \n\
									    \n\
			return obj;					    \n\
		err:							    \n\
			%1$s__destroy(obj);				    \n\
			errno = -err;					    \n\
			return NULL;					    \n\
		}							    \n\
									    \n\
		#ifdef __cplusplus					    \n\
		struct %1$s *%1$s::open(const struct bpf_object *src) { return %1$s__open(src); }\n\
		void %1$s::destroy(struct %1$s *skel) { %1$s__destroy(skel); }\n\
		#endif /* __cplusplus */				    \n\
									    \n\
		#endif /* %2$s */					    \n\
		",
		obj_name, header_guard);
	err = 0;
out:
	bpf_object__close(obj);
	if (obj_data)
		munmap(obj_data, mmap_sz);
	close(fd);
	return err;
}

static int do_object(int argc, char **argv)
{
	struct bpf_linker *linker;
	const char *output_file, *file;
	int err = 0;

	if (!REQ_ARGS(2)) {
		usage();
		return -1;
	}

	output_file = GET_ARG();

	linker = bpf_linker__new(output_file, NULL);
	if (!linker) {
		p_err("failed to create BPF linker instance");
		return -1;
	}

	while (argc) {
		file = GET_ARG();

		err = bpf_linker__add_file(linker, file, NULL);
		if (err) {
			p_err("failed to link '%s': %s (%d)", file, strerror(errno), errno);
			goto out;
		}
	}

	err = bpf_linker__finalize(linker);
	if (err) {
		p_err("failed to finalize ELF file: %s (%d)", strerror(errno), errno);
		goto out;
	}

	err = 0;
out:
	bpf_linker__free(linker);
	return err;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s object OUTPUT_FILE INPUT_FILE [INPUT_FILE...]\n"
		"       %1$s %2$s skeleton FILE [name OBJECT_NAME]\n"
		"       %1$s %2$s subskeleton FILE [name OBJECT_NAME]\n"
		"       %1$s %2$s min_core_btf INPUT OUTPUT OBJECT [OBJECT...]\n"
		"       %1$s %2$s help\n"
		"\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-L|--use-loader} }\n"
		"",
		bin_name, "gen");

	return 0;
}


static int minimize_btf(const char *src_btf, const char *dst_btf, const char *objspaths[])
{
	struct btfgen_info *info;
	struct btf *btf_new = NULL;
	int err, i;

	info = btfgen_new_info(src_btf);
	if (!info) {
		err = -errno;
		p_err("failed to allocate info structure: %s", strerror(errno));
		goto out;
	}

	for (i = 0; objspaths[i] != NULL; i++) {
		err = btfgen_record_obj(info, objspaths[i]);
		if (err) {
			p_err("error recording relocations for %s: %s", objspaths[i],
			      strerror(errno));
			goto out;
		}
	}

	btf_new = btfgen_get_btf(info);
	if (!btf_new) {
		err = -errno;
		p_err("error generating BTF: %s", strerror(errno));
		goto out;
	}

	err = btf_save_raw(btf_new, dst_btf);
	if (err) {
		p_err("error saving btf file: %s", strerror(errno));
		goto out;
	}

out:
	btf__free(btf_new);
	btfgen_free_info(info);

	return err;
}

static int do_min_core_btf(int argc, char **argv)
{
	const char *input, *output, **objs;
	int i, err;

	if (!REQ_ARGS(3)) {
		usage();
		return -1;
	}

	input = GET_ARG();
	output = GET_ARG();

	objs = (const char **) calloc(argc + 1, sizeof(*objs));
	if (!objs) {
		p_err("failed to allocate array for object names");
		return -ENOMEM;
	}

	i = 0;
	while (argc)
		objs[i++] = GET_ARG();

	err = minimize_btf(input, output, objs);
	free(objs);
	return err;
}

static const struct cmd cmds[] = {
	{ "object",		do_object },
	{ "skeleton",		do_skeleton },
	{ "subskeleton",	do_subskeleton },
	{ "min_core_btf",	do_min_core_btf},
	{ "help",		do_help },
	{ 0 }
};

int do_gen(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
