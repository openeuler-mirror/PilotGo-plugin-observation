#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/err.h>
#include <linux/btf.h>
#include <elf.h>
#include <libelf.h>
#include <fcntl.h>
#include "libbpf.h"
#include "btf.h"
#include "libbpf_internal.h"
#include "strset.h"

#define BTF_EXTERN_SEC ".extern"

struct src_sec
{
    const char *sec_name;
    /* positional (not necessarily ELF) index in an array of sections */
    int id;
    /* positional (not necessarily ELF) index of a matching section in a final object file */
    int dst_id;
    /* section data offset in a matching output section */
    int dst_off;
    /* whether section is omitted from the final ELF file */
    bool skipped;
    /* whether section is an ephemeral section, not mapped to an ELF section */
    bool ephemeral;

    /* ELF info */
    size_t sec_idx;
    Elf_Scn *scn;
    Elf64_Shdr *shdr;
    Elf_Data *data;

    /* corresponding BTF DATASEC type ID */
    int sec_type_id;
};

struct src_obj
{
    const char *filename;
    int fd;
    Elf *elf;
    /* Section header strings section index */
    size_t shstrs_sec_idx;
    /* SYMTAB section index */
    size_t symtab_sec_idx;

    struct btf *btf;
    struct btf_ext *btf_ext;

    /* List of sections (including ephemeral). Slot zero is unused. */
    struct src_sec *secs;
    int sec_cnt;

    /* mapping of symbol indices from src to dst ELF */
    int *sym_map;
    /* mapping from the src BTF type IDs to dst ones */
    int *btf_type_map;
};

/* single .BTF.ext data section */
struct btf_ext_sec_data
{
    size_t rec_cnt;
    __u32 rec_sz;
    void *recs;
};

struct glob_sym
{
    /* ELF symbol index */
    int sym_idx;
    /* associated section id for .ksyms, .kconfig, etc, but not .extern */
    int sec_id;
    /* extern name offset in STRTAB */
    int name_off;
    /* optional associated BTF type ID */
    int btf_id;
    /* BTF type ID to which VAR/FUNC type is pointing to; used for
     * rewriting types when extern VAR/FUNC is resolved to a concrete
     * definition
     */
    int underlying_btf_id;
    /* sec_var index in the corresponding dst_sec, if exists */
    int var_idx;

    /* extern or resolved/global symbol */
    bool is_extern;
    /* weak or strong symbol, never goes back from strong to weak */
    bool is_weak;
};

struct dst_sec
{
    char *sec_name;
    /* positional (not necessarily ELF) index in an array of sections */
    int id;

    bool ephemeral;

    /* ELF info */
    size_t sec_idx;
    Elf_Scn *scn;
    Elf64_Shdr *shdr;
    Elf_Data *data;

    /* final output section size */
    int sec_sz;
    /* final output contents of the section */
    void *raw_data;

    /* corresponding STT_SECTION symbol index in SYMTAB */
    int sec_sym_idx;

    /* section's DATASEC variable info, emitted on BTF finalization */
    bool has_btf;
    int sec_var_cnt;
    struct btf_var_secinfo *sec_vars;

    /* section's .BTF.ext data */
    struct btf_ext_sec_data func_info;
    struct btf_ext_sec_data line_info;
    struct btf_ext_sec_data core_relo_info;
};

struct bpf_linker
{
    char *filename;
    int fd;
    Elf *elf;
    Elf64_Ehdr *elf_hdr;

    /* Output sections metadata */
    struct dst_sec *secs;
    int sec_cnt;

    struct strset *strtab_strs; /* STRTAB unique strings */
    size_t strtab_sec_idx;      /* STRTAB section index */
    size_t symtab_sec_idx;      /* SYMTAB section index */

    struct btf *btf;
    struct btf_ext *btf_ext;

    /* global (including extern) ELF symbols */
    int glob_sym_cnt;
    struct glob_sym *glob_syms;
};

#define pr_warn_elf(fmt, ...) \
    libbpf_print(LIBBPF_WARN, "libbpf: " fmt ": %s\n", ##__VA_ARGS__, elf_errmsg(-1))

static int init_output_elf(struct bpf_linker *linker, const char *file);

static int linker_load_obj_file(struct bpf_linker *linker, const char *filename,
                                const struct bpf_linker_file_opts *opts,
                                struct src_obj *obj);
static int linker_sanity_check_elf(struct src_obj *obj);
static int linker_sanity_check_elf_symtab(struct src_obj *obj, struct src_sec *sec);
static int linker_sanity_check_elf_relos(struct src_obj *obj, struct src_sec *sec);
static int linker_sanity_check_btf(struct src_obj *obj);
static int linker_sanity_check_btf_ext(struct src_obj *obj);
static int linker_fixup_btf(struct src_obj *obj);
static int linker_append_sec_data(struct bpf_linker *linker, struct src_obj *obj);
static int linker_append_elf_syms(struct bpf_linker *linker, struct src_obj *obj);
static int linker_append_elf_sym(struct bpf_linker *linker, struct src_obj *obj,
                                 Elf64_Sym *sym, const char *sym_name, int src_sym_idx);
static int linker_append_elf_relos(struct bpf_linker *linker, struct src_obj *obj);
static int linker_append_btf(struct bpf_linker *linker, struct src_obj *obj);
static int linker_append_btf_ext(struct bpf_linker *linker, struct src_obj *obj);

static int finalize_btf(struct bpf_linker *linker);
static int finalize_btf_ext(struct bpf_linker *linker);

void bpf_linker__free(struct bpf_linker *linker)
{
    int i;

    if (!linker)
        return;

    free(linker->filename);

    if (linker->elf)
        elf_end(linker->elf);

    if (linker->fd >= 0)
        close(linker->fd);

    strset__free(linker->strtab_strs);

    btf__free(linker->btf);
    btf_ext__free(linker->btf_ext);

    for (i = 1; i < linker->sec_cnt; i++)
    {
        struct dst_sec *sec = &linker->secs[i];

        free(sec->sec_name);
        free(sec->raw_data);
        free(sec->sec_vars);

        free(sec->func_info.recs);
        free(sec->line_info.recs);
        free(sec->core_relo_info.recs);
    }
    free(linker->secs);

    free(linker->glob_syms);
    free(linker);
}

struct bpf_linker *bpf_linker__new(const char *filename, struct bpf_linker_opts *opts)
{
    struct bpf_linker *linker;
    int err;

    if (!OPTS_VALID(opts, bpf_linker_opts))
        return errno = EINVAL, NULL;

    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        pr_warn_elf("libelf initialization failed");
        return errno = EINVAL, NULL;
    }

    linker = calloc(1, sizeof(*linker));
    if (!linker)
        return errno = ENOMEM, NULL;

    linker->fd = -1;

    err = init_output_elf(linker, filename);
    if (err)
        goto err_out;

    return linker;

err_out:
    bpf_linker__free(linker);
    return errno = -err, NULL;
}
static struct dst_sec *add_dst_sec(struct bpf_linker *linker, const char *sec_name)
{
    struct dst_sec *secs = linker->secs, *sec;
    size_t new_cnt = linker->sec_cnt ? linker->sec_cnt + 1 : 2;

    secs = libbpf_reallocarray(secs, new_cnt, sizeof(*secs));
    if (!secs)
        return NULL;

    /* zero out newly allocated memory */
    memset(secs + linker->sec_cnt, 0, (new_cnt - linker->sec_cnt) * sizeof(*secs));

    linker->secs = secs;
    linker->sec_cnt = new_cnt;

    sec = &linker->secs[new_cnt - 1];
    sec->id = new_cnt - 1;
    sec->sec_name = strdup(sec_name);
    if (!sec->sec_name)
        return NULL;

    return sec;
}

static Elf64_Sym *add_new_sym(struct bpf_linker *linker, size_t *sym_idx)
{
    struct dst_sec *symtab = &linker->secs[linker->symtab_sec_idx];
    Elf64_Sym *syms, *sym;
    size_t sym_cnt = symtab->sec_sz / sizeof(*sym);

    syms = libbpf_reallocarray(symtab->raw_data, sym_cnt + 1, sizeof(*sym));
    if (!syms)
        return NULL;

    sym = &syms[sym_cnt];
    memset(sym, 0, sizeof(*sym));

    symtab->raw_data = syms;
    symtab->sec_sz += sizeof(*sym);
    symtab->shdr->sh_size += sizeof(*sym);
    symtab->data->d_size += sizeof(*sym);

    if (sym_idx)
        *sym_idx = sym_cnt;

    return sym;
}