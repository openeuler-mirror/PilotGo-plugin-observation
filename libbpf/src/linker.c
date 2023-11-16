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

static int init_output_elf(struct bpf_linker *linker, const char *file)
{
    int err, str_off;
    Elf64_Sym *init_sym;
    struct dst_sec *sec;

    linker->filename = strdup(file);
    if (!linker->filename)
        return -ENOMEM;

    linker->fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (linker->fd < 0)
    {
        err = -errno;
        pr_warn("failed to create '%s': %d\n", file, err);
        return err;
    }

    linker->elf = elf_begin(linker->fd, ELF_C_WRITE, NULL);
    if (!linker->elf)
    {
        pr_warn_elf("failed to create ELF object");
        return -EINVAL;
    }

    /* ELF header */
    linker->elf_hdr = elf64_newehdr(linker->elf);
    if (!linker->elf_hdr)
    {
        pr_warn_elf("failed to create ELF header");
        return -EINVAL;
    }

    linker->elf_hdr->e_machine = EM_BPF;
    linker->elf_hdr->e_type = ET_REL;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    linker->elf_hdr->e_ident[EI_DATA] = ELFDATA2LSB;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    linker->elf_hdr->e_ident[EI_DATA] = ELFDATA2MSB;
#else
#error "Unknown __BYTE_ORDER__"
#endif

    /* STRTAB */
    /* initialize strset with an empty string to conform to ELF */
    linker->strtab_strs = strset__new(INT_MAX, "", sizeof(""));
    if (libbpf_get_error(linker->strtab_strs))
        return libbpf_get_error(linker->strtab_strs);

    sec = add_dst_sec(linker, ".strtab");
    if (!sec)
        return -ENOMEM;

    sec->scn = elf_newscn(linker->elf);
    if (!sec->scn)
    {
        pr_warn_elf("failed to create STRTAB section");
        return -EINVAL;
    }

    sec->shdr = elf64_getshdr(sec->scn);
    if (!sec->shdr)
        return -EINVAL;

    sec->data = elf_newdata(sec->scn);
    if (!sec->data)
    {
        pr_warn_elf("failed to create STRTAB data");
        return -EINVAL;
    }

    str_off = strset__add_str(linker->strtab_strs, sec->sec_name);
    if (str_off < 0)
        return str_off;

    sec->sec_idx = elf_ndxscn(sec->scn);
    linker->elf_hdr->e_shstrndx = sec->sec_idx;
    linker->strtab_sec_idx = sec->sec_idx;

    sec->shdr->sh_name = str_off;
    sec->shdr->sh_type = SHT_STRTAB;
    sec->shdr->sh_flags = SHF_STRINGS;
    sec->shdr->sh_offset = 0;
    sec->shdr->sh_link = 0;
    sec->shdr->sh_info = 0;
    sec->shdr->sh_addralign = 1;
    sec->shdr->sh_size = sec->sec_sz = 0;
    sec->shdr->sh_entsize = 0;

    /* SYMTAB */
    sec = add_dst_sec(linker, ".symtab");
    if (!sec)
        return -ENOMEM;

    sec->scn = elf_newscn(linker->elf);
    if (!sec->scn)
    {
        pr_warn_elf("failed to create SYMTAB section");
        return -EINVAL;
    }

    sec->shdr = elf64_getshdr(sec->scn);
    if (!sec->shdr)
        return -EINVAL;

    sec->data = elf_newdata(sec->scn);
    if (!sec->data)
    {
        pr_warn_elf("failed to create SYMTAB data");
        return -EINVAL;
    }

    str_off = strset__add_str(linker->strtab_strs, sec->sec_name);
    if (str_off < 0)
        return str_off;

    sec->sec_idx = elf_ndxscn(sec->scn);
    linker->symtab_sec_idx = sec->sec_idx;

    sec->shdr->sh_name = str_off;
    sec->shdr->sh_type = SHT_SYMTAB;
    sec->shdr->sh_flags = 0;
    sec->shdr->sh_offset = 0;
    sec->shdr->sh_link = linker->strtab_sec_idx;
    /* sh_info should be one greater than the index of the last local
     * symbol (i.e., binding is STB_LOCAL). But why and who cares?
     */
    sec->shdr->sh_info = 0;
    sec->shdr->sh_addralign = 8;
    sec->shdr->sh_entsize = sizeof(Elf64_Sym);

    /* .BTF */
    linker->btf = btf__new_empty();
    err = libbpf_get_error(linker->btf);
    if (err)
        return err;

    /* add the special all-zero symbol */
    init_sym = add_new_sym(linker, NULL);
    if (!init_sym)
        return -EINVAL;

    init_sym->st_name = 0;
    init_sym->st_info = 0;
    init_sym->st_other = 0;
    init_sym->st_shndx = SHN_UNDEF;
    init_sym->st_value = 0;
    init_sym->st_size = 0;

    return 0;
}
int bpf_linker__add_file(struct bpf_linker *linker, const char *filename,
                         const struct bpf_linker_file_opts *opts)
{
    struct src_obj obj = {};
    int err = 0;

    if (!OPTS_VALID(opts, bpf_linker_file_opts))
        return libbpf_err(-EINVAL);

    if (!linker->elf)
        return libbpf_err(-EINVAL);

    err = err ?: linker_load_obj_file(linker, filename, opts, &obj);
    err = err ?: linker_append_sec_data(linker, &obj);
    err = err ?: linker_append_elf_syms(linker, &obj);
    err = err ?: linker_append_elf_relos(linker, &obj);
    err = err ?: linker_append_btf(linker, &obj);
    err = err ?: linker_append_btf_ext(linker, &obj);

    /* free up src_obj resources */
    free(obj.btf_type_map);
    btf__free(obj.btf);
    btf_ext__free(obj.btf_ext);
    free(obj.secs);
    free(obj.sym_map);
    if (obj.elf)
        elf_end(obj.elf);
    if (obj.fd >= 0)
        close(obj.fd);

    return libbpf_err(err);
}

static bool is_dwarf_sec_name(const char *name)
{
    /* approximation, but the actual list is too long */
    return strncmp(name, ".debug_", sizeof(".debug_") - 1) == 0;
}

static bool is_ignored_sec(struct src_sec *sec)
{
    Elf64_Shdr *shdr = sec->shdr;
    const char *name = sec->sec_name;

    /* no special handling of .strtab */
    if (shdr->sh_type == SHT_STRTAB)
        return true;

    /* ignore .llvm_addrsig section as well */
    if (shdr->sh_type == SHT_LLVM_ADDRSIG)
        return true;

    /* no subprograms will lead to an empty .text section, ignore it */
    if (shdr->sh_type == SHT_PROGBITS && shdr->sh_size == 0 &&
        strcmp(sec->sec_name, ".text") == 0)
        return true;

    /* DWARF sections */
    if (is_dwarf_sec_name(sec->sec_name))
        return true;

    if (strncmp(name, ".rel", sizeof(".rel") - 1) == 0)
    {
        name += sizeof(".rel") - 1;
        /* DWARF section relocations */
        if (is_dwarf_sec_name(name))
            return true;

        /* .BTF and .BTF.ext don't need relocations */
        if (strcmp(name, BTF_ELF_SEC) == 0 ||
            strcmp(name, BTF_EXT_ELF_SEC) == 0)
            return true;
    }

    return false;
}

static struct src_sec *add_src_sec(struct src_obj *obj, const char *sec_name)
{
    struct src_sec *secs = obj->secs, *sec;
    size_t new_cnt = obj->sec_cnt ? obj->sec_cnt + 1 : 2;

    secs = libbpf_reallocarray(secs, new_cnt, sizeof(*secs));
    if (!secs)
        return NULL;

    /* zero out newly allocated memory */
    memset(secs + obj->sec_cnt, 0, (new_cnt - obj->sec_cnt) * sizeof(*secs));

    obj->secs = secs;
    obj->sec_cnt = new_cnt;

    sec = &obj->secs[new_cnt - 1];
    sec->id = new_cnt - 1;
    sec->sec_name = sec_name;

    return sec;
}

static int linker_load_obj_file(struct bpf_linker *linker, const char *filename,
                                const struct bpf_linker_file_opts *opts,
                                struct src_obj *obj)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    const int host_endianness = ELFDATA2LSB;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    const int host_endianness = ELFDATA2MSB;
#else
#error "Unknown __BYTE_ORDER__"
#endif
    int err = 0;
    Elf_Scn *scn;
    Elf_Data *data;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;
    struct src_sec *sec;

    pr_debug("linker: adding object file '%s'...\n", filename);

    obj->filename = filename;

    obj->fd = open(filename, O_RDONLY | O_CLOEXEC);
    if (obj->fd < 0)
    {
        err = -errno;
        pr_warn("failed to open file '%s': %d\n", filename, err);
        return err;
    }
    obj->elf = elf_begin(obj->fd, ELF_C_READ_MMAP, NULL);
    if (!obj->elf)
    {
        err = -errno;
        pr_warn_elf("failed to parse ELF file '%s'", filename);
        return err;
    }

    /* Sanity check ELF file high-level properties */
    ehdr = elf64_getehdr(obj->elf);
    if (!ehdr)
    {
        err = -errno;
        pr_warn_elf("failed to get ELF header for %s", filename);
        return err;
    }
    if (ehdr->e_ident[EI_DATA] != host_endianness)
    {
        err = -EOPNOTSUPP;
        pr_warn_elf("unsupported byte order of ELF file %s", filename);
        return err;
    }
    if (ehdr->e_type != ET_REL || ehdr->e_machine != EM_BPF || ehdr->e_ident[EI_CLASS] != ELFCLASS64)
    {
        err = -EOPNOTSUPP;
        pr_warn_elf("unsupported kind of ELF file %s", filename);
        return err;
    }

    if (elf_getshdrstrndx(obj->elf, &obj->shstrs_sec_idx))
    {
        err = -errno;
        pr_warn_elf("failed to get SHSTRTAB section index for %s", filename);
        return err;
    }

    scn = NULL;
    while ((scn = elf_nextscn(obj->elf, scn)) != NULL)
    {
        size_t sec_idx = elf_ndxscn(scn);
        const char *sec_name;

        shdr = elf64_getshdr(scn);
        if (!shdr)
        {
            err = -errno;
            pr_warn_elf("failed to get section #%zu header for %s",
                        sec_idx, filename);
            return err;
        }

        sec_name = elf_strptr(obj->elf, obj->shstrs_sec_idx, shdr->sh_name);
        if (!sec_name)
        {
            err = -errno;
            pr_warn_elf("failed to get section #%zu name for %s",
                        sec_idx, filename);
            return err;
        }

        data = elf_getdata(scn, 0);
        if (!data)
        {
            err = -errno;
            pr_warn_elf("failed to get section #%zu (%s) data from %s",
                        sec_idx, sec_name, filename);
            return err;
        }

        sec = add_src_sec(obj, sec_name);
        if (!sec)
            return -ENOMEM;

        sec->scn = scn;
        sec->shdr = shdr;
        sec->data = data;
        sec->sec_idx = elf_ndxscn(scn);

        if (is_ignored_sec(sec))
        {
            sec->skipped = true;
            continue;
        }

        switch (shdr->sh_type)
        {
        case SHT_SYMTAB:
            if (obj->symtab_sec_idx)
            {
                err = -EOPNOTSUPP;
                pr_warn("multiple SYMTAB sections found, not supported\n");
                return err;
            }
            obj->symtab_sec_idx = sec_idx;
            break;
        case SHT_STRTAB:
            /* we'll construct our own string table */
            break;
        case SHT_PROGBITS:
            if (strcmp(sec_name, BTF_ELF_SEC) == 0)
            {
                obj->btf = btf__new(data->d_buf, shdr->sh_size);
                err = libbpf_get_error(obj->btf);
                if (err)
                {
                    pr_warn("failed to parse .BTF from %s: %d\n", filename, err);
                    return err;
                }
                sec->skipped = true;
                continue;
            }
            if (strcmp(sec_name, BTF_EXT_ELF_SEC) == 0)
            {
                obj->btf_ext = btf_ext__new(data->d_buf, shdr->sh_size);
                err = libbpf_get_error(obj->btf_ext);
                if (err)
                {
                    pr_warn("failed to parse .BTF.ext from '%s': %d\n", filename, err);
                    return err;
                }
                sec->skipped = true;
                continue;
            }

            /* data & code */
            break;
        case SHT_NOBITS:
            /* BSS */
            break;
        case SHT_REL:
            /* relocations */
            break;
        default:
            pr_warn("unrecognized section #%zu (%s) in %s\n",
                    sec_idx, sec_name, filename);
            err = -EINVAL;
            return err;
        }
    }

    err = err ?: linker_sanity_check_elf(obj);
    err = err ?: linker_sanity_check_btf(obj);
    err = err ?: linker_sanity_check_btf_ext(obj);
    err = err ?: linker_fixup_btf(obj);

    return err;
}