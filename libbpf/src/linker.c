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
