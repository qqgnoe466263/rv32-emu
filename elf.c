#include "elf.h"

bool is_elf_valid(struct Elf32_Ehdr *e_hdr)
{
    u8 *ident = e_hdr->e_ident;

    /* Check for ELF magic */
    if (ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' ||
        ident[3] != 'F')
        return false;

    /* Must be 32bit ELF */
    if (ident[EI_CLASS] != ELFCLASS32)
        return false;

    /* Check if machine type is RISC-V */
    if (e_hdr->e_machine != EM_RISCV)
        return false;

    return true;
}

#if CONFIG_ARCH_TEST
u32 parse_elf(u8 *ram, u8 *elf, u32 *start, u32 *end)
#else
u32 parse_elf(u8 *ram, u8 *elf)
#endif
{
    struct Elf32_Ehdr *e_hdr = (struct Elf32_Ehdr *) elf;

    if (!is_elf_valid(e_hdr))
        return 0;

#if CONFIG_ARCH_TEST
    /* Get ELF string table */
    struct Elf32_Shdr *e_shdr =
        (struct Elf32_Shdr *) (elf + e_hdr->e_shoff +
                               e_hdr->e_shentsize * e_hdr->e_shstrndx);
    char *shstrtab = (char *) (elf + e_shdr->sh_offset);
    if (!shstrtab) {
        fprintf(stderr, "Couldn't find shstrtab\n");
        return 0;
    }

    for (int i = 0; i < e_hdr->e_shnum; i++) {
        struct Elf32_Shdr *e_shdr =
            (struct Elf32_Shdr *) (elf + e_hdr->e_shoff +
                                   e_hdr->e_shentsize * i);

        if (e_shdr->sh_type == SHT_SYMTAB || e_shdr->sh_type == SHT_DYNSYM) {
            struct Elf32_Sym *symtab_hdr =
                (struct Elf32_Sym *) (elf + e_shdr->sh_offset);
            struct Elf32_Shdr *symtab_shdr =
                (struct Elf32_Shdr *) (elf + e_hdr->e_shoff +
                                       e_hdr->e_shentsize * e_shdr->sh_link);
            /* .symtab */
            char *symtab = (char *) elf + symtab_shdr->sh_offset;
            int symbol_cnt = e_shdr->sh_size / sizeof(struct Elf32_Sym);
            for (int i = 0; i < symbol_cnt; i++) {
                char *sym_name = symtab + symtab_hdr[i].st_name;
                if (!strcmp(sym_name, "begin_signature")) {
                    *start = symtab_hdr[i].st_value;
                    continue;
                }
                if (!strcmp(sym_name, "end_signature")) {
                    *end = symtab_hdr[i].st_value;
                }
            }
        }
    }
#endif

    /* ELF load */
    u32 pc = e_hdr->e_entry;

    /* Loop over all of the program headers */
    for (int i = 0; i < e_hdr->e_phnum; i++) {
        struct Elf32_Phdr *e_phdr =
            (struct Elf32_Phdr *) (elf + e_hdr->e_phoff +
                                   e_hdr->e_phentsize * i);
        if (e_phdr->p_type != PT_LOAD)
            continue;

        u32 start = e_phdr->p_paddr - 0x80000000;
        u32 size = e_phdr->p_filesz;
        u32 offset = e_phdr->p_offset;
        memcpy(ram + start, elf + offset, size);
    }

    return pc;
}
