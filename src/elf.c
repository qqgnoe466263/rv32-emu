#include "elf.h"

s8 is_elf_valid(struct Elf32_Ehdr *e_hdr)
{
    u8 *ident = e_hdr->e_ident;

    /* Check for ELF magic */
    if (ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' ||
        ident[3] != 'F') {
        ELF_DBG("Not an ELF\n");
        return false;
    }

    /* Must be 32bit ELF */
    if (ident[EI_CLASS] != ELFCLASS32) {
        ELF_DBG("Not a 32bit ELF\n");
        return false;
    }

    /* Check if machine type is RISC-V */
    if (e_hdr->e_machine != EM_RISCV) {
        ELF_DBG("Not a RISCV ELF\n");
        return false;
    }

    return true;
}

s8 parse_elf(u8 *mem, u8 *elf_file, u32 *entry)
{
    struct Elf32_Ehdr *e_hdr = (struct Elf32_Ehdr *)elf_file;

    if (!is_elf_valid(e_hdr)) {
        return false;
    }

    /* Get ELF string table */
    struct Elf32_Shdr *e_shdr = (struct Elf32_Shdr *)(elf_file +
                                                e_hdr->e_shoff +
                                                e_hdr->e_shentsize * e_hdr->e_shstrndx);
    char *shstrtab = (char *)(elf_file + e_shdr->sh_offset);
    if (!shstrtab) {
        ELF_DBG("Couldn't find shstrtab\n");
        return false;
    }

    ELF_DBG("[Nr] %10s %9s %9s %9s\n", "Name", "Addr", "Off", "Size");
    for (int i = 0; i < e_hdr->e_shnum; i++) {
        struct Elf32_Shdr *e_shdr = (struct Elf32_Shdr *)(elf_file +
                                                    e_hdr->e_shoff +
                                                    e_hdr->e_shentsize * i);
        char *sec_name = shstrtab + e_shdr->sh_name;
        ELF_DBG("[%02d] %10s %9x %9x %9x\n", i, sec_name,
                                             e_shdr->sh_addr,
                                             e_shdr->sh_offset,
                                             e_shdr->sh_size);
        if (e_shdr->sh_type == SHT_SYMTAB ||
            e_shdr->sh_type == SHT_DYNSYM) {
            struct Elf32_Sym *symtab_hdr = (struct Elf32_Sym *)
                        (elf_file + e_shdr->sh_offset);
            struct Elf32_Shdr *symtab_shdr = (struct Elf32_Shdr *)(elf_file +
                                                e_hdr->e_shoff +
                                                e_hdr->e_shentsize * e_shdr->sh_link);
            /* .symtab */
            char *symtab = (char *)elf_file + symtab_shdr->sh_offset;
            int symbol_cnt = e_shdr->sh_size / sizeof(struct Elf32_Sym);
            for (int i = 0; i < symbol_cnt; i++) {
                char *sym_name = symtab + symtab_hdr[i].st_name;
                //ELF_DBG("sym_name : %s\n", sym_name);
                if (!strcmp(sym_name, "begin_signature")) {
                    // This is for riscv-compliance
                    continue;
                }
                if (!strcmp(sym_name, "end_signature")) {
                    // This is for riscv-compliance
                }
            }
        }
    }

    /* ELF load */
    *entry = e_hdr->e_entry;
    ELF_DBG("Entry Point : 0x%08x\n", e_hdr->e_entry);
    ELF_DBG("There are %d program headers, starting of program header : %d\n",
           e_hdr->e_phnum, e_hdr->e_phoff);

    /* Loop over all of the program headers */
    ELF_DBG("Program Headers:\n");
    for (int i = 0; i < e_hdr->e_phnum; i++) {
        struct Elf32_Phdr *e_phdr = (struct Elf32_Phdr *)(elf_file +
                                    e_hdr->e_phoff + e_hdr->e_phentsize * i);
        if (e_phdr->p_type != PT_LOAD)
            continue;

        ELF_DBG("    Offset        VirtAddr        PhysAddr\n");
        ELF_DBG("0x%08x      0x%08x      0x%08x\n", e_phdr->p_offset,
                                                   e_phdr->p_vaddr,
                                                   e_phdr->p_paddr);

        ELF_DBG("   FileSiz          MemSiz           Flags           Align\n");
        ELF_DBG("0x%08x      0x%08x      0x%08x      0x%08x\n", e_phdr->p_filesz,
                                                               e_phdr->p_memsz,
                                                               e_phdr->p_flags,
                                                               e_phdr->p_align);
        u32 start  = e_phdr->p_paddr;
        u32 size   = e_phdr->p_filesz;
        u32 offset = e_phdr->p_offset;
        printf("start : 0x%08x, size : 0x%08x, offset : 0x%08x\n",
               start, size, offset);
        memcpy(mem + start, elf_file + offset, size);
        ELF_DBG("\n");
    }

    return true;
}
