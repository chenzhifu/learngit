//
//  elfinfo.c
//  execassister
//
//  Created by j1gsaw on 14-10-30.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#include "elfinfo.h"
#include "log.h"
#include "utils.h"
#include "elfapi.h"
#include "elfverifier.h"

const char* elf_classtype[] = {
    "None", "32", "64"
};

const char* elf_datatype[] = {
    "None", "LSB", "MSB"
};

const char* elf_type[] = {
    "None",
    "Relocatable file",
    "Executable file",
    "Shared object file"
};

const char* elf_shtype[] = {
    "NULL",
    "PROGBITS",
    "SYMTAB",
    "STRTAB",
    "RELA",
    "HASH",
    "DYNAMIC",
    "NOTE",
    "NOBITS",
    "REL",
    "SHLIB",
    "DYNSYM",
    "",
    "",
    "INIT_ARRAY",
    "FINI_ARRAY",
    "PREINIT_ARRAY",
};

const char* elf_shflag[] = {
    "W", // SHF_WRITE
    "A", // SHF_ALLOC
    "E", // SHF_EXECINSTR
    "",
    "M", // SHF_MERGE
    "S", // SHF_STRINGS
    "I", // SHF_INFO_LINK
    "L", // SHF_LINK_ORDER
    "O", // SHF_OS_NONCONFORMING
    "G", // SHF_GROUP
    "T", // SHF_TLS
};

const char* elf_progtype[] = {
    "NULL",
    "LOAD",
    "DYNAMIC",
    "INTERP",
    "NOTE",
    "SHLIB",
    "PHDR",
    "TLS",
};

const char* elf_shbind[] = {
    "LOCAL",
    "GLOBAL",
    "WEAK",
};

const char* elf_symtype[] = {
    "NOTYPE",
    "OBJECT",
    "FUNC",
    "SECTION",
    "FILE",
    "COMMON",
    "TLS",
};

const char* elf_dyntype[] = {
    "NULL",
    "NEEDED",
    "PLTRELSZ",
    "PLTGOT",
    "HASH",
    "STRTAB",
    "SYMTAB",
    "RELA",
    "RELASZ",
    "RELAENT",
    "STRSZ",
    "SYMENT",
    "INIT",
    "FINI",
    "SONAME",
    "RPATH",
    "SYMBOLIC",
    "REL",
    "RELSZ",
    "RELENT",
    "PLTREL",
    "DEBUG",
    "TEXTREL",
    "JMPREL",
    "BIND_NOW",
    "INIT_ARRAY",
    "FINI_ARRAY",
    "INIT_ARRAYSZ",
    "FINI_ARRAYSZ",
    "RUNPATH",
    "FLAGS",
    "ENCODING",
    "PREINIT_ARRAY",
    "PREINIT_ARRAYSZ",
};

void info_elf_header(elfparser* parser)
{
    char* str;
    Elf32_Ehdr* hdr = parser->header;
    int i, j;
    Elf32_Shdr *shdr32;
    Elf32_Phdr *phdr32;
    
    log_info("--- ELF Header ---\n");
    log_info("ARCHITECTURE: %s, %s", elf_classtype[hdr->e_ident[EI_CLASS]],
             elf_datatype[hdr->e_ident[EI_DATA]]);
    log_info("TYPE: %s", elf_type[hdr->e_type]);
    
    switch (hdr->e_machine) {
        case EM_386:
            str = "Intel 8086";
            break;
            
        case EM_MIPS:
            str = "MIPS";
            break;
            
        case EM_ARM:
            str = "ARM";
            break;
    }
    log_info("MACHINE: %s", str);
    log_info("ENTRYPOINT: 0x%08x", hdr->e_entry);
    log_info("FLAG: 0x%08x", hdr->e_flags);
    log_info("HEADER SIZE: 0x%x", hdr->e_ehsize);
    
    log_info("\n--- SECTION HEADER TABLE ---\n");
    log_info("NAME\tTYPE\tFLAG\tADDRESS\tFILE OFFSET\tSIZE\tENTRY SIZE");
    
    for (i = 0, shdr32 = parser->shdr_table; i < parser->shdr_size; i++, shdr32++) {
        log_print("%s\t", get_section_name(parser, shdr32));
        
        if (shdr32->sh_type > ARRAY_SIZE(elf_shtype, char *)) {
            log_print("0x%08x\t", shdr32->sh_type);
        } else {
            log_print("%s\t", elf_shtype[shdr32->sh_type]);
        }
        
        if (!shdr32->sh_flags) {
            log_print("N");
        } else {
            for (j = 0; j < ARRAY_SIZE(elf_shflag, char *); j++) {
                if (shdr32->sh_flags & (1 << j)) {
                    log_print("%s", elf_shflag[j]);
                }
            }
        }
        log_info("\t0x%08x\t0x%x\t0x%x\t0x%x\t",
                 shdr32->sh_addr, shdr32->sh_offset, shdr32->sh_size, shdr32->sh_entsize);
    }
    
    log_info("\n--- PROGRAM HEADER TABLE ---\n");
    log_info("TYPE\tOFFSET\tVADDR\tFILE SIZE\tMEM SIZE\tFLAG");
    for (i = 0, phdr32 = parser->phdr_table; i < parser->phdr_size; i++, phdr32++) {
        if (phdr32->p_type < ARRAY_SIZE(elf_progtype, char *)) {
            log_print("%s\t", elf_progtype[phdr32->p_type]);
        } else if (phdr32->p_type == PT_ARM_EXIDX) {
            log_print("PT_ARM_EXIDX\t");
        } else {
            log_print("0x%x\t", phdr32->p_type);
        }
        
        log_print("0x%08x\t0x%08x\t0x%x\t0x%x\t",
                  phdr32->p_offset, phdr32->p_vaddr, phdr32->p_filesz, phdr32->p_memsz);
        log_info("%s%s%s", (phdr32->p_flags & PF_R) ? "R":"-",
                 (phdr32->p_flags & PF_W) ? "W":"-", (phdr32->p_flags & PF_X) ? "X":"-");
    }
}

void info_elf_sections(elfparser* parser)
{
    int i;
    Elf32_Shdr *shdr;
    
    for (i = 0, shdr = parser->shdr_table; i < parser->shdr_size; i++, shdr++) {
        switch (shdr->sh_type) {
            case SHT_REL:
            case SHT_RELA:
                parse_elf_section(parser->base, shdr, parser, info_section_reloc);
                break;
                
            case SHT_SYMTAB:
            case SHT_DYNSYM:
                parse_elf_section(parser->base, shdr, parser, info_section_symbol);
                break;
                
            case SHT_HASH:
                parse_elf_section(parser->base, shdr, parser, info_section_hash);
                break;
                
            case SHT_DYNAMIC:
                parse_elf_section(parser->base, shdr, parser, info_section_dynamic);
                break;
                
            default:
                break;
        }
    }
}

int info_section_dynamic(void* base, Elf32_Shdr *shdr, elfparser* parser, void* infoaddr, int infosize)
{
    log_info("\n>>> SECTION DYNAMIC <<<\n");
    log_info("dynamic symbol table for: %s",
             get_section_name(parser, parser->shdr_table + shdr->sh_link));
    
    return 0;
}

int info_section_hash(void* base, Elf32_Shdr *shdr, elfparser* parser, void* infoaddr, int infosize)
{
    log_info("\n>>> HASH <<<\n");
    log_info("hash symbol table for: %s",
             get_section_name(parser, parser->shdr_table + shdr->sh_link));
    
    return 0;
}

int info_section_reloc(void* base, Elf32_Shdr *shdr, elfparser* parser, void* infoaddr, int infosize)
{
    int i;
    Elf32_Rel *rel;
    
    rel = (Elf32_Rel *)infoaddr;
    log_info("\n>>> RELOC <<<\n");
    
    log_info("associcate symbol table: %s",
             get_section_name(parser, parser->shdr_table + shdr->sh_link));
    log_info("relocation applies for section: %s",
             get_section_name(parser, parser->shdr_table + shdr->sh_info));
    
    log_info("OFFSET\tSYMBOL INDEX\tTYPE");
    for (i = 0; i < infosize; i++, rel++) {
        log_info("(0x%x\t%d\t%d)",
                 rel->r_offset, ELF32_R_SYM(rel->r_info), ELF32_R_TYPE(rel->r_info));
    }
    
    return 0;
}

int info_section_symbol(void* base, Elf32_Shdr *shdr, elfparser* parser, void* infoaddr, int infosize)
{
    int i;
    Elf32_Sym* sym;
    Elf32_Shdr* sh_sstr;
    bool noname = false;
    
    sym = (Elf32_Sym *)infoaddr;
    log_info("\n>>> SYM <<<\n");
    log_info("NAME\tSECTION\tVALUE\tSIZE\tBIND\tTYPE");
    sh_sstr = parser->shdr_table + shdr->sh_link;
    if (verify_section(parser, sh_sstr) & E_ADDROUTOFRANGE) {
        noname = true;
    }
    for (i = 0; i < infosize; i++, sym++) {
        if (noname) {
            log_print("UNKNOWN\t");
        } else {
            log_print("%s\t", get_symbol_name(parser, sh_sstr, sym));
        }
        if (sym->st_shndx && sym->st_shndx < parser->shdr_size) {
            log_print("%s\t", get_section_name(parser, parser->shdr_table + sym->st_shndx));
        } else {
            switch (sym->st_shndx) {
                case SHN_UNDEF:
                    log_print("%s\t", "UNDEF");
                    break;
                    
                case SHN_ABS:
                    log_print("%s\t", "ABS");
                    break;
                    
                case SHN_COMMON:
                    log_print("%s\t", "COMMON");
                    break;
                    
                default:
                    break;
            }
        }
        
        log_print("0x%08x\t0x%x\t", sym->st_value, sym->st_size);
        if (ELF32_ST_BIND(sym->st_info) < ARRAY_SIZE(elf_shbind, char *)) {
            log_print("%s\t", elf_shbind[ELF32_ST_BIND(sym->st_info)]);
        } else {
            log_print("0x%x\t", ELF32_ST_BIND(sym->st_info));
        }
        
        if (ELF32_ST_TYPE(sym->st_info) < ARRAY_SIZE(elf_symtype, char *)) {
            log_print("%s\n", elf_symtype[ELF32_ST_TYPE(sym->st_info)]);
        } else {
            log_print("0x%x\n", ELF32_ST_TYPE(sym->st_info));
        }
    }
    
    return 0;
}

void info_dynamic(elfparser* parser)
{
    int i;
    Elf32_Dyn *dyn;
    
    log_info("\n>>> DYNAMIC <<<\n");
    log_info("TYPE\tPTR(VAL)");
    for (i = 0, dyn = parser->dyn_table; i < parser->dyn_size; i++, dyn++) {
        if (dyn->d_tag < ARRAY_SIZE(elf_dyntype, char *)) {
            log_print("%s\t", elf_dyntype[dyn->d_tag]);
        } else {
            log_print("0x%x\t", dyn->d_tag);
        }
        log_info("0x%x", dyn->d_un.d_ptr);
    }
}