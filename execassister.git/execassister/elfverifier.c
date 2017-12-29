//
//  elfverifier.c
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#include "elfverifier.h"
#include "utils.h"
#include <string.h>
#include "log.h"
#include "elfapi.h"

bool is_elf(Elf32_Ehdr* header)
{
    return (!strncmp((char *)header->e_ident, ELFMAG, 4));
}

int verify_header(elfparser* parser)
{
    int result = 0;

    if ((parser->header->e_shoff <= 0) || (parser->header->e_shnum <= 0)) {
        log_info("elf section header empty.");
        result |= E_NOSECTION;
    }
    if (parser->header->e_shstrndx >= parser->header->e_shnum) {
        log_info("elf section name table out of range.");
        result |= E_NAMEUNKNOWN;
    }
    return result;
}

int verify_segment(elfparser* parser, Elf32_Phdr* phdr)
{
    int result = 0;

    if (phdr->p_type == PT_NULL) {
        return result;
    }

    if (((addr_t)phdr->p_offset + phdr->p_filesz) > parser->size) {
        log_info("segment offset out of range.");
        result |= E_ADDROUTOFRANGE;
    }

    if (((addr_t)phdr->p_vaddr + phdr->p_memsz) > parser->size) {
        log_info("segment offset out of range.");
        result |= E_ADDROUTOFRANGE;
    }

    return result;
}

int verify_section(elfparser* parser, Elf32_Shdr* shdr)
{
    int result = 0;

    if (shdr->sh_type == SHT_NULL) {
        return result;
    }

    if (parser->shdr_sstr && shdr->sh_name >= parser->shdr_sstr->sh_size) {
        log_info("section name index out of range.");
        result |= E_NAMEUNKNOWN;
    }

    if ((shdr->sh_offset + shdr->sh_size) >= parser->size) {
        log_info("section offset out of range.");
        result |= E_ADDROUTOFRANGE;
    }

    if (shdr->sh_link >= parser->shdr_size) {
        goto check_link_failed;
    }

    if (IS_RELOC(shdr) && shdr->sh_info >= parser->shdr_size) {
        goto check_link_failed;
    }

    return result;
check_link_failed:
    log_info("section link index out of range.");
    return (result | E_INDEXOUTOFRANGE);
}

int verify_symbol(elfparser* parser, Elf32_Shdr* shdr, Elf32_Sym* sym)
{
    int result = 0;

    if (sym->st_name >= shdr->sh_size) {
        log_info("symbol name index out of range.");
        result |= E_NAMEUNKNOWN;
    }
    return result;
}
