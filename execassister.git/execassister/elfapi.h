//
//  elfapi.h
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#ifndef __execassister__elfapi__
#define __execassister__elfapi__

#include "elfparser.h"
#include "elfloader.h"

typedef int (*_section_callback)(void*          base,
                                 Elf32_Shdr*    shdr,
                                 elfparser*     parser,
                                 void*          entry_start,
                                 int            entry_size);

int parse_elf_header(u1* base, elfparser* parser);
int parse_elf_segments(u1* base, elfparser* parser);
int parse_elf_sections(u1* base, elfparser* parser);
int parse_elf_dynamic(u1* base, Elf32_Phdr* phdr, elfparser* parser);
int parse_elf_section(u1* base, Elf32_Shdr* shdr, elfparser* parser, _section_callback callback);

char* get_section_name(elfparser* parser, Elf32_Shdr* shdr);
char* get_symbol_name(elfparser* parser, Elf32_Shdr* shdr, Elf32_Sym* sym);

elfparser* load_to_parse(elf_loader* loader);
elf_needed* load_elf_needed(elf_loader* loader);
int elf_reloc(elf_loader* loader);
int symbol_reloc(elf_loader* loader, Elf32_Rel* rels, int relnum);

addr_t calc_bias(soinfo* si);
addr_t find_symbol(elf_needed* needed, char* symname);
int check_addr_perm(addr_t addr, int flag);

int elf_dump(elf_loader* loader, char* dstname);
int fix_phdr_table(elf_loader* loader);
int fix_reloc(elf_loader* loader, Elf32_Rel* rels, int relnum);

#define IS_RELOC(shdr) (shdr->sh_type != SHT_REL && shdr->sh_type != SHT_RELA)
#define IS_SYMBOL(shdr) (shdr->sh_type != SHT_STRTAB && shdr->sh_type != SHT_DYNSYM)

#define ADDR_R 0100
#define ADDR_W 0010
#define ADDR_X 0001

#endif /* defined(__execassister__elfapi__) */
