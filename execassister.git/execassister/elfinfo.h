//
//  elfinfo.h
//  execassister
//
//  Created by j1gsaw on 14-10-30.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#ifndef __execassister__elfinfo__
#define __execassister__elfinfo__

#include "elfparser.h"

void info_elf_header(elfparser* parser);
void info_elf_sections(elfparser* parser);
void info_elf_segments(elfparser* parser);
void info_dynamic(elfparser* parser);

int info_section_dynamic(void* base, Elf32_Shdr *shdr, elfparser* parser, void* estart, int esize);
int info_section_hash(void* base, Elf32_Shdr *shdr, elfparser* parser, void* infoaddr, int infosize);
int info_section_reloc(void* base, Elf32_Shdr *shdr, elfparser* parser, void* infoaddr, int infosize);
int info_section_symbol(void* base, Elf32_Shdr *shdr, elfparser* parser, void* infoaddr, int infosize);

#endif /* defined(__execassister__elfinfo__) */
