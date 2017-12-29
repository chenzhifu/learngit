//
//  elfverifier.h
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#ifndef __execassister__elfverifier__
#define __execassister__elfverifier__

#include "elfparser.h"
#include "utils.h"

bool is_elf(Elf32_Ehdr* header);
int verify_header(elfparser* parser);
int verify_section(elfparser* parser, Elf32_Shdr* shdr);
int verify_symbol(elfparser* parser, Elf32_Shdr* shdr, Elf32_Sym* sym);
int verify_segment(elfparser* parser, Elf32_Phdr* phdr);

#endif /* defined(__execassister__elfverifier__) */
