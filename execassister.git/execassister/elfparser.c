//
//  elfparser.c
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#include "elfparser.h"
#include <sys/mman.h>
#include <stdlib.h>
#include "log.h"
#include "elfapi.h"

elfparser* elf_parse(int fd, off_t fsize)
{
    void* elfmem;
    elfparser* parser;
    
    if ((parser = malloc(sizeof(elfparser))) == 0) {
        log_error("malloc elfparser failed.");
        return 0;
    }
    memset(parser, 0, sizeof(elfparser));
    
    if ((elfmem = mmap(0, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) < 0) {
        log_error("mmap elf failed.");
        free(parser);
        return 0;
    }
    parser->base = elfmem;
    parser->size = fsize;
    
    if (parse_elf_header(elfmem, parser) < 0) {
        log_error("elf header parse failed.");
        goto parse_failed;
    }
    
    if (parse_elf_segments(elfmem, parser) < 0) {
        log_error("elf program table parse failed.");
        goto parse_failed;
    }
    
    if (parse_elf_sections(elfmem, parser) < 0) {
        log_error("elf section table parse failed.");
        goto parse_failed;
    }
    
    return parser;
    
parse_failed:
    munmap(elfmem, fsize);
    free(parser);
    return 0;
}