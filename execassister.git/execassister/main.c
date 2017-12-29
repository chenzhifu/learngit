//
//  main.c
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#include <fcntl.h>
#include <sys/stat.h>
#include "log.h"
#include "elfparser.h"
#include "elfinfo.h"
#include "elfloader.h"

typedef enum {
    TYPE_ELF,
    TYPE_DEX,
    TYPE_ODEX,
    TYPE_OAT,
    TYPE_MACHO,
} EXECTYPE;

int load(const char* path)
{
    int fd;
    struct stat stat;
    elfparser* parser;
    elf_loader* loader;

    if ((fd = open(path, O_RDWR)) <= 0) {
        log_error("open %s failed.", path);
        return -1;
    }
    fstat(fd, &stat);

    parser = elf_parse(fd, stat.st_size);
    if (parser) {
        info_elf_header(parser);
        info_elf_sections(parser);
        info_dynamic(parser);
    }

    loader = elf_load(fd, stat.st_size);
    if (loader->parser->init_func) {
        log_info("execute init.");
        loader->parser->init_func();
    }
    log_info("start dump.");
    elf_dump(loader, "unpacked");
    log_info("end dump.");

    return 0;
}

int main(int argc, char** argv)
{
    //load("/Users/j1gsaw/Desktop/libsecexe.so");
    load(argv[1]);
    return 0;
}
