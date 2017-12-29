//
//  log.c
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#include "log.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#define LOG_MAX 1024

void log_error(const char* fmt, ...)
{
    char buf[LOG_MAX];
    va_list arg;
    
    va_start(arg, fmt);
    
    vsnprintf(buf, LOG_MAX, fmt, arg);
    fprintf(stderr, "%s(error: %s)\n", buf, strerror(errno));
#ifdef __ANDROID__
    LOGE("%s(error: %s)\n", buf, strerror(errno));
#endif
    va_end(arg);
}

void log_info(const char* fmt, ...)
{
    char buf[LOG_MAX];
    va_list arg;
    
    va_start(arg, fmt);
    
    vsnprintf(buf, LOG_MAX, fmt, arg);
    fprintf(stdout, "%s\n", buf);
#ifdef __ANDROID__
    LOGI("%s\n", buf);
#endif
    va_end(arg);
}

void log_print(const char* fmt, ...)
{
    char buf[LOG_MAX];
    va_list arg;
    
    va_start(arg, fmt);
    
    vsnprintf(buf, LOG_MAX, fmt, arg);
    fprintf(stdout, "%s", buf);
#ifdef __ANDROID__
    LOGI("%s", buf);
#endif
    va_end(arg);
}