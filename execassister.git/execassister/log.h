//
//  log.h
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#ifndef __execassister__log__
#define __execassister__log__

#ifdef __ANDROID__
#include <android/log.h>

#define _TAG        "ExecAssister"
#define _TAG_ERROR  "ExecAssisterError"
#define _TAG_LOG    "ExecAssisterLog"

#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, _TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG  , _TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO   , _TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN   , _TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR  , _TAG, __VA_ARGS__)

#endif /* defined(__ANDROID__) */

void log_error(const char* fmt, ...);
void log_info(const char* fmt, ...);
void log_print(const char* fmt, ...);

#endif /* defined(__execassister__log__) */
