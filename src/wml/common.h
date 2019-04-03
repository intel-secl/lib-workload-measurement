/*
 * common.h
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#elif __linux__
#include <linux/limits.h>
#include "safe_lib.h"
#endif

#include "log.h"

#ifdef _WIN32
#define popen		_popen
#define pclose		_pclose
#define snprintf	sprintf_s
//For memory allocation and deallocation
#define malloc(size) 		HeapAlloc(GetProcessHeap(), 0, size)
#define free(mem_ptr) 		HeapFree(GetProcessHeap(),0, mem_ptr)
#define calloc(count, size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, count*size)
#endif

#ifdef _WIN32
#define MAX_CMD_LEN 8192
#elif __linux__
#define MAX_CMD_LEN ARG_MAX
#endif

#define MAX_LEN 4096
#define NODE_LEN 512

char node_value[NODE_LEN];
char fs_mount_path[NODE_LEN];

#endif /* COMMON_H_ */
