/*
 * logging.c
 *
 *  Created on: 14-June-2018
 *      Author: Arvind Rawat
 */

#include <fcntl.h>
#ifdef __linux__
#include <stdlib.h>
#endif

#include "logging.h"
#include "log.h"

#ifdef _WIN32
#define default_log_file "C:/Logs/wml/measure.log"
#elif __linux__
#define default_log_file "/var/log/wml/measure.log"
#endif

#define default_log_level LOG_INFO

static const char *level_names[] = {
  "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

int str2enum (const char *str)
{
    int i;
    for (i = 0; i < sizeof(level_names)/sizeof(level_names[0]); i++)
        if (!strcmp(str, level_names[i]))
            return i;
	return -1;
}

#define BUFSIZE 4096

FILE* configure_logger() {

	int fd = -1;
	FILE *fp = NULL;
	int log_level = -1;
	char *log_file = NULL;

	const char* lf = getenv("WML_LOG_FILE");
	if (lf != NULL) {
#ifdef _WIN32
		char *buffer = malloc(BUFSIZE);
		char** lppPart = NULL;
		if (GetFullPathName(lf, BUFSIZE, buffer, lppPart)) {
			log_file = buffer;
		}
#elif __linux__
		log_file = realpath(lf, NULL);
#endif
		if (log_file == NULL) {
			printf("Invalid log file specified\n");
			return NULL;
		}
#ifdef _WIN32
		fd = open(log_file, O_CREAT | O_WRONLY | O_APPEND, S_IREAD | S_IWRITE);
#elif __linux__
		fd = open(log_file, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
		if (fd == -1) {
			printf("Unable to get file descriptor for log file\n");
			free(log_file);
			return NULL;
		}

		fp = fdopen(fd, "a");
		//fp = fopen(log_file, "a");
		free(log_file);
	}
	else {
		fp = fopen(default_log_file, "w");
	}
	
	if (fp == NULL) {
		printf("Unable to open log file\n");
		return NULL;
	}
	
	const char* ll = getenv("WML_LOG_LEVEL");
	if (ll != NULL) {
		log_level = str2enum(ll);
		if (log_level == -1) {
			printf("Invalid log level specified\n");
			fclose(fp);
			return NULL;
		}
	}
	else {
		log_level = default_log_level;
	}
	
	log_set_fp(fp);
	log_set_level(log_level);
	log_set_quiet(1);
	
	return fp;
}
