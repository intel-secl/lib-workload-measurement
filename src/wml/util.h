/*
 * util.h
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#ifndef UTIL_H_
#define UTIL_H_

#include "common.h"

char *toUpperCase(char *str);
void tagEntry(char* line);
char *getTagValue(char *line, char *key);
void convertWildcardToRegex(char *wildcard);
char *tokenizeString(char *line, char *delim);
FILE *getMatchingEntries(char *line, FILE *fd, char file_type);
void replaceAllStr(char * orig_str, char * search_str, char * replace_str);

void calculateSymlinkHashUtil(char *sym_path, FILE *fq, char *hash_type, int version);
void calculateFileHashUtil(char *file_path, FILE *fq, char *hash_type, int version);
void calculateDirHashUtil(char *dir_path, char *include, char *exclude, FILE *fq, char *hash_type);

#endif /* UTIL_H_ */
