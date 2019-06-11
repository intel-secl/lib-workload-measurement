/*
 * crypt.h
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#ifndef CRYPT_H_
#define CRYPT_H_

#include "common.h"

#ifdef _WIN32
#include <bcrypt.h>
#elif __linux__
#include <openssl/evp.h>
#endif

#define MAX_HASH_LEN 97

int validateHashAlgorithm(char *hash_type);
int initializeHashAlgorithm(char *hash_type);
void generateCumulativeHash(char *hash, char *hash_type);
void generateFileHash(char *output, FILE *file, char *hash_type);
void generateStrHash(char *output, char *str, char *hash_type);

#endif /* CRYPT_H_ */
