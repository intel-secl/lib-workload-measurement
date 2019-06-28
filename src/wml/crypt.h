/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * crypt.h
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#ifndef CRYPT_H_
#define CRYPT_H_

#define MAX_HASH_LEN 97

int validateHashAlgorithm(char *hash_type);
int initializeHashAlgorithm(char *hash_type);
void generateCumulativeHash(char *hash, char *hash_type);
void generateFileHash(char *output, FILE *file, char *hash_type);
void generateStrHash(char *output, char *str, char *hash_type);

#endif /* CRYPT_H_ */
