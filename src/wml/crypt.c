/*
 * crypt.c
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#include "char_converter.h"
#include "crypt.h"

#ifdef _WIN32
//For CNG crypto APIs using bcrypt
BCRYPT_ALG_HANDLE	handle_Alg = NULL;
#define NT_SUCCESS(Status)		(((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL		((NTSTATUS)0xC0000001L)
#elif __linux__
//For Openssl EVP APIs
const EVP_MD	*md;
#endif

/*These global variables are required for calculating the cumulative hash */
int cumulative_hash_len = 0;
unsigned char cumulative_hash[MAX_HASH_LEN] = {'\0'};

static const char *hash_algorithms[] = {
	"SHA256"
};

int validateHashAlgorithm(char *hash_type) {

	int i;
	for (i = 0; i < sizeof(hash_algorithms) / sizeof(hash_algorithms[0]); i++)
	if (!strcmp(hash_type, hash_algorithms[i]))
		return 1;
	return 0;
}

int initializeHashAlgorithm(char *hash_type) {

#ifdef _WIN32
	size_t out_data_size;
	wchar_t hash_alg[10];
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	mbstowcs_s(&out_data_size, hash_alg, sizeof(hash_alg), hash_type, strnlen_s(hash_type, 9) + 1);
	status = BCryptOpenAlgorithmProvider(&handle_Alg, hash_alg, NULL, 0);
	if (!NT_SUCCESS(status)) {
		log_error("Could not open algorithm handle : 0x%x", status);
		return 0;
	}

	status = BCryptGetProperty(handle_Alg, BCRYPT_HASH_LENGTH, (PBYTE)&cumulative_hash_len, sizeof(DWORD), &out_data_size, 0);
	if (!NT_SUCCESS(status)) {
		log_error("Could not calculate hash size : 0x%x", status);
		BCryptCloseAlgorithmProvider(handle_Alg, 0);
		return 0;
	}
#elif __linux__
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(hash_type);
	if (md == NULL) {
		log_error("Digest Algorithm not supported by Openssl : %s", hash_type);
		return 0;
	}

	cumulative_hash_len = EVP_MD_size(md);
#endif
	return 1;
}

/*This function keeps track of the cumulative hash and stores it in a global variable (which is later written to a file) */
void generateCumulativeHash(char *hash, char *hash_type) {

    log_debug("Incoming Hash : %s", hash);
	char ob[MAX_HASH_LEN]= {'\0'};
	char cur_hash[MAX_HASH_LEN] = {'\0'};

	int cur_hash_len = hex2bin(hash, strnlen_s(hash, MAX_HASH_LEN), (unsigned char *)cur_hash, sizeof(cur_hash));
	bin2hex(cumulative_hash, cumulative_hash_len, ob, sizeof(ob));
	log_debug("Cumulative Hash before : %s", ob);

#ifdef _WIN32
	BCRYPT_HASH_HANDLE      handle_Hash_object = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   out_data_size = 0;

	status = BCryptCreateHash(handle_Alg, &handle_Hash_object, NULL, 0, NULL, 0, 0);
	if (!NT_SUCCESS(status)) {
		log_error("Could not create hash object : 0x%x", status);
		return;
	}

	status = BCryptHashData(handle_Hash_object, cumulative_hash, cumulative_hash_len, 0);
	if (!NT_SUCCESS(status)) {
		log_error("Could not calculate hash : 0x%x", status);
		BCryptDestroyHash(handle_Hash_object);
		return;
	}

	if (cur_hash_len == cumulative_hash_len) {
		status = BCryptHashData(handle_Hash_object, cur_hash, cur_hash_len, 0);
		if (!NT_SUCCESS(status)) {
			log_error("Could not calculate hash : 0x%x", status);
			BCryptDestroyHash(handle_Hash_object);
			return;
		}
	}
	else {
		log_warn("length of string converted from hex is : %d not equal to expected hash digest length : %d", cur_hash_len, cumulative_hash_len);
		log_warn("ERROR: current hash is not being updated in cumulative hash");
	}

	//Dump the hash in variable and finish the Hash Object handle
	status = BCryptFinishHash(handle_Hash_object, cumulative_hash, cumulative_hash_len, 0);
	BCryptDestroyHash(handle_Hash_object);
#elif __linux__
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);

	EVP_DigestUpdate(mdctx, cumulative_hash, cumulative_hash_len);
	if (cur_hash_len == cumulative_hash_len) {
		EVP_DigestUpdate(mdctx, cur_hash, cur_hash_len);
	}
	else {
		log_warn("length of string converted from hex is : %d not equal to expected hash digest length : %d", cur_hash_len, cumulative_hash_len);
		log_warn("ERROR: current hash is not being updated in cumulative hash");
	}

	//Dump the hash in variable and destroy the mdctx context
	EVP_DigestFinal_ex(mdctx, cumulative_hash, &cumulative_hash_len);
	EVP_MD_CTX_destroy(mdctx);
#endif
	bin2hex(cumulative_hash, cumulative_hash_len, ob, sizeof(ob));
	log_debug("Cumulative Hash after : %s", ob);
}

void generateFileHash(char *output, FILE *file, char *hash_type) {

	int bytesRead = 0;
	const int bufSize = 65000;
	unsigned char hash_value[MAX_HASH_LEN];

    char *buffer = (char *)malloc(bufSize);
    if(!buffer) {
		log_error("Can't allocate memory for buffer");
        return;
    }

#ifdef _WIN32
	BCRYPT_HASH_HANDLE      handle_Hash_object = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   out_data_size = 0;

	status = BCryptCreateHash(handle_Alg, &handle_Hash_object, NULL, 0, NULL, 0, 0);
	if (!NT_SUCCESS(status)) {
		log_error("Could not create hash object : 0x%x", status);
		free(buffer);
		return;
	}

	while ((bytesRead = fread(buffer, 1, bufSize, file))) {
		// calculate hash of bytes read
		status = BCryptHashData(handle_Hash_object, buffer, bytesRead, 0);
		if (!NT_SUCCESS(status)) {
			log_error("Could not calculate hash : 0x%x", status);
			BCryptDestroyHash(handle_Hash_object);
			free(buffer);
			return;
		}
	}

	//Dump the hash in variable and finish the Hash Object handle
	status = BCryptFinishHash(handle_Hash_object, hash_value, cumulative_hash_len, 0);
	BCryptDestroyHash(handle_Hash_object);
#elif __linux__
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	while ((bytesRead = fread(buffer, 1, bufSize, file))) {
		// calculate hash of bytes read
		EVP_DigestUpdate(mdctx, buffer, bytesRead);
	}

	//Dump the hash in variable and destroy the mdctx context
	EVP_DigestFinal_ex(mdctx, hash_value, &cumulative_hash_len);
	EVP_MD_CTX_destroy(mdctx);
#endif
	bin2hex(hash_value, cumulative_hash_len, output, MAX_HASH_LEN);
	generateCumulativeHash(output, hash_type);
	free(buffer);
}

void generateStrHash(char *output, char *str, char *hash_type) {

	unsigned char hash_value[MAX_HASH_LEN];

#ifdef _WIN32
	BCRYPT_HASH_HANDLE      handle_Hash_object = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   out_data_size = 0;

	status = BCryptCreateHash(handle_Alg, &handle_Hash_object, NULL, 0, NULL, 0, 0);
	if (!NT_SUCCESS(status)) {
		log_error("Could not create hash object : 0x%x", status);
		return;
	}

	status = BCryptHashData(handle_Hash_object, str, strnlen_s(str, MAX_LEN), 0);
	if (!NT_SUCCESS(status)) {
		log_error("Could not calculate hash : 0x%x", status);
		BCryptDestroyHash(handle_Hash_object);
		return;
	}

	//Dump the hash in variable and finish the Hash Object handle
	status = BCryptFinishHash(handle_Hash_object, hash_value, cumulative_hash_len, 0);
	BCryptDestroyHash(handle_Hash_object);
#elif __linux__
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, str, strnlen_s(str, MAX_LEN));

	//Dump the hash in variable and destroy the mdctx context
	EVP_DigestFinal_ex(mdctx, hash_value, &cumulative_hash_len);
	EVP_MD_CTX_destroy(mdctx);
#endif
	bin2hex(hash_value, cumulative_hash_len, output, MAX_HASH_LEN);
	generateCumulativeHash(output, hash_type);
}
