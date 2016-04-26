/**
 * @file /cryptron/ecies.h
 *
 * @brief ECIES module functions.
 *
 * $Author: Ladar Levison $
 * $Website: http://lavabit.com $
 * $Date: 2010/08/06 06:02:03 $
 * $Revision: a51931d0f81f6abe29ca91470931d41a374508a7 $
 *
 */

#ifndef LAVABIT_ECIES_H
#define LAVABIT_ECIES_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/stack.h>

#define ECIES_CURVE NID_secp256k1
#define ECIES_CIPHER EVP_aes_256_cbc()
#define ECIES_HASHER EVP_sha256()
#define ECIES_AUTH_TAG_LENGTH 32 //As per 1609.2 it has to be of size 20. But as per openssl function EVP_MD_size(EEVP_sha256()) its 32
#define SYMMETRIC_KEY_LENGTH 16

typedef struct
{

    struct
    {
        uint8_t field_size;
    } length;

} secure_head_t;

typedef char * secure_t;

void secure_free(secure_t *cryptex);
void * secure_key_data(secure_t *cryptex);
void * secure_mac_data(secure_t *cryptex);
void * secure_body_data(secure_t *cryptex);
uint8_t secure_key_length(secure_t *cryptex);
uint8_t secure_mac_length();
uint8_t secure_body_length();
void * secure_alloc(uint64_t key, int *clen);

void ecies_group_init(void);
void ecies_group_free(void);
EC_GROUP * ecies_group(void);

void ecies_key_free(EC_KEY *key);

EC_KEY * ecies_key_create(void);
EC_KEY * ecies_key_create_public_hex(char *hex);
EC_KEY * ecies_key_create_private_hex(char *hex);
EC_KEY * ecies_key_create_public_octets(unsigned char *octets, size_t length);

char * ecies_key_public_get_hex(EC_KEY *key);
char * ecies_key_private_get_hex(EC_KEY *key);

secure_t * ecies_encrypt(char *key, unsigned char *data, size_t length, int *clen);
unsigned char * ecies_decrypt(char *key, secure_t *cryptex, size_t *length);

#endif
