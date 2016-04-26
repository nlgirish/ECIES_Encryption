/**
 * @file /cryptron/secure.c
 *
 * @brief Functions for handling the secure data type.
 *
 * $Author: Ladar Levison $
 * $Website: http://lavabit.com $
 * $Date: 2010/08/05 11:43:50 $
 * $Revision: c363dfa193830feb5d014a7c6f0abf2d1365f668 $
 *
 */

#include "ecies.h"

uint8_t secure_key_length(secure_t *cryptex)
{
    secure_head_t *head = (secure_head_t *)cryptex;
    return head->length.field_size;
}

uint8_t secure_mac_length()
{
    return ECIES_AUTH_TAG_LENGTH;
}

uint8_t secure_body_length()
{
    return SYMMETRIC_KEY_LENGTH;
}

void * secure_key_data(secure_t *cryptex)
{
    return (char *)cryptex + sizeof(secure_head_t);
}

void * secure_mac_data(secure_t *cryptex)
{
    secure_head_t *head = (secure_head_t *)cryptex;
    return (char *)cryptex + (sizeof(secure_head_t) + (head->length.field_size * sizeof(unsigned long)) + SYMMETRIC_KEY_LENGTH);
}

void * secure_body_data(secure_t *cryptex)
{
    secure_head_t *head = (secure_head_t *)cryptex;
    return (char *)cryptex + (sizeof(secure_head_t) + (head->length.field_size * sizeof(unsigned long)));
}

//As per 1609.2: MAC size is 32 and Body (symmetric Key length) is 16
void * secure_alloc(uint64_t key, int *clen)
{
    secure_t *cryptex = malloc(sizeof(secure_head_t) + (key * sizeof(unsigned long)) + ECIES_AUTH_TAG_LENGTH + SYMMETRIC_KEY_LENGTH);
    *clen = sizeof(secure_head_t) + (key * sizeof(unsigned long)) + ECIES_AUTH_TAG_LENGTH + SYMMETRIC_KEY_LENGTH;
    secure_head_t *head = (secure_head_t *)cryptex;
    head->length.field_size = key;
    return cryptex;
}

void secure_free(secure_t *cryptex)
{
    free(cryptex);
    return;
}
