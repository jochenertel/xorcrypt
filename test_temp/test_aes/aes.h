/***************************************************************************************************
 *
 * file     : aes.h
 * function : aes block cipher implementation
 *            - based on PUBLIC DOMAIN code from https://github.com/WaterJuice/WjCryptLib
 *            - this code has been distributed as PUBLIC DOMAIN
 * author   : Jochen Ertel
 * created  : 06.01.2019
 * updated  : 20.01.2019
 *
 **************************************************************************************************/

#ifndef AES_H
#define AES_H

#include <stdint.h>


/***************************************************************************************************
 * structure definition
 **************************************************************************************************/

typedef struct {
  uint32_t      eK[60];
  uint32_t      dK[60];
  uint_fast32_t Nr;
} aes_ctx_t;


/***************************************************************************************************
 * aes functions
 **************************************************************************************************/

/* key_size must be values of 16, 24 or 32 byte only */
void aes_init (aes_ctx_t *ctx, uint8_t *key, uint8_t key_size);

/* plain and cipher have to point to 16 byte arrays */
void aes_encrypt (aes_ctx_t *ctx, uint8_t *plain, uint8_t *cipher);
void aes_decrypt (aes_ctx_t *ctx, uint8_t *cipher, uint8_t *plain);


#endif
