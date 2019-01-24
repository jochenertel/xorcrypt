/***************************************************************************************************
 *
 * file     : sha256.h
 * function : sha256 hash implementation
 *            - based on PUBLIC DOMAIN code from https://github.com/jb55/sha256.c
 *            - this code has been distributed as PUBLIC DOMAIN
 *            - includes sha256 as well as its hmac mode of operation
 * author   : Jochen Ertel
 * created  : 11.12.2018
 * updated  : 11.12.2018
 *
 **************************************************************************************************/

#ifndef SHA256_H
#define SHA256_H

#include <stdlib.h>
#include <stdint.h>


/***************************************************************************************************
 * structure definitions
 **************************************************************************************************/

typedef struct {
  uint32_t state[8];
  uint64_t count;
  uint8_t  buffer[64];
} sha256_ctx_t;

typedef struct {
  sha256_ctx_t hash;
  uint8_t      k0[64];
} hmac_sha256_ctx_t;


/***************************************************************************************************
 * sha256 functions
 **************************************************************************************************/

void sha256_init   (sha256_ctx_t *ctx);
void sha256_update (sha256_ctx_t *ctx, const uint8_t *data, size_t size);
void sha256_final  (sha256_ctx_t *ctx, uint8_t *digest);

void sha256 (const uint8_t *data, size_t size, uint8_t *digest);


/***************************************************************************************************
 * hmac_sha256 functions
 **************************************************************************************************/

void hmac_sha256_init   (hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t size);
void hmac_sha256_update (hmac_sha256_ctx_t *ctx, const uint8_t *data, size_t size);
void hmac_sha256_final  (hmac_sha256_ctx_t *ctx, uint8_t *mac);

void hmac_sha256 (const uint8_t *key, size_t ksize, const uint8_t *data, size_t dsize, uint8_t *mac);

#endif
