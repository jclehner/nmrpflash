/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stdint.h>
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef struct {
	uint8_t data[64];
	uint32_t datalen;
	unsigned long long bitlen;
	uint32_t state[8];
} sha256_ctx;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t data[], size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t hash[]);

#endif   // SHA256_H
