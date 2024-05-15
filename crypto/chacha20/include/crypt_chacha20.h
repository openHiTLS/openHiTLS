/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_CHACHA20_H
#define CRYPT_CHACHA20_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CHACHA20

#include <stdint.h>
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CHACHA20_STATESIZE 16
#define CHACHA20_STATEBYTES (CHACHA20_STATESIZE * sizeof(uint32_t))
#define CHACHA20_KEYLEN 32
#define CHACHA20_NONCELEN 12

typedef struct {
    uint32_t state[CHACHA20_STATESIZE]; // state RFC 7539
    union {
        uint32_t c[CHACHA20_STATESIZE];
        uint8_t u[CHACHA20_STATEBYTES];
    } last; // save the last data
    uint32_t lastLen; // remaining length of the last data in bytes
    uint8_t set; // indicates whether the key and nonce are set
} CRYPT_CHACHA20_Ctx;

int32_t CRYPT_CHACHA20_SetKey(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *key, uint32_t keyLen);

int32_t CRYPT_CHACHA20_Update(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *in,
    uint8_t *out, uint32_t len);

int32_t CRYPT_CHACHA20_Ctrl(CRYPT_CHACHA20_Ctx *ctx, CRYPT_CipherCtrl opt,
    void *val, uint32_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CHACHA20

#endif // CRYPT_CHACHA20_H
