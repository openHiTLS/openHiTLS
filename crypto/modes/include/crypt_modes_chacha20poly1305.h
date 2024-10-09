/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_MODES_CHACHA20POLY1305_H
#define CRYPT_MODES_CHACHA20POLY1305_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CHACHA20POLY1305

#include <stdint.h>
#include "crypt_local_types.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    uint32_t acc[6];    // The intermediate data of the acc, must be greater than 130 bits.
    uint32_t r[4];      // Key information r, 16 bytes, that is, 4 * sizeof(uint32_t)
    uint32_t s[4];      // Key information s, 16 bytes, that is, 4 * sizeof(uint32_t)
    uint32_t table[36]; // Indicates the table used to accelerate the assembly calculation.
    uint8_t last[16];   // A block 16 bytes are cached for the last unprocessed data.
    uint32_t lastLen;   // Indicates the remaining length of the last data.
    uint32_t flag;      // Used to save the assembly status information.
} Poly1305Ctx;

typedef struct {
    void *key; // Handle for the method.
    const EAL_CipherMethod *method; // algorithm method
    Poly1305Ctx polyCtx;
    uint64_t aadLen; // Status, indicating whether identification data is set.
    uint64_t cipherTextLen; // status, indicating whether the identification data is set.
} MODES_CHACHA20POLY1305_Ctx;

int32_t MODES_CHACHA20POLY1305_InitCtx(MODES_CHACHA20POLY1305_Ctx *ctx, const struct EAL_CipherMethod *m);

void MODES_CHACHA20POLY1305_DeinitCtx(MODES_CHACHA20POLY1305_Ctx *ctx);

void MODES_CHACHA20POLY1305_Clean(MODES_CHACHA20POLY1305_Ctx *ctx);

int32_t MODES_CHACHA20POLY1305_Ctrl(MODES_CHACHA20POLY1305_Ctx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len);

int32_t MODES_CHACHA20POLY1305_SetEncryptKey(MODES_CHACHA20POLY1305_Ctx *ctx, const uint8_t *key, uint32_t len);

int32_t MODES_CHACHA20POLY1305_SetDecryptKey(MODES_CHACHA20POLY1305_Ctx *ctx, const uint8_t *key, uint32_t len);

int32_t MODES_CHACHA20POLY1305_Encrypt(MODES_CHACHA20POLY1305_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

int32_t MODES_CHACHA20POLY1305_Decrypt(MODES_CHACHA20POLY1305_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CHACHA20POLY1305

#endif // CRYPT_MODES_CHACHA20POLY1305_H
