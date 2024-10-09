/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef CRYPT_MODES_GCM_H
#define CRYPT_MODES_GCM_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_GCM

#include <stdint.h>
#include "crypt_local_types.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define GCM_BLOCKSIZE 16

typedef struct {
    uint64_t h;
    uint64_t l;
} MODES_GCM_GF128;

typedef struct {
    // The information can be set once and used multiple times.
    uint8_t iv[GCM_BLOCKSIZE];      // Processed IV information. The length is 16 bytes.
    uint8_t ghash[GCM_BLOCKSIZE];   // Intermediate data for tag calculation.
    MODES_GCM_GF128 hTable[16]; // The window uses 4 bits, 2 ^ 4 = 16 entries need to be pre-calculated.
    void *ciphCtx; // Context defined by each symmetric algorithm.
    const EAL_CipherMethod *ciphMeth; // algorithm method
    /**
     * tagLen may be any one of the following five values: 16, 15, 14, 13, or 12 bytes
     * For certain applications, tagLen may be 8 or 4 bytes
     */
    uint8_t tagLen;
    uint32_t cryptCnt; // Indicate the number of encryption times that the key can be used.

    // Intermediate encryption/decryption information. The lifecycle is one encryption/decryption operation,
    // and needs to be reset during each encryption/decryption operation.
    uint8_t last[GCM_BLOCKSIZE];    // ctr mode last
    uint8_t remCt[GCM_BLOCKSIZE];     // Remaining ciphertext
    uint8_t ek0[GCM_BLOCKSIZE];     // ek0
    uint64_t plaintextLen;  // use for calc tag
    uint32_t aadLen;        // use for calc tag
    uint32_t lastLen;       // ctr mode lastLen
} MODES_GCM_Ctx;

int32_t MODES_GCM_InitCtx(MODES_GCM_Ctx *ctx, const struct EAL_CipherMethod *m);

void MODES_GCM_DeinitCtx(MODES_GCM_Ctx *ctx);

void MODES_GCM_Clean(MODES_GCM_Ctx *ctx);

int32_t MODES_GCM_Ctrl(MODES_GCM_Ctx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len);

int32_t MODES_GCM_SetKey(MODES_GCM_Ctx *ctx, const uint8_t *ciphCtx, uint32_t len);

int32_t MODES_GCM_InitHashTable(MODES_GCM_Ctx *ctx);

int32_t MODES_GCM_Encrypt(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

int32_t MODES_GCM_Decrypt(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#ifdef HITLS_CRYPTO_AES
int32_t AES_GCM_EncryptBlock(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

int32_t AES_GCM_DecryptBlock(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif  // HITLS_CRYPTO_AES

#ifdef HITLS_CRYPTO_SM4
/**
 * @brief SM4-GCM mode key setting
 *
 * @param ctx [IN] Mode handle
 * @param key [IN] Encryption key
 * @param len [IN] Encryption key length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_GCM_SetKey(MODES_GCM_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief SM4-GCM mode encryption
 *
 * @param [IN] ctx  Mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_GCM_EncryptBlock(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief SM4-GCM mode decryption
 *
 * @param ctx [IN]  Mode handle
 * @param in [IN]   Data to be decrypted
 * @param out [OUT] Decrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_GCM_DecryptBlock(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif // HITLS_CRYPTO_SM4

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_GCM

#endif // CRYPT_MODES_GCM_H
