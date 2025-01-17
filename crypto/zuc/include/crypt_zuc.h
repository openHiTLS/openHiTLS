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

#ifndef CRYPT_ZUC_H
#define CRYPT_ZUC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ZUC

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


#define CRYPT_ZUC128 0x01
#define CRYPT_ZUC256 0x02
#define CRYPT_ZUC128_KEYLEN 16
#define CRYPT_ZUC256_KEYLEN 32
#define CRYPT_ZUC_MAX_KEYLEN 32
#define CRYPT_ZUC_IVLEN16B 16
#define CRYPT_ZUC_IVLEN23B 23
#define CRYPT_ZUC_IVARRLEN 25
#define CRYPT_ZUC_MAX_KEYSTREAMLEN 65536

#define KEYSET 0x01
#define IVSET  0x02

typedef struct{
    uint32_t S[16]; // LFSR Registers
    uint32_t X[4];  // BitReorganization outputs registers
    uint32_t R[2];  // F Registers
    uint8_t key[CRYPT_ZUC_MAX_KEYLEN];
    uint8_t iv[CRYPT_ZUC_IVARRLEN];
    uint8_t set;  // bit 0 for keyset, bit 1 for iv set
    uint8_t type; // 0x01 for ZUC128, 0x02 for ZUC256
    uint8_t ivlen;
    uint8_t cache_padding[3]; // aligned 160 bytes
} CRYPT_ZUC_Ctx;

/**
 * @ingroup zuc
 * @brief Encrypt/Decrypt stream with key stream.
 *
 * @param ctx [IN]  ZUC handle
 * @param in  [IN]  Input stream.
 * @param out [OUT] Output stream. 
 * @param len [IN]  Input stream length.
*/
int32_t CRYPT_ZUC_Update(CRYPT_ZUC_Ctx *ctx, const uint8_t *in,
    uint8_t *out, uint32_t len);

/**
 * @ingroup zuc
 * @brief Set/Get IV with val.
 *
 * @param ctx [IN]  ZUC handle.
 * @param opt [IN]  CRYPT_
 * @param out [OUT] Output stream. 
 * @param len [IN]  Input stream length. Should be divisible by 4
*/
int32_t CRYPT_ZUC_Ctrl(CRYPT_ZUC_Ctx *ctx, int32_t opt, void *val, uint32_t len);

void CRYPT_ZUC_Clean(CRYPT_ZUC_Ctx *ctx);

/**
 * @ingroup zuc
 * @brief Set the ZUC encryption key.
 *
 * @param ctx [IN]  ZUC handle
 * @param key [IN]  Encryption key
 * @param len [IN]  Key length. The value must be 32 bytes.
*/
int32_t CRYPT_ZUC_SetKey128(CRYPT_ZUC_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup zuc
 * @brief Set the ZUC encryption key.
 *
 * @param ctx [IN]  ZUC handle
 * @param key [IN]  Encryption key
 * @param len [IN]  Key length. The value must be 32 bytes.
*/
int32_t CRYPT_ZUC_SetKey256(CRYPT_ZUC_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup zuc
 * @brief Set the ZUC Initialization Vector.
 *
 * @param ctx [IN]  ZUC handle
 * @param iv  [IN]  Initialization Vector
 * @param len [IN]  IV length. The value must be 16 bytes.
*/
int32_t CRYPT_ZUC_SetIV(CRYPT_ZUC_Ctx *ctx, const uint8_t *iv, uint32_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_AES

#endif // CRYPT_AES_H
