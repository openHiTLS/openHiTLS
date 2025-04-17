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

#ifndef CRYPT_SLH_DSA_H
#define CRYPT_SLH_DSA_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stdint.h>
#include "bsl_params.h"

typedef struct SlhDsaCtx CryptSlhDsaCtx;
typedef struct HashFuncs SlhDsaHashFuncs;
typedef union Adrs SlhDsaAdrs;

/**
 * @brief Create a new SLH-DSA context
 * 
 * @return CryptSlhDsaCtx* Pointer to the new SLH-DSA context
 */
CryptSlhDsaCtx *CRYPT_SLH_DSA_NewCtx(void);

/**
 * @brief Create a new SLH-DSA context
 * 
 * @param libCtx Pointer to the library context
 * 
 * @return CryptSlhDsaCtx* Pointer to the new SLH-DSA context
 */
CryptSlhDsaCtx *CRYPT_SLH_DSA_NewCtxEx(void *libCtx);

/**
 * @brief Free a SLH-DSA context
 * 
 * @param ctx Pointer to the SLH-DSA context
 */
void CRYPT_SLH_DSA_FreeCtx(CryptSlhDsaCtx *ctx);

/**
 * @brief Generate a SLH-DSA key pair
 * 
 * @param ctx Pointer to the SLH-DSA context
 */
int32_t CRYPT_SLH_DSA_Gen(CryptSlhDsaCtx *ctx);

/**
 * @brief Sign data using SLH-DSA, the msg is pre-hashed, and the hash-id should be set before calling this function.
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param msg Pointer to the message to sign
 * @param msgLen Length of the message
 * @param sig Pointer to the signature
 * @param sigLen Length of the signature
 */
int32_t CRYPT_SLH_DSA_SignData(CryptSlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
                               uint32_t *sigLen);

/**
 * @brief Verify data using SLH-DSA, the msg is pre-hashed, and the hash-id should be set before calling this function.
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param msg Pointer to the message to verify
 * @param msgLen Length of the message
 * @param sig Pointer to the signature
 * @param sigLen Length of the signature
 */
int32_t CRYPT_SLH_DSA_VerifyData(const CryptSlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
                                 uint32_t sigLen);

/**
 * @brief Sign data using SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param algId Algorithm ID
 * @param data Pointer to the data to sign
 * @param dataLen Length of the data
 * @param sign Pointer to the signature
 * @param signLen Length of the signature
 */
int32_t CRYPT_SLH_DSA_Sign(CryptSlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                           uint32_t *signLen);

/**
 * @brief Verify data using SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param algId Algorithm ID
 * @param data Pointer to the data to verify
 * @param dataLen Length of the data
 * @param sign Pointer to the signature
 * @param signLen Length of the signature
 */

int32_t CRYPT_SLH_DSA_Verify(const CryptSlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                             const uint8_t *sign, uint32_t signLen);

/**
 * @brief Control function for SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param opt Option
 * @param val Value
 * @param len Length of the value
 */
int32_t CRYPT_SLH_DSA_Ctrl(CryptSlhDsaCtx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @brief Get the public key of SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param para Pointer to the public key
 */
int32_t CRYPT_SLH_DSA_GetPubKey(const CryptSlhDsaCtx *ctx, BSL_Param *para);

/**
 * @brief Get the private key of SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param para Pointer to the private key
 */
int32_t CRYPT_SLH_DSA_GetPrvKey(const CryptSlhDsaCtx *ctx, BSL_Param *para);

/**
 * @brief Set the public key of SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param para Pointer to the public key
 */
int32_t CRYPT_SLH_DSA_SetPubKey(CryptSlhDsaCtx *ctx, const BSL_Param *para);

/**
 * @brief Set the private key of SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param para Pointer to the private key
 */
int32_t CRYPT_SLH_DSA_SetPrvKey(CryptSlhDsaCtx *ctx, const BSL_Param *para);

#endif // HITLS_CRYPTO_SLH_DSA
#endif // CRYPT_SLH_DSA_H