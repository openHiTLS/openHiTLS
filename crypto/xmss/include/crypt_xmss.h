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

#ifndef CRYPT_XMSS_H
#define CRYPT_XMSS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XMSS

#include <stdint.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct SlhDsaCtx CryptXmssCtx;
typedef struct HashFuncs XmssHashFuncs;
typedef union Adrs XmssAdrs;

/**
 * @brief Allocate XMSS context memory space.
 *
 * @retval (CryptXmssCtx *) Pointer to the memory space of the allocated context
 * @retval NULL             Invalid null pointer.
 */
CryptXmssCtx *CRYPT_XMSS_NewCtx(void); // create key structure

/**
 * @brief Allocate XMSS context memory space.
 * 
 * @param libCtx [IN] Library context
 *
 * @retval (CryptXmssCtx *) Pointer to the memory space of the allocated context
 * @retval NULL             Invalid null pointer.
 */
CryptXmssCtx *CRYPT_XMSS_NewCtxEx(void *libCtx);

/**
 * @brief release XMSS key context structure
 *
 * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_XMSS_FreeCtx(CryptXmssCtx *ctx);

/**
 * @brief Generate the XMSS key pair.
 *
 * @param ctx [IN/OUT] XMSS context structure
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_SUCCESS            The key pair is successfully generated.
 */
int32_t CRYPT_XMSS_Gen(CryptXmssCtx *ctx);

/**
 * @brief Sign data using XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param algId Algorithm ID
 * @param data Pointer to the data to sign
 * @param dataLen Length of the data
 * @param sign Pointer to the signature
 * @param signLen Length of the signature
 */
int32_t CRYPT_XMSS_Sign(CryptXmssCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                        uint32_t *signLen);

/**
 * @brief Verify data using XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param algId Algorithm ID
 * @param data Pointer to the data to verify
 * @param dataLen Length of the data
 * @param sign Pointer to the signature
 * @param signLen Length of the signature
 */
int32_t CRYPT_XMSS_Verify(const CryptXmssCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                          const uint8_t *sign, uint32_t signLen);

/**
 * @brief Control function for XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param opt Option
 * @param val Value
 * @param len Length of the value
 */
int32_t CRYPT_XMSS_Ctrl(CryptXmssCtx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @brief Get the public key of XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param para Pointer to the public key
 */
int32_t CRYPT_XMSS_GetPubKey(const CryptXmssCtx *ctx, BSL_Param *para);

/**
 * @brief Get the private key of XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param para Pointer to the private key
 */
int32_t CRYPT_XMSS_GetPrvKey(const CryptXmssCtx *ctx, BSL_Param *para);

/**
 * @brief Set the public key of XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param para Pointer to the public key
 */
int32_t CRYPT_XMSS_SetPubKey(CryptXmssCtx *ctx, const BSL_Param *para);

/**
 * @brief Set the private key of XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param para Pointer to the private key
 */
int32_t CRYPT_XMSS_SetPrvKey(CryptXmssCtx *ctx, const BSL_Param *para);

CryptXmssCtx *CRYPT_XMSS_DupCtx(CryptXmssCtx *ctx);

#ifdef HITLS_CRYPTO_XMSS_CHECK

/**
 * @ingroup xmss
 * @brief check the key pair consistency
 *
 * @param checkType [IN] check type
 * @param pkey1 [IN] xmss key context structure
 * @param pkey2 [IN] xmss key context structure
 *
 * @retval CRYPT_SUCCESS    check success.
 * Others. For details, see error code in errno.
 */
int32_t CRYPT_XMSS_Check(uint32_t checkType, const CryptXmssCtx *pkey1, const CryptXmssCtx *pkey2);

#endif // HITLS_CRYPTO_XMSS_CHECK

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_XMSS

#endif // CRYPT_XMSS_H
