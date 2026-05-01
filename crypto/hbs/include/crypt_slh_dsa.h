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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct SlhDsaCtx CryptSlhDsaCtx;

/**
 * @ingroup slh_dsa
 * @brief Create a new SLH-DSA context.
 *
 * @retval CryptSlhDsaCtx* Pointer to the new SLH-DSA context
 * @retval NULL             Memory allocation failed
 */
CryptSlhDsaCtx *CRYPT_SLH_DSA_NewCtx(void);

/**
 * @ingroup slh_dsa
 * @brief Create a new SLH-DSA context.
 *
 * @param libCtx [IN] Pointer to the library context
 *
 * @retval CryptSlhDsaCtx* Pointer to the new SLH-DSA context
 * @retval NULL             Memory allocation failed
 */
CryptSlhDsaCtx *CRYPT_SLH_DSA_NewCtxEx(void *libCtx);

/**
 * @ingroup slh_dsa
 * @brief Free a SLH-DSA context.
 *
 * @param ctx [IN] Pointer to the SLH-DSA context
 */
void CRYPT_SLH_DSA_FreeCtx(CryptSlhDsaCtx *ctx);

CryptSlhDsaCtx *CRYPT_SLH_DSA_DupCtx(CryptSlhDsaCtx *ctx);

/**
 * @ingroup slh_dsa
 * @brief Generate a SLH-DSA key pair.
 *
 * @param ctx [IN/OUT] Pointer to the SLH-DSA context
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_Gen(CryptSlhDsaCtx *ctx);

/**
 * @ingroup slh_dsa
 * @brief Sign data using SLH-DSA.
 *
 * @param ctx     [IN] Pointer to the SLH-DSA context
 * @param algId   [IN] Algorithm ID
 * @param data    [IN] Pointer to the data to sign
 * @param dataLen [IN] Length of the data
 * @param sign    [OUT] Pointer to the signature
 * @param signLen [IN/OUT] Length of the signature
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_Sign(CryptSlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                           uint32_t *signLen);

/**
 * @ingroup slh_dsa
 * @brief Verify data using SLH-DSA.
 *
 * @param ctx     [IN] Pointer to the SLH-DSA context
 * @param algId   [IN] Algorithm ID
 * @param data    [IN] Pointer to the data to verify
 * @param dataLen [IN] Length of the data
 * @param sign    [IN] Pointer to the signature
 * @param signLen [IN] Length of the signature
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_Verify(const CryptSlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                             const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup slh_dsa
 * @brief Control function for SLH-DSA.
 *
 * @param ctx [IN/OUT] Pointer to the SLH-DSA context
 * @param opt [IN] Option
 * @param val [IN] Value
 * @param len [IN] Length of the value
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_Ctrl(CryptSlhDsaCtx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @ingroup slh_dsa
 * @brief Get the public key of SLH-DSA.
 *
 * @param ctx [IN] Pointer to the SLH-DSA context
 * @param pub [OUT] Pointer to the public key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_GetPubKey(const CryptSlhDsaCtx *ctx, CRYPT_SlhDsaPub *pub);

/**
 * @ingroup slh_dsa
 * @brief Get the private key of SLH-DSA.
 *
 * @param ctx [IN] Pointer to the SLH-DSA context
 * @param prv [OUT] Pointer to the private key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_GetPrvKey(const CryptSlhDsaCtx *ctx, CRYPT_SlhDsaPrv *prv);

/**
 * @ingroup slh_dsa
 * @brief Set the public key of SLH-DSA.
 *
 * @param ctx [IN/OUT] Pointer to the SLH-DSA context
 * @param pub [IN] Pointer to the public key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_SetPubKey(CryptSlhDsaCtx *ctx, const CRYPT_SlhDsaPub *pub);

/**
 * @ingroup slh_dsa
 * @brief Set the private key of SLH-DSA.
 *
 * @param ctx [IN/OUT] Pointer to the SLH-DSA context
 * @param prv [IN] Pointer to the private key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_SetPrvKey(CryptSlhDsaCtx *ctx, const CRYPT_SlhDsaPrv *prv);

/**
 * @ingroup slh_dsa
 * @brief Get the public key of SLH-DSA (BSL_Param variant).
 *
 * @param ctx  [IN] Pointer to the SLH-DSA context
 * @param para [OUT] Pointer to the public key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_GetPubKeyEx(const CryptSlhDsaCtx *ctx, BSL_Param *para);

/**
 * @ingroup slh_dsa
 * @brief Get the private key of SLH-DSA (BSL_Param variant).
 *
 * @param ctx  [IN] Pointer to the SLH-DSA context
 * @param para [OUT] Pointer to the private key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_GetPrvKeyEx(const CryptSlhDsaCtx *ctx, BSL_Param *para);

/**
 * @ingroup slh_dsa
 * @brief Set the public key of SLH-DSA (BSL_Param variant).
 *
 * @param ctx  [IN/OUT] Pointer to the SLH-DSA context
 * @param para [IN] Pointer to the public key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_SetPubKeyEx(CryptSlhDsaCtx *ctx, const BSL_Param *para);

/**
 * @ingroup slh_dsa
 * @brief Set the private key of SLH-DSA (BSL_Param variant).
 *
 * @param ctx  [IN/OUT] Pointer to the SLH-DSA context
 * @param para [IN] Pointer to the private key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_SetPrvKeyEx(CryptSlhDsaCtx *ctx, const BSL_Param *para);

#ifdef HITLS_CRYPTO_SLH_DSA_CHECK
/**
 * @ingroup slh_dsa
 * @brief Check the key pair of SLH-DSA.
 *
 * @param checkType [IN] Check type
 * @param pkey1     [IN] Pointer to the first SLH-DSA context
 * @param pkey2     [IN] Pointer to the second SLH-DSA context
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_SLH_DSA_Check(uint32_t checkType, const CryptSlhDsaCtx *pkey1, const CryptSlhDsaCtx *pkey2);
#endif /* HITLS_CRYPTO_SLH_DSA_CHECK */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_SLH_DSA */
#endif /* CRYPT_SLH_DSA_H */
