/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HS_VERIFY_H
#define HS_VERIFY_H

#include <stdint.h>
#include <stdbool.h>
#include "hitls_crypt_type.h"
#include "tls.h"
#include "hs_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Initialize the verify context
 * @attention If it has been initialized, the verify context will be reset
 *
 * @param   hsCtx [IN] Handshake context
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 */
int32_t VERIFY_Init(HS_Ctx *hsCtx);

/**
 * @brief   Release verify context
 *
 * @param   hsCtx [IN] Handshake context
 */
void VERIFY_Deinit(HS_Ctx *hsCtx);

/**
 * @brief   Calculate verify data
 *
 * @param   ctx [IN] tls Context
 * @param   isClient [IN] Indicates whether the context is client. If yes, the system calculates the verify data
 * sent by the client. Otherwise, the system calculates the verify data sent by the server.
 * @param   masterSecret [IN]
 * @param   masterSecretLen [IN]
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_UNREGISTERED_CALLBACK Callback unregistered
 * @retval  HITLS_CRYPT_ERR_DIGEST      Hash operation failed
 * @retval  HITLS_CRYPT_ERR_HMAC        HMAC operation failed
 * @retval  HITLS_MEMALLOC_FAIL         Memory allocation failed
 */
int32_t VERIFY_CalcVerifyData(TLS_Ctx *ctx, bool isClient, const uint8_t *masterSecret, uint32_t masterSecretLen);

/**
 * @brief   Calculate the client verify signature data
 *
 * @param   ctx [IN] TLS context. Different TLS and DTLS versions require different processing
 * @param   privateKey [IN] Certificate private key
 * @param   signScheme [IN] Signature hash algorithm
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PACK_SIGNATURE_ERR  Signing failed
 */
int32_t VERIFY_CalcSignData(TLS_Ctx *ctx, HITLS_CERT_Key *privateKey, HITLS_SignHashAlgo signScheme);

/**
 * @brief   Verify the client signature data
 *
 * @param   ctx [IN] TLS context. Different TLS and DTLS versions require different processing
 * @param   pubkey [IN] Public key of the device certificate
 * @param   signScheme [IN] Signature hash algorithm
 * @param   signData [IN] Signature
 * @param   signDataLen [IN] Signature length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PACK_SIGNATURE_ERR Signing failed
 */
int32_t VERIFY_VerifySignData(TLS_Ctx *ctx, HITLS_CERT_Key *pubkey, HITLS_SignHashAlgo signScheme,
                              const uint8_t *signData, uint16_t signDataLen);

/**
 * @brief   Set the verify data
 *
 * @param   ctx [IN] verify context
 * @param   verifyData [IN]
 * @param   verifyDataLen [IN]
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 */
int32_t VERIFY_SetVerifyData(VerifyCtx *ctx, const uint8_t *verifyData, uint32_t verifyDataLen);

/**
 * @brief   Obtain the verify data
 *
 * @param   ctx [IN] verify context
 * @param   verifyData [OUT]
 * @param   verifyDataLen [IN/OUT] IN: maximum length of data OUT:verify data Len
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 */
int32_t VERIFY_GetVerifyData(const VerifyCtx *ctx, uint8_t *verifyData, uint32_t *verifyDataLen);

/**
 * @brief   TLS1.3 calculate verify data
 *
 * @param   ctx [IN] TLS Context
 * @param   isClient [IN] Indicates whether the context is client. If yes, the system calculates the verify data
 * sent by the client. Otherwise, the system calculates the verify data sent by the server.
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_UNREGISTERED_CALLBACK     Callback unregistered
 * @retval  HITLS_CRYPT_ERR_DIGEST          Hash operation failed
 * @retval  HITLS_CRYPT_ERR_HMAC            HMAC operation failed
 * @retval  HITLS_MEMALLOC_FAIL             Memory allocation failed
 */
int32_t VERIFY_Tls13CalcVerifyData(TLS_Ctx *ctx, bool isClient);

/**
 * @brief    Reprocess the verify data for the hello retry request message
 *
 * @param   ctx [IN] TLS Context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t VERIFY_HelloRetryRequestVerifyProcess(TLS_Ctx *ctx);

int32_t VERIFY_CalcPskBinder(const TLS_Ctx *ctx, HITLS_HashAlgo hashAlgo, bool isExternalPsk, uint8_t *psk,
    uint32_t pskLen, const uint8_t *msg, uint32_t msgLen, uint8_t *binder, uint32_t binderLen);

#ifdef __cplusplus
}
#endif /* end __cplusplus */
#endif /* end HS_VERIFY_H */
