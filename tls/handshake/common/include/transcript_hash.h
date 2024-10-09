/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef TRANSCRIPT_HASH_H
#define TRANSCRIPT_HASH_H

#include <stdint.h>
#include "hitls_crypt_type.h"
#include "hs_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Set the hash algorithm
 *
 * @param   ctx [IN] verify context
 * @param   hashAlgo [IN] hash algorithm
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_CRYPT_ERR_DIGEST hash operation failed
 * @retval  HITLS_UNREGISTERED_CALLBACK The callback function is not registered.
 */
int32_t VERIFY_SetHash(VerifyCtx *ctx, HITLS_HashAlgo hashAlgo);

/**
 * @brief   Add handshake message data
 *
 * @param   ctx [IN] verify context
 * @param   data [IN] Handshake message data
 * @param   len [IN] Data length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_UNREGISTERED_CALLBACK The callback function is not registered.
 * @retval  HITLS_CRYPT_ERR_DIGEST hash operation failed
 * @retval  HITLS_MEMCPY_FAIL
 * @retval  HITLS_MEMALLOC_FAIL
 */
int32_t VERIFY_Append(VerifyCtx *ctx, const uint8_t *data, uint32_t len);

/**
 * @brief   Calculate the SessionHash
 *
 * @param   ctx [IN] verify context
 * @param   digest [OUT] digest data
 * @param   digestLen [IN/OUT] IN:maximum length of digest OUT:digest length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see SAL_CRYPT_DigestFinal
 */
int32_t VERIFY_CalcSessionHash(VerifyCtx *ctx, uint8_t *digest, uint32_t *digestLen);

/**
 * @brief   Release the message cache linked list
 *
 * @param   ctx [IN] verify context
 */
void VERIFY_FreeMsgCache(VerifyCtx *ctx);

#ifdef __cplusplus
}
#endif /* end __cplusplus */
#endif /* end TRANSCRIPT_HASH_H */
