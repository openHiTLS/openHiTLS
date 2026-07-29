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

#ifndef TRANSCRIPT_HASH_H
#define TRANSCRIPT_HASH_H

#include <stdint.h>
#include "hitls_crypt_type.h"
#include "hs_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t VERIFY_SetHashWithVersion(HITLS_Lib_Ctx *libCtx, const char *attrName, VerifyCtx *ctx,
    HITLS_HashAlgo hashAlgo, uint16_t version);

typedef enum {
    /* Hash the bytes exactly as supplied. */
    VERIFY_TRANSCRIPT_RAW,
    /* Hash a raw DTLS handshake message using the DTLS1.3 transcript form:
     * msg_type || length || message body. */
    VERIFY_TRANSCRIPT_DTLS13,
} VERIFY_TranscriptStyle;

int32_t VERIFY_UpdateTranscriptHash(HITLS_HASH_Ctx *hashCtx, const uint8_t *msg, uint32_t msgLen,
    VERIFY_TranscriptStyle style);

int32_t VERIFY_UpdateCachedTranscriptHash(HITLS_HASH_Ctx *hashCtx, const HsMsgCache *cache, uint16_t version,
    uint32_t skipLastCount);

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

int32_t VERIFY_AppendDtlsRaw(VerifyCtx *ctx, const uint8_t *data, uint32_t len, VERIFY_TranscriptStyle liveStyle);

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
