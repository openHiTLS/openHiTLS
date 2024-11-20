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
#include <stdint.h>
#include "hitls_build.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hs_msg.h"
#include "pack_common.h"

#ifdef HITLS_TLS_PROTO_DTLS12
/**
 * @brief Pack the packet header.
 *
 * @param type [IN] message type
 * @param sequence [IN] Sequence number (dedicated for DTLS)
 * @param length [IN] message body length
 * @param buf [OUT] message header
 */
void PackDtlsMsgHeader(HS_MsgType type, uint16_t sequence, uint32_t length, uint8_t *buf)
{
    buf[0] = (uint8_t)type & 0xffu;                               /** Type of the handshake message */
    BSL_Uint24ToByte(length, &buf[DTLS_HS_MSGLEN_ADDR]); /** Fills the length of the handshake message */
    BSL_Uint16ToByte(
        sequence, &buf[DTLS_HS_MSGSEQ_ADDR]); /** The 2 bytes starting from the 4th byte are the sn of the message */
    BSL_Uint24ToByte(
        0, &buf[DTLS_HS_FRAGMENT_OFFSET_ADDR]); /** The 3 bytes starting from the 6th byte are the fragment offset. */
    BSL_Uint24ToByte(
        length, &buf[DTLS_HS_FRAGMENT_LEN_ADDR]); /** The 3 bytes starting from the 9th byte are the fragment length. */
}
#endif /* HITLS_TLS_PROTO_DTLS12 */

#if defined(HITLS_TLS_FEATURE_SESSION_ID) || defined(HITLS_TLS_PROTO_TLS13)
/**
 * @brief Pack the message session ID.
 *
 * @param id [IN] Session ID
 * @param idSize [IN] Session ID length
 * @param buf [OUT] message buffer
 * @param bufLen [IN] Maximum message length
 * @param usedLen [OUT] Length of the packed message
 *
 * @retval HITLS_SUCCESS Assembly succeeded.
 * @retval HITLS_PACK_SESSIONID_ERR Failed to pack the sessionId.
 * @retval HITLS_MEMCPY_FAIL Memory Copy Failure
 */
int32_t PackSessionId(const uint8_t *id, uint32_t idSize, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    /* If the sessionId length does not meet the requirement, an error code is returned */
    if ((idSize != 0) && ((idSize > TLS_HS_MAX_SESSION_ID_SIZE) || (idSize < TLS_HS_MIN_SESSION_ID_SIZE))) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_SESSIONID_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15849, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "session id size is incorrect when pace session id.", 0, 0, 0, 0);
        return HITLS_PACK_SESSIONID_ERR;
    }

    uint32_t bufOffset = 0u;
    buf[bufOffset] = (uint8_t)idSize;

    /* Calculate the buffer offset length */
    bufOffset += sizeof(uint8_t);
    /* If the value of sessionId is 0, a success message is returned */
    if (idSize == 0u) {
        *usedLen = bufOffset;
        return HITLS_SUCCESS;
    }

    if ((bufLen - bufOffset) < idSize) {
        return PackBufLenError(BINLOG_ID15850, BINGLOG_STR("session id"));
    }
    /* Copy the session ID */
    (void)memcpy_s(&buf[bufOffset], bufLen - bufOffset, id, idSize);
    /* Update the offset length */
    bufOffset += idSize;

    *usedLen = bufOffset;
    return HITLS_SUCCESS;
}
#endif /* #if HITLS_TLS_FEATURE_SESSION_ID || HITLS_TLS_PROTO_TLS13 */

int32_t PackBufLenError(uint32_t logId, const void *format)
{
    BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
    if (format != NULL) {
        BSL_LOG_BINLOG_VARLEN(logId, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "buffer not enough when pack %s.",
            format);
    }
    return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
}