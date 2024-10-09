/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hs_msg.h"

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
    /* If the sessionId length does not meet the requirement, return an error code */
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
    /* If the value of sessionId is 0, return HITLS_SUCCESS */
    if (idSize == 0u) {
        *usedLen = bufOffset;
        return HITLS_SUCCESS;
    }

    /* Copy the session ID */
    int32_t ret = memcpy_s(&buf[bufOffset], bufLen - bufOffset, id, idSize);
    if (ret != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15850, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "memcpy fail when pack session id.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    /* Update the offset length */
    bufOffset += idSize;

    *usedLen = bufOffset;
    return HITLS_SUCCESS;
}

/**
 * @brief Pack the message header.
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
        sequence, &buf[DTLS_HS_MSGSEQ_ADDR]); /** Two bytes starting from four bytes are the sn of the message */
    BSL_Uint24ToByte(
        0, &buf[DTLS_HS_FRAGMENT_OFFSET_ADDR]); /** The three bytes starting from 6 bytes are the fragment offset. */
    BSL_Uint24ToByte(
        length, &buf[DTLS_HS_FRAGMENT_LEN_ADDR]); /** Three bytes starting from 9 bytes are the fragment length. */
}
