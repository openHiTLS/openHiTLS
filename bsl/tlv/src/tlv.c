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

#include "hitls_build.h"
#ifdef HITLS_BSL_TLV

#include <stdint.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_bytes.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_binlog_id.h"
#include "tlv.h"

int32_t BSL_TLV_Pack(const BSL_Tlv *tlv, uint8_t *buffer, uint32_t bufLen, uint32_t *usedLen)
{
    uint8_t *curPos = buffer;
    if ((bufLen < TLV_HEADER_LENGTH) || (tlv->length > bufLen - TLV_HEADER_LENGTH)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05013, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TLV build error: bufLen = %u is not enough for tlv length = %u, tlv type = 0x%x.",
            bufLen, tlv->length, tlv->type, 0);
        BSL_ERR_PUSH_ERROR(BSL_TLV_ERR_BAD_PARAM);
        return BSL_TLV_ERR_BAD_PARAM;
    }

    /* Write the TLV type */
    BSL_Uint32ToByte(tlv->type, curPos);
    curPos += sizeof(uint32_t);
    /* Write the TLV length */
    BSL_Uint32ToByte(tlv->length, curPos);
    curPos += sizeof(uint32_t);
    /* Write TLV data */
    if (memcpy_s(curPos, bufLen - TLV_HEADER_LENGTH, tlv->value, tlv->length) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05014, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TLV build error: write tlv value fail, bufLen = %u, tlv length = %u, tlv type = 0x%x.",
            bufLen, tlv->length, tlv->type, 0);
        BSL_ERR_PUSH_ERROR(BSL_TLV_ERR_MEMCPY_FAIL);
        return BSL_TLV_ERR_MEMCPY_FAIL;
    }

    *usedLen = TLV_HEADER_LENGTH + tlv->length;
    return BSL_SUCCESS;
}

static int32_t TLV_ParseHeader(const uint8_t *data, uint32_t dataLen, uint32_t *type, uint32_t *length)
{
    const uint8_t *curPos = data;
    /* Parse the TLV type */
    uint32_t tlvType = BSL_ByteToUint32(curPos);
    curPos += sizeof(uint32_t);
    /* Parse the TLV length */
    uint32_t tlvLen = BSL_ByteToUint32(curPos);
    if (tlvLen > dataLen - TLV_HEADER_LENGTH) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05015, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Check TLV header error: dataLen = %u, tlv length = %u, tlv type = 0x%x.", dataLen, tlvLen, tlvType, 0);
        BSL_ERR_PUSH_ERROR(BSL_TLV_ERR_BAD_PARAM);
        return BSL_TLV_ERR_BAD_PARAM;
    }

    *type = tlvType;
    *length = tlvLen;
    return BSL_SUCCESS;
}

int32_t BSL_TLV_Parse(uint32_t wantType, const uint8_t *data, uint32_t dataLen, BSL_Tlv *tlv, uint32_t *readLen)
{
    int32_t ret;
    const uint8_t *curPos = data;
    uint32_t remainLen = dataLen;
    uint32_t type;
    uint32_t length;
    while (remainLen >= TLV_HEADER_LENGTH) {
        /* Parse the TLV type and length */
        ret = TLV_ParseHeader(curPos, remainLen, &type, &length);
        if (ret != BSL_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05016, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Parse TLV error: tlv header illegal.", 0, 0, 0, 0);
            return ret;
        }
        remainLen -= (TLV_HEADER_LENGTH + length);

        /* The TLV type matches the expected type */
        if (wantType == type) {
            /* Parse the TLV data */
            if (memcpy_s(tlv->value, tlv->length, curPos + TLV_HEADER_LENGTH, length) != EOK) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05017, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "Parse TLV error: write tlv value fail, bufLen = %u, tlv length = %u, tlv type = 0x%x.",
                    tlv->length, length, type, 0);
                BSL_ERR_PUSH_ERROR(BSL_TLV_ERR_MEMCPY_FAIL);
                return BSL_TLV_ERR_MEMCPY_FAIL;
            }
            tlv->type = type;
            tlv->length = length;
            *readLen = dataLen - remainLen;
            return BSL_SUCCESS;
        }
        /* The TLV type does not match the expected type. Continue to parse the next TLV. */
        curPos += (TLV_HEADER_LENGTH + length);
    }
    /* No matched TLV found */
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05018, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Parse TLV error: no want type(0x%x), dataLen = %u.", wantType, dataLen, 0, 0);
    BSL_ERR_PUSH_ERROR(BSL_TLV_ERR_NO_WANT_TYPE);
    return BSL_TLV_ERR_NO_WANT_TYPE;
}

int32_t BSL_TLV_FindValuePos(uint32_t wantType, const uint8_t *data, uint32_t dataLen,
    uint32_t *offset, uint32_t *length)
{
    int32_t ret;
    const uint8_t *curPos = data;
    uint32_t remainLen = dataLen;
    uint32_t type;
    while (remainLen > TLV_HEADER_LENGTH) {
        /* Parse the TLV type and length */
        ret = TLV_ParseHeader(curPos, remainLen, &type, length);
        if (ret != BSL_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05019, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Find TLV error: tlv header illegal.", 0, 0, 0, 0);
            return ret;
        }
        /* The TLV type matches the expected type */
        if (wantType == type) {
            *offset = dataLen - remainLen + TLV_HEADER_LENGTH;
            return BSL_SUCCESS;
        }
        /* The TLV type does not match the expected type. Continue to parse the next TLV. */
        curPos += (TLV_HEADER_LENGTH + *length);
        remainLen -= (TLV_HEADER_LENGTH + *length);
    }
    /* No matched TLV found */
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05020, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Find TLV error: no want type(0x%x), dataLen = %u.", wantType, dataLen, 0, 0);
    BSL_ERR_PUSH_ERROR(BSL_TLV_ERR_NO_WANT_TYPE);
    return BSL_TLV_ERR_NO_WANT_TYPE;
}
#endif /* HITLS_BSL_TLV */
