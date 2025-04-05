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
#include "hitls_error.h"
#include "tls.h"

int32_t CovertRecordAlertToReturnValue(ALERT_Description description)
{
    switch (description) {
        case ALERT_PROTOCOL_VERSION:
            return HITLS_REC_INVALID_PROTOCOL_VERSION;
        case ALERT_BAD_RECORD_MAC:
            return HITLS_REC_BAD_RECORD_MAC;
        case ALERT_DECODE_ERROR:
            return HITLS_REC_DECODE_ERROR;
        case ALERT_RECORD_OVERFLOW:
            return HITLS_REC_RECORD_OVERFLOW;
        case ALERT_UNEXPECTED_MESSAGE:
            return HITLS_REC_ERR_RECV_UNEXPECTED_MSG;
        default:
            return HITLS_REC_INVLAID_RECORD;
    }
}

int32_t RecordSendAlertMsg(TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    /* RFC6347 4.1.2.7.  Handling Invalid Records:
       We choose to discard invalid dtls record message and do not generate alerts. */
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    } else {
        ctx->method.sendAlert(ctx, level, description);
        return CovertRecordAlertToReturnValue(description);
    }
}
