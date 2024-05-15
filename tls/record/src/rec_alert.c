/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
    if (IS_DTLS_VERSION(ctx->config.tlsConfig.maxVersion)) {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    } else {
        ctx->method.sendAlert(ctx, level, description);
        return CovertRecordAlertToReturnValue(description);
    }
}
