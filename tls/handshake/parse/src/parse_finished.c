/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hs_msg.h"
#include "parse_msg.h"

int32_t ParseFinished(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    /* if the cache length is 0, return an error code */
    if (bufLen == 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15830, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse finished message failed, bufLen could not be zero.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    FinishedMsg *msg = &hsMsg->body.finished;

    /* get the data of verify */
    msg->verifyData = BSL_SAL_Malloc(bufLen);
    if (msg->verifyData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15831, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verifyData malloc fail when parse finished msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    if (memcpy_s(msg->verifyData, bufLen, buf, bufLen) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15832, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verifyData copy fail when parse finished msg.", 0, 0, 0, 0);
        BSL_SAL_FREE(msg->verifyData);
        return HITLS_MEMCPY_FAIL;
    }
    msg->verifyDataSize = bufLen;

    return HITLS_SUCCESS;
}

void CleanFinished(FinishedMsg *msg)
{
    if (msg != NULL) {
        BSL_SAL_FREE(msg->verifyData);
    }
    return;
}
