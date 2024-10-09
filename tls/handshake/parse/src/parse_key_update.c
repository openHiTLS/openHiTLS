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

#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_msg.h"

int32_t ParseKeyUpdate(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    uint32_t bufOffset = 0u;

    /* if the cache length is not 1, return an error code */
    if (bufLen != 1u) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15868, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse keyUpdate message failed, bufLen should be one ,but actually is %d.", bufLen, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    KeyUpdateMsg *msg = &hsMsg->body.keyUpdate;
    msg->requestUpdate = buf[bufOffset];

    return HITLS_SUCCESS;
}
