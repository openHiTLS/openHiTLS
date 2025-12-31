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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hs_msg.h"
#include "parse_msg.h"
#include "parse_common.h"

int32_t ParseFinished(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    /* if the cache length is 0, return an error code */
    if (bufLen == 0u) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15830,
            BINGLOG_STR("parse 0 length finish"), ALERT_DECODE_ERROR);
    }

    FinishedMsg *msg = &hsMsg->body.finished;

    /* get the data of verify */
    BSL_SAL_FREE(msg->verifyData);
    msg->verifyData = BSL_SAL_Malloc(bufLen);
    if (msg->verifyData == NULL) {
        return ParseErrorProcess(ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15831,
            BINGLOG_STR("verifyData malloc fail"), ALERT_UNKNOWN);
    }
    (void)memcpy_s(msg->verifyData, bufLen, buf, bufLen);
    msg->verifyDataSize = bufLen;

    return HITLS_SUCCESS;
}

void CleanFinished(FinishedMsg *msg)
{
    if (msg != NULL) {
        BSL_SAL_FREE(msg->verifyData);
    }
}
