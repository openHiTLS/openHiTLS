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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "rec.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "send_process.h"


int32_t SendChangeCipherSpecProcess(TLS_Ctx *ctx)
{
    /* send message which changed cipher suites */
    int32_t ret = ctx->method.sendCCS(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* enable key specification */
    ret = REC_ActivePendingState(ctx, true);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15873, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "active pending fail.", 0, 0, 0, 0);
        return ret;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15874, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send ccs msg success.", 0, 0, 0, 0);
    ctx->negotiatedInfo.isEncryptThenMacWrite = ctx->negotiatedInfo.isEncryptThenMac;
    /* update the state machine */
    return HS_ChangeState(ctx, TRY_SEND_FINISH);
}
