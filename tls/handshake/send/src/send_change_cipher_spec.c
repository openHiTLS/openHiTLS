/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

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
    int32_t ret;

    /** send message which changed cipher suites */
    ret = ctx->method.sendCCS(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /** enable key specification */
    ret = REC_ActivePendingState(ctx, true);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15873, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "active pending fail.", 0, 0, 0, 0);
        return ret;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15874, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send ccs msg success.", 0, 0, 0, 0);
    ctx->negotiatedInfo.isEncryptThenMacWrite = ctx->negotiatedInfo.isEncryptThenMac;
    /** update the state machine */
    return HS_ChangeState(ctx, TRY_SEND_FINISH);
}
