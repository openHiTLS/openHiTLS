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
#include "tls.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "pack.h"
#include "send_process.h"


int32_t ServerSendServerHelloDoneProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    /** get the server infomation */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** determine whether to assemble a message */
    if (hsCtx->msgLen == 0) {
        /* assemble message */
        ret = HS_PackMsg(ctx, SERVER_HELLO_DONE, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15879, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack server hello done msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    /** writing Handshake message */
    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15880, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send server hello done msg success.", 0, 0, 0, 0);

    /** update the state machine */
    if (hsCtx->isNeedClientCert) {
        return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
    }
    return HS_ChangeState(ctx, TRY_RECV_CLIENT_KEY_EXCHANGE);
}
