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
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_verify.h"
#include "hs_common.h"
#include "pack.h"
#include "send_process.h"


int32_t ServerSendHelloRequestProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    /* get the server infomation */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /* determine whether to assemble a message */
    if (hsCtx->msgLen == 0) {
        /* assemble message */
        ret = HS_PackMsg(ctx, HELLO_REQUEST, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15906, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack hello request msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    /* writing handshake message */
    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* hash calculation is not required for HelloRequest messages */
    ret = VERIFY_Init(hsCtx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17150, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "VERIFY_Init fail", 0, 0, 0, 0);
        return ret;
    }

    /* The server does not enter the renegotiation state when sending a HelloRequest message.
       The server enters the renegotiation state only when receiving a ClientHello message. */
    ctx->negotiatedInfo.isRenegotiation = false;

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15907, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send hello request msg success.", 0, 0, 0, 0);

    return HS_ChangeState(ctx, TRY_RECV_CLIENT_HELLO);
}
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */