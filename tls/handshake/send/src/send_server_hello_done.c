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
#ifdef HITLS_TLS_HOST_SERVER
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_dtls_timer.h"
#include "pack.h"
#include "send_process.h"

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t ServerSendServerHelloDoneProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    /* get the server infomation */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /* determine whether to assemble a message */
    if (hsCtx->msgLen == 0) {
        /* assemble message */
        ret = HS_PackMsg(ctx, SERVER_HELLO_DONE);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15879, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack server hello done msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    /* writing Handshake message */
    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15880, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send server hello done msg success.", 0, 0, 0, 0);

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    ret = HS_StartTimer(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */

    /* update the state machine */
    if (hsCtx->isNeedClientCert) {
        return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
    }
    return HS_ChangeState(ctx, TRY_RECV_CLIENT_KEY_EXCHANGE);
}
#endif /* #if HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_SERVER */