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
#if defined(HITLS_TLS_HOST_SERVER) && defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)

#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "rec.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_verify.h"
#include "pack.h"
#include "send_process.h"

int32_t DtlsServerSendHelloVerifyRequestProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    HS_Ctx *hsCtx = ctx->hsCtx;

    /* determine whether to assemble a message */
    if (hsCtx->msgLen == 0) {
        ret = HS_PackMsg(ctx, HELLO_VERIFY_REQUEST);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17333, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack hello verify request msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* If HelloVerifyRequest is used, the initial ClientHello and
       HelloVerifyRequest are not included in the calculation of the
       handshake_messages (for the CertificateVerify message) and
       verify_data (for the Finished message). */
    ret = VERIFY_Init(hsCtx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17152, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "VERIFY_Init fail", 0, 0, 0, 0);
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17334, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send hello verify request msg success.", 0, 0, 0, 0);
    /* The reason for clearing the retransmission queue is that
       the HelloVerifyRequest message does not need to be retransmitted. */
    REC_RetransmitListClean(ctx->recCtx);
    return HS_ChangeState(ctx, TRY_RECV_CLIENT_HELLO);
}
#endif /* defined(HITLS_TLS_HOST_SERVER) && defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP) */