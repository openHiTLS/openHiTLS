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
#if defined(HITLS_TLS_HOST_SERVER) && defined(HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY)
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "pack.h"
#include "send_process.h"
#include "bsl_sal.h"
#ifdef HITLS_TLS_FEATURE_PHA
#define CERT_REQ_CTX_SIZE 32
#endif /* #ifdef HITLS_TLS_FEATURE_PHA */
static int32_t PackAndSendCertRequest(TLS_Ctx *ctx)
{
    /* get the server infomation */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /* determine whether to assemble a message */
    if (hsCtx->msgLen == 0) {
        /* assemble message */
        int32_t ret = HS_PackMsg(ctx, CERTIFICATE_REQUEST);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15836, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack certificate request msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    return HS_SendMsg(ctx);
}
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t ServerSendCertRequestProcess(TLS_Ctx *ctx)
{
    int32_t ret = PackAndSendCertRequest(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15837, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send certificate request msg success.", 0, 0, 0, 0);

    /* update the state machine */
    ctx->hsCtx->isNeedClientCert = true;
    ctx->negotiatedInfo.certReqSendTime++;
    return HS_ChangeState(ctx, TRY_SEND_SERVER_HELLO_DONE);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13ServerSendCertRequestProcess(TLS_Ctx *ctx)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PHA
    if (ctx->phaState == PHA_PENDING) {
        BSL_SAL_FREE(ctx->certificateReqCtx);
        ctx->certificateReqCtx = BSL_SAL_Calloc(CERT_REQ_CTX_SIZE, sizeof(uint8_t));
        if (ctx->certificateReqCtx == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15630, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "cert req ctx malloc fail.", 0, 0, 0, 0);
            return HITLS_MEMALLOC_FAIL;
        }
        ret = SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), ctx->certificateReqCtx, CERT_REQ_CTX_SIZE);
        if (ret != HITLS_SUCCESS) {
            BSL_SAL_FREE(ctx->certificateReqCtx);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15631, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "generate random cert req ctx fail.", 0, 0, 0, 0);
            return ret;
        }
        ctx->certificateReqCtxSize = CERT_REQ_CTX_SIZE;
    }
#endif /* HITLS_TLS_FEATURE_PHA */
    ret = PackAndSendCertRequest(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15838, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send tls1.3 certificate request msg success.", 0, 0, 0, 0);

    ctx->hsCtx->isNeedClientCert = true;
    ctx->negotiatedInfo.certReqSendTime++;
#ifdef HITLS_TLS_FEATURE_PHA
    if (ctx->phaState == PHA_PENDING) {
        ctx->phaState = PHA_REQUESTED;
        SAL_CRYPT_DigestFree(ctx->phaCurHash);
        ctx->phaCurHash = ctx->hsCtx->verifyCtx->hashCtx;
        ctx->hsCtx->verifyCtx->hashCtx = NULL;
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }
#endif /* HITLS_TLS_FEATURE_PHA */
    return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_SERVER && HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY */