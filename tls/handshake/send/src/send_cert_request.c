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
#include "hs_msg.h"
#include "hs_common.h"
#include "pack.h"
#include "send_process.h"
#include "bsl_sal.h"

#define CERT_REQ_CTX_SIZE 32

static int32_t PackAndSendCertRequest(TLS_Ctx *ctx)
{
    int32_t ret;
    /** get the server infomation */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** determine whether to assemble a message */
    if (hsCtx->msgLen == 0) {
        /* assemble message */
        ret = HS_PackMsg(ctx, CERTIFICATE_REQUEST, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15836, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack certificate request msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

int32_t ServerSendCertRequestProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    ret = PackAndSendCertRequest(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15837, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send certificate request msg success.", 0, 0, 0, 0);

    /** update the state machine */
    ctx->hsCtx->isNeedClientCert = true;
    ctx->negotiatedInfo.certReqSendTime++;
    return HS_ChangeState(ctx, TRY_SEND_SERVER_HELLO_DONE);
}

int32_t Tls13ServerSendCertRequestProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    if (ctx->phaState == PHA_PENDING) {
        BSL_SAL_FREE(ctx->certificateReqCtx);
        ctx->certificateReqCtx = BSL_SAL_Calloc(CERT_REQ_CTX_SIZE, sizeof(uint8_t));
        if (ctx->certificateReqCtx == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15774, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "cert req ctx malloc fail.", 0, 0, 0, 0);
            return HITLS_MEMALLOC_FAIL;
        }
        ret = SAL_CRYPT_Rand(ctx->certificateReqCtx, CERT_REQ_CTX_SIZE);
        if (ret != HITLS_SUCCESS) {
            BSL_SAL_FREE(ctx->certificateReqCtx);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15775, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "generate random cert req ctx fail.", 0, 0, 0, 0);
            return ret;
        }
        ctx->certificateReqCtxSize = CERT_REQ_CTX_SIZE;
    }
    ret = PackAndSendCertRequest(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15838, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send tls1.3 certificate request msg success.", 0, 0, 0, 0);

    ctx->hsCtx->isNeedClientCert = true;
    ctx->negotiatedInfo.certReqSendTime++;
    if (ctx->phaState == PHA_PENDING) {
        ctx->phaState = PHA_REQUESTED;
        SAL_CRYPT_DigestFree(ctx->phaCurHash);
        ctx->phaCurHash = ctx->hsCtx->verifyCtx->hashCtx;
        ctx->hsCtx->verifyCtx->hashCtx = NULL;
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }
    return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE);
}
