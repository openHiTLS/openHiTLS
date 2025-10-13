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
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "hitls_error.h"
#include "hitls_sni.h"
#include "bsl_err_internal.h"
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif /* HITLS_TLS_FEATURE_INDICATOR */
#include "hs_reass.h"
#include "hs_common.h"
#include "hs_verify.h"
#include "hs_kx.h"
#include "hs.h"
#include "parse.h"

#define DTLS_OVER_UDP_DEFAULT_SIZE 2048u
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
#define EXTRA_DATA_SIZE 128u
#endif
#ifdef HITLS_TLS_FEATURE_FLIGHT
static int32_t UIO_Init(TLS_Ctx *ctx)
{
    if (ctx->bUio != NULL) {
        return HITLS_SUCCESS;
    }
    int32_t ret = HITLS_SUCCESS;
    BSL_UIO *bUio = BSL_UIO_New(BSL_UIO_BufferMethod());
    if (bUio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17172, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN, "UIO_New fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    uint32_t bufferLen = (uint32_t)ctx->config.pmtu;
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) &&
        BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        ret = BSL_UIO_Ctrl(bUio, BSL_UIO_SET_BUFFER_SIZE, sizeof(uint32_t), &bufferLen);
        if (ret != BSL_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17173, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
                "SET_BUFFER_SIZE fail, ret %d", ret, 0, 0, 0);
            BSL_UIO_Free(bUio);
            BSL_ERR_PUSH_ERROR(HITLS_UIO_FAIL);
            return HITLS_UIO_FAIL;
        }
    }
#endif
    ctx->bUio = bUio;
    ret = BSL_UIO_Append(bUio, ctx->uio);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17174, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
            "UIO_Append fail, ret %d", ret, 0, 0, 0);
        BSL_UIO_Free(bUio);
        ctx->bUio = NULL;
        return ret;
    }

    ctx->uio = bUio;
    return HITLS_SUCCESS;
}

static int32_t UIO_Deinit(TLS_Ctx *ctx)
{
    if (ctx->bUio == NULL) {
        return HITLS_SUCCESS;
    }

    ctx->uio = BSL_UIO_PopCurrent(ctx->uio);
    BSL_UIO_FreeChain(ctx->bUio);
    ctx->bUio = NULL;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_FLIGHT */

static int32_t HsInitChangeState(TLS_Ctx *ctx)
{
    if (ctx->isClient) {
        return HS_ChangeState(ctx, TRY_SEND_CLIENT_HELLO);
    }
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    // the server sends a hello request first during renegotiation
    if (ctx->negotiatedInfo.isRenegotiation) {
        return HS_ChangeState(ctx, TRY_SEND_HELLO_REQUEST);
    }
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */
    return HS_ChangeState(ctx, TRY_RECV_CLIENT_HELLO);
}

int32_t NewHsCtxConfig(TLS_Ctx *ctx, HS_Ctx *hsCtx)
{
    (void)ctx;
    if (VERIFY_Init(hsCtx) != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17178, "VERIFY_Init fail");
    }
#ifdef HITLS_TLS_FEATURE_FLIGHT
    if (ctx->config.tlsConfig.isFlightTransmitEnable == true && UIO_Init(ctx) != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17179, "UIO_Init fail");
    }
#endif /* HITLS_TLS_FEATURE_FLIGHT */
    hsCtx->kxCtx = HS_KeyExchCtxNew();
    if (hsCtx->kxCtx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17180, "KeyExchCtxNew fail");
    }
#ifdef HITLS_TLS_PROTO_TLS13
    hsCtx->firstClientHello = NULL;
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_PROTO_DTLS12
    hsCtx->reassMsg = HS_ReassNew();
    if (hsCtx->reassMsg == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17181, "ReassNew fail");
    }
#endif
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_HANDSHAKE_START, INDICATE_VALUE_SUCCESS);
#endif /* HITLS_TLS_FEATURE_INDICATOR */
    return HITLS_SUCCESS;
}

int32_t HS_Init(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID17175, "ctx null");
    }
    // prevent multiple init in the ctx->hsCtx
    if (ctx->hsCtx != NULL) {
        return HITLS_SUCCESS;
    }
    HS_Ctx *hsCtx = (HS_Ctx *)BSL_SAL_Calloc(1u, sizeof(HS_Ctx));
    if (hsCtx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17176, "Calloc fail");
    }
    ctx->hsCtx = hsCtx;
    hsCtx->clientRandom = ctx->negotiatedInfo.clientRandom;
    hsCtx->serverRandom = ctx->negotiatedInfo.serverRandom;
    hsCtx->bufferLen = HITLS_HS_INIT_BUFFER_SIZE;
    hsCtx->msgBuf = BSL_SAL_Malloc(hsCtx->bufferLen);
    if (hsCtx->msgBuf == NULL) {
        (void)RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17177, "Malloc fail");
        goto ERR;
    }
    ret = NewHsCtxConfig(ctx, hsCtx);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    return HsInitChangeState(ctx);
ERR:
    HS_DeInit(ctx);
    BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
    return HITLS_MEMALLOC_FAIL;
}

void HS_DeInit(TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->hsCtx == NULL) {
        return;
    }
    HS_Ctx *hsCtx = ctx->hsCtx;
    HS_CleanMsg(ctx->hsCtx->hsMsg);
    BSL_SAL_FREE(ctx->hsCtx->hsMsg);
    BSL_SAL_FREE(hsCtx->msgBuf);
#if defined(HITLS_TLS_FEATURE_SESSION) || defined(HITLS_TLS_PROTO_TLS13)
    BSL_SAL_FREE(hsCtx->sessionId);
#endif /* HITLS_TLS_FEATURE_SESSION || HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    BSL_SAL_FREE(hsCtx->ticket);
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->hsCtx->firstClientHello != NULL) {
        HS_Msg hsMsg = {0};
        hsMsg.type = CLIENT_HELLO;
        hsMsg.body.clientHello = *ctx->hsCtx->firstClientHello;
        HS_CleanMsg(&hsMsg);
        BSL_SAL_FREE(ctx->hsCtx->firstClientHello);
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
	/* clear sensitive information */
    BSL_SAL_CleanseData(hsCtx->masterKey, MAX_DIGEST_SIZE);
    if (hsCtx->peerCert != NULL) {
        SAL_CERT_PairFree(ctx->config.tlsConfig.certMgrCtx, hsCtx->peerCert);
        hsCtx->peerCert = NULL;
    }

    VERIFY_Deinit(hsCtx);
#ifdef HITLS_TLS_FEATURE_FLIGHT
    if (ctx->config.tlsConfig.isFlightTransmitEnable == true) {
        UIO_Deinit(ctx);
    }
#endif /* HITLS_TLS_FEATURE_FLIGHT */
    HS_KeyExchCtxFree(hsCtx->kxCtx);
#ifdef HITLS_TLS_PROTO_DTLS12
    HS_ReassFree(hsCtx->reassMsg);
#endif
    BSL_SAL_FREE(ctx->hsCtx);
    return;
}