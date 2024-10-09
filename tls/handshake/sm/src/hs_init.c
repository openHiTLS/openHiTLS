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

#include "bsl_sal.h"
#include "hitls_error.h"
#include "hitls_sni.h"
#include "bsl_err_internal.h"
#include "indicator.h"
#include "hs_reass.h"
#include "hs_common.h"
#include "hs_verify.h"
#include "hs_kx.h"
#include "hs.h"
#include "parse.h"

#define EXTRA_DATA_SIZE 128u

static int32_t UIO_Init(TLS_Ctx *ctx)
{
    if (ctx->bUio != NULL) {
        return HITLS_SUCCESS;
    }

    BSL_UIO *bUio = BSL_UIO_New(BSL_UIO_BufferMethod());
    if (bUio == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->bUio = bUio;
    int32_t ret = BSL_UIO_Append(bUio, ctx->uio);
    if (ret != BSL_SUCCESS) {
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

static int32_t HsInitChangeState(TLS_Ctx *ctx)
{
    if (ctx->isClient) {
        return HS_ChangeState(ctx, TRY_SEND_CLIENT_HELLO);
    }
    // the server sends a hello request first during renegotiation
    if (ctx->negotiatedInfo.isRenegotiation) {
        return HS_ChangeState(ctx, TRY_SEND_HELLO_REQUEST);
    }
    return HS_ChangeState(ctx, TRY_RECV_CLIENT_HELLO);
}

int32_t HS_Init(TLS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    // prevent multiple init in the ctx->hsCtx
    if (ctx->hsCtx != NULL) {
        return HITLS_SUCCESS;
    }
    HS_Ctx *hsCtx = (HS_Ctx *)BSL_SAL_Calloc(1u, sizeof(HS_Ctx));
    if (hsCtx == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->hsCtx = hsCtx;
    hsCtx->clientRandom = ctx->negotiatedInfo.clientRandom;
    hsCtx->serverRandom = ctx->negotiatedInfo.serverRandom;
    hsCtx->bufferLen = ctx->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13 ?
            REC_MAX_TLS13_ENCRYPTED_LEN : REC_MAX_PLAIN_LENGTH;
    hsCtx->msgBuf = BSL_SAL_Malloc(hsCtx->bufferLen);
    if (hsCtx->msgBuf == NULL) {
        goto exit;
    }
    if (VERIFY_Init(hsCtx) != HITLS_SUCCESS) {
        goto exit;
    }
    if (ctx->config.tlsConfig.isFlightTransmitEnable == true) {
        if (UIO_Init(ctx) != HITLS_SUCCESS) {
            goto exit;
        }
    }
    hsCtx->kxCtx = HS_KeyExchCtxNew();
    if (hsCtx->kxCtx == NULL) {
        goto exit;
    }
    hsCtx->firstClientHello = NULL;
#ifndef HITLS_NO_DTLS12
    hsCtx->reassMsg = HS_ReassNew();
    if (hsCtx->reassMsg == NULL) {
        goto exit;
    }
#endif
    INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_HANDSHAKE_START, INDICATE_VALUE_SUCCESS);
    return HsInitChangeState(ctx);
exit:
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

    BSL_SAL_FREE(hsCtx->msgBuf);
    BSL_SAL_FREE(hsCtx->sessionId);
    BSL_SAL_FREE(hsCtx->serverName);
    BSL_SAL_FREE(hsCtx->ticket);
    if (ctx->hsCtx->firstClientHello != NULL) {
        HS_Msg hsMsg = {0};
        hsMsg.type = CLIENT_HELLO;
        hsMsg.body.clientHello = *ctx->hsCtx->firstClientHello;
        HS_CleanMsg(&hsMsg);
        BSL_SAL_FREE(ctx->hsCtx->firstClientHello);
    }
	/* clear sensitive information */
    BSL_SAL_CleanseData(hsCtx->masterKey, MAX_DIGEST_SIZE);
    if (hsCtx->peerCert != NULL) {
        SAL_CERT_PairFree(ctx->config.tlsConfig.certMgrCtx, hsCtx->peerCert);
        hsCtx->peerCert = NULL;
    }

    VERIFY_Deinit(hsCtx);
    if (ctx->config.tlsConfig.isFlightTransmitEnable == true) {
        UIO_Deinit(ctx);
    }
    HS_KeyExchCtxFree(hsCtx->kxCtx);
#ifndef HITLS_NO_DTLS12
    HS_ReassFree(hsCtx->reassMsg);
#endif
    BSL_SAL_FREE(ctx->hsCtx);
    return;
}