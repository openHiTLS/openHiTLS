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
#ifdef HITLS_TLS_FEATURE_QUIC_TLS
#include "bsl_err_internal.h"
#include "bsl_log_internal.h"
#include "bsl_sal.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "tls_binlog_id.h"
#include "tls.h"
#include "hs_ctx.h"
#include "quic_tls_internal.h"

/* ---- per-connection context lifetime ---- */

QUIC_TLS_Ctx *QUIC_TLS_CtxNew(void)
{
    QUIC_TLS_Ctx *quicTlsCtx = BSL_SAL_Calloc(1u, sizeof(QUIC_TLS_Ctx));
    if (quicTlsCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return NULL;
    }
    quicTlsCtx->readLevel = HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL;
    quicTlsCtx->writeLevel = HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL;
    return quicTlsCtx;
}

/* Clear transient QUIC state while retaining the active method for reuse after HITLS_Clear. */
void QUIC_TLS_CtxReset(QUIC_TLS_Ctx *quicTlsCtx)
{
    if (quicTlsCtx == NULL) {
        return;
    }
    for (uint32_t i = 0; i < QUIC_TLS_ENCRYPTION_LEVEL_COUNT; ++i) {
        BSL_SAL_FREE(quicTlsCtx->input[i].data);
    }
    BSL_SAL_CleanseData(quicTlsCtx->input, sizeof(quicTlsCtx->input));

    BSL_SAL_FREE(quicTlsCtx->localTransportParams);
    quicTlsCtx->localTransportParamsLen = 0;

    BSL_SAL_FREE(quicTlsCtx->peerTransportParams);
    quicTlsCtx->peerTransportParamsLen = 0;

    quicTlsCtx->readLevel = HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL;
    quicTlsCtx->writeLevel = HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL;
    BSL_SAL_CleanseData(quicTlsCtx->readSecretInstalled, sizeof(quicTlsCtx->readSecretInstalled));
    BSL_SAL_CleanseData(quicTlsCtx->writeSecretInstalled, sizeof(quicTlsCtx->writeSecretInstalled));

    quicTlsCtx->flightPending = false;
}

/* Release all resources owned by the QUIC context and then destroy the context itself. */
void QUIC_TLS_CtxFree(QUIC_TLS_Ctx *quicTlsCtx)
{
    if (quicTlsCtx == NULL) {
        return;
    }
    QUIC_TLS_CtxReset(quicTlsCtx);
    BSL_SAL_CleanseData(quicTlsCtx, sizeof(QUIC_TLS_Ctx));
    BSL_SAL_Free(quicTlsCtx);
}

bool QUIC_TLS_BufferHasData(const QUIC_TLS_Ctx *quicTlsCtx, HITLS_QUIC_TLS_EncryptionLevel level)
{
    if (quicTlsCtx == NULL || (uint32_t)level >= QUIC_TLS_ENCRYPTION_LEVEL_COUNT) {
        return false;
    }
    return quicTlsCtx->input[level].length != quicTlsCtx->input[level].offset;
}

/* ---- QUIC-mode helpers used by record / key-schedule / CM ---- */

bool QUIC_TLS_IsMode(const TLS_Ctx *ctx)
{
    /*
     * The context pointer itself is the mode flag: quicTlsCtx is allocated only by a
     * successful HITLS_QUIC_TLS_SetQuicTlsMethod and released only by HITLS_Free, and no
     * failure path can leave it allocated with the method uncommitted, so
     * quicTlsCtx != NULL is exactly "QUIC mode is active on this connection".
     */
    return ctx != NULL && ctx->quicTlsCtx != NULL;
}

int32_t QUIC_TLS_CallbackFailed(uint32_t callbackId, int32_t callbackRet)
{
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17415, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                          "QUIC callback %u failed with return value %d.", callbackId, callbackRet, 0, 0);
    BSL_ERR_PUSH_ERROR(HITLS_REC_CB_FAIL);
    return HITLS_REC_CB_FAIL;
}

/*
 * Map a TLS 1.3 traffic-secret buffer to the QUIC encryption level that uses it. HS_SwitchTrafficKey passes a
 * pointer to one of the canonical secret arrays owned by TLS_Ctx or HS_Ctx, so comparing buffer addresses identifies
 * the secret category without inspecting secret bytes. Initial secrets are derived by QUIC itself, and Early Data is
 * not supported by the current QUIC-TLS API, so only Handshake and Application levels are accepted here.
 */
static int32_t QuicTlsGetSecretLevel(TLS_Ctx *ctx, const uint8_t *secret, HITLS_QUIC_TLS_EncryptionLevel *level)
{
    /* Handshake traffic secrets are owned by the temporary handshake context and exist only while hsCtx is active. */
    if (ctx->hsCtx != NULL &&
        (secret == ctx->hsCtx->clientHsTrafficSecret || secret == ctx->hsCtx->serverHsTrafficSecret)) {
        *level = HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE;
        return HITLS_SUCCESS;
    }
    /* Application traffic secrets are stored directly in TLS_Ctx and remain available after the handshake ends. */
    if (secret == ctx->clientAppTrafficSecret || secret == ctx->serverAppTrafficSecret) {
        *level = HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION;
        return HITLS_SUCCESS;
    }
    /* Reject Early Data, exporter, resumption, copied, or otherwise non-canonical secret buffers. */
    BSL_ERR_PUSH_ERROR(HITLS_CONFIG_UNSUPPORT);
    return HITLS_CONFIG_UNSUPPORT;
}

int32_t QUIC_TLS_SetTrafficSecret(TLS_Ctx *ctx, const uint8_t *secret, uint32_t secretLen, bool isOut)
{
    if (!QUIC_TLS_IsMode(ctx) || secret == NULL || secretLen == 0) {
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }

    /* Identify the QUIC level from the canonical TLS traffic-secret buffer passed by HS_SwitchTrafficKey. */
    HITLS_QUIC_TLS_EncryptionLevel level;
    int32_t ret = QuicTlsGetSecretLevel(ctx, secret, &level);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    QUIC_TLS_Ctx *quicTlsCtx = ctx->quicTlsCtx;
    /* A read or write secret may be installed only once at each level during a QUIC-TLS handshake. */
    if ((isOut && quicTlsCtx->writeSecretInstalled[level]) || (!isOut && quicTlsCtx->readSecretInstalled[level])) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_STATE_ILLEGAL);
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }

    /* RFC 9001 s4.1.3: the peer must consume all CRYPTO data at the current level before advancing. */
    if (!isOut && level != quicTlsCtx->readLevel && QUIC_TLS_BufferHasData(quicTlsCtx, quicTlsCtx->readLevel)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17417, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "QUIC read-level switch from %u to %u with unconsumed data at old level.",
                              quicTlsCtx->readLevel, level, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_QUIC_TLS_PROTOCOL_VIOLATION);
        return HITLS_QUIC_TLS_PROTOCOL_VIOLATION;
    }
    const HITLS_Cipher *cipher = &ctx->negotiatedInfo.cipherSuiteInfo;
    if (isOut) {
        ret = quicTlsCtx->cbs.setWriteSecret((HITLS_Ctx *)ctx, level, cipher, secret, secretLen, quicTlsCtx->callbackArg);
    } else {
        ret = quicTlsCtx->cbs.setReadSecret((HITLS_Ctx *)ctx, level, cipher, secret, secretLen, quicTlsCtx->callbackArg);
    }
    if (ret != HITLS_SUCCESS) {
        return QUIC_TLS_CallbackFailed(
            isOut ? HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET : HITLS_QUIC_TLS_FUNC_SET_READ_SECRET, ret);
    }

    /* Commit the level transition only after the QUIC has accepted and installed the secret. */
    if (isOut) {
        quicTlsCtx->writeSecretInstalled[level] = true;
        quicTlsCtx->writeLevel = level;
    } else {
        quicTlsCtx->readSecretInstalled[level] = true;
        quicTlsCtx->readLevel = level;
    }
    return HITLS_SUCCESS;
}

bool QUIC_TLS_IsCipherSuiteSupported(const TLS_Ctx *ctx, uint16_t cipherSuite)
{
    if (!QUIC_TLS_IsMode(ctx)) {
        return true;
    }
    /*
     * RFC 9001 Section 5.3 whitelist: only TLS 1.3 suites with a defined QUIC
     * header-protection scheme are usable in QUIC mode: AES_128_GCM_SHA256,
     * AES_256_GCM_SHA384, CHACHA20_POLY1305_SHA256 and AES_128_CCM_SHA256.
     * Everything else (CCM_8, the RFC 8998 SM4 suites) is rejected in QUIC
     * mode.
     */
    switch (cipherSuite) {
        case HITLS_AES_128_GCM_SHA256:
        case HITLS_AES_256_GCM_SHA384:
        case HITLS_CHACHA20_POLY1305_SHA256:
        case HITLS_AES_128_CCM_SHA256:
            return true;
        default:
            return false;
    }
}

#endif /* HITLS_TLS_FEATURE_QUIC_TLS */
