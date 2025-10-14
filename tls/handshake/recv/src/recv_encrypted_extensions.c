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
#ifdef HITLS_TLS_PROTO_TLS13
#ifdef HITLS_TLS_HOST_CLIENT
#include <stdint.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "record.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_extensions.h"
#include "hs_msg.h"
#include "hs_verify.h"
#include "alpn.h"


typedef int32_t (*CheckEncryptedExtFunc)(TLS_Ctx *ctx, const EncryptedExtensions *eEMsg);
#ifdef HITLS_TLS_FEATURE_SNI
static int32_t Tls13ClientCheckServerName(TLS_Ctx *ctx, const EncryptedExtensions *eEMsg)
{
    if ((ctx->hsCtx->extFlag.haveServerName == false) && (eEMsg->haveServerName == true)) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16200, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send server_name but get extended server_name .", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    /* Receive empty server_name extension */
    if ((ctx->hsCtx->extFlag.haveServerName == true) && (eEMsg->haveServerName == true)) {
        /* Not in session resumption and the client has previously sent the server_name extension */
        if (ctx->session == NULL && ctx->config.tlsConfig.serverName != NULL &&
            ctx->config.tlsConfig.serverNameSize > 0) {
            /* Indicates server negotiated the server_name extension in client successfully */
            ctx->negotiatedInfo.isSniStateOK = true;
            ctx->negotiatedInfo.serverNameSize = ctx->config.tlsConfig.serverNameSize;

            BSL_SAL_FREE(ctx->negotiatedInfo.serverName);
            ctx->negotiatedInfo.serverName =
                (uint8_t *)BSL_SAL_Dump(ctx->config.tlsConfig.serverName,
                    ctx->negotiatedInfo.serverNameSize * sizeof(uint8_t));
            if (ctx->negotiatedInfo.serverName == NULL) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17075, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "Dump fail", 0, 0, 0, 0);
                return HITLS_MEMCPY_FAIL;
            }
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SNI */

#ifdef HITLS_TLS_FEATURE_ALPN
static int32_t Tls13ClientCheckNegotiatedAlpn(TLS_Ctx *ctx, const EncryptedExtensions *eEMsg)
{
    return ClientCheckNegotiatedAlpn(
        ctx, eEMsg->haveSelectedAlpn, eEMsg->alpnSelected, eEMsg->alpnSelectedSize);
}
#endif

static int32_t ClientCheckEncryptedExtensionsFlag(TLS_Ctx *ctx, const EncryptedExtensions *eEMsg)
{
    static const CheckEncryptedExtFunc EXT_INFO_LIST[] = {
#ifdef HITLS_TLS_FEATURE_SNI
        Tls13ClientCheckServerName,
#endif /* HITLS_TLS_FEATURE_SNI */
#ifdef HITLS_TLS_FEATURE_ALPN
        Tls13ClientCheckNegotiatedAlpn,
#endif
        NULL,
    };

    int32_t ret = HS_CheckReceivedExtension(ctx, ENCRYPTED_EXTENSIONS, eEMsg->extensionTypeMask,
        HS_EX_TYPE_TLS1_3_ALLOWED_OF_ENCRYPTED_EXTENSIONS);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    for (uint32_t i = 0; i < sizeof(EXT_INFO_LIST) / sizeof(EXT_INFO_LIST[0]); i++) {
        if (EXT_INFO_LIST[i] == NULL) {
            continue;
        }
        ret = EXT_INFO_LIST[i](ctx, eEMsg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}

int32_t Tls13ClientRecvEncryptedExtensionsProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret;

    const EncryptedExtensions *eEMsg = &msg->body.encryptedExtensions;
    // Process the extension.
    ret = ClientCheckEncryptedExtensionsFlag(ctx, eEMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* In psk_only mode, the 'server verify data' needs to be calculated
     * for verifying the 'finished' message from the server. */
    PskInfo13 *pskInfo = &ctx->hsCtx->kxCtx->pskInfo13;
    if ((pskInfo->psk != NULL)) {
        ret = VERIFY_Tls13CalcVerifyData(ctx, false);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15856, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client calculate server finished data error.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return ret;
        }

        return HS_ChangeState(ctx, TRY_RECV_FINISH);
    }

    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_REQUEST);
}
#endif /* HITLS_TLS_HOST_CLIENT */
#endif /* HITLS_TLS_PROTO_TLS13 */