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
#if defined(HITLS_TLS_PROTO_TLS13) && defined(HITLS_TLS_HOST_SERVER)
#include <stdint.h>
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "crypt.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_kx.h"
#include "hs_common.h"
#include "hs_msg.h"
#include "pack.h"
#include "send_process.h"


int32_t Tls13ServerSendEncryptedExtensionsProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    /* Obtain the client information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /* Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        /* The CCS message cannot be encrypted. Therefore, the sending key of the server must be activated after the CCS
         * message is sent */
        uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
        if (hashLen == 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17130, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "DigestSize fail", 0, 0, 0, 0);
            return HITLS_CRYPT_ERR_DIGEST;
        }
        ret = HS_SwitchTrafficKey(ctx, ctx->hsCtx->serverHsTrafficSecret, hashLen, true);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17131, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "SwitchTrafficKey fail", 0, 0, 0, 0);
            return ret;
        }

        ret = HS_PackMsg(ctx, ENCRYPTED_EXTENSIONS);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15875, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack tls1.3 encrypted extensions fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15876, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send tls1.3 encrypted extensions success.", 0, 0, 0, 0);

    if (ctx->hsCtx->kxCtx->pskInfo13.psk != NULL) {
        return HS_ChangeState(ctx, TRY_SEND_FINISH);
    }
#ifdef HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY
    /* The server sends a CertificateRequest message only when the VerifyPeer mode is enabled */
    if (ctx->config.tlsConfig.isSupportClientVerify
#ifdef HITLS_TLS_FEATURE_PHA
        && (ctx->phaState != PHA_EXTENSION || !ctx->config.tlsConfig.isSupportPostHandshakeAuth)
#endif /* HITLS_TLS_FEATURE_PHA */
        ) {
        return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_REQUEST);
    }
#endif /* HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY */
    return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE);
}
#endif /* HITLS_TLS_PROTO_TLS13 && HITLS_TLS_HOST_SERVER */