/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

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
    /** Obtain the client information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {

        /* The CCS message cannot be encrypted. Therefore, the sending key of the server must be activated after the CCS
         * message is sent */
        uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
        if (hashLen == 0) {
            return HITLS_CRYPT_ERR_DIGEST;
        }
        ret = HS_SwitchTrafficKey(ctx, ctx->hsCtx->serverHsTrafficSecret, hashLen, true);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        ret = HS_PackMsg(ctx, ENCRYPTED_EXTENSIONS, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
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

    /* The server sends a CertificateRequest message only when the VerifyPeer mode is enabled */
    if (ctx->config.tlsConfig.isSupportClientVerify && ctx->phaState != PHA_EXTENSION) {
        /* VerifyOnce is used to control the CR sent only in the initial handshake phase. */
        /* certReqSendTime indicates the number of sent CRs. If the value of certReqSendTime is not zero in the
         * post-authentication phase, it indicates that the CRs have been sent */
        if (ctx->negotiatedInfo.certReqSendTime < 1 || !(ctx->config.tlsConfig.isSupportClientOnceVerify)) {
            return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_REQUEST);
        }
    }

    return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE);
}
