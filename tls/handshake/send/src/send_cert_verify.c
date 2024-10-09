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
#include "hs_verify.h"
#include "hs_common.h"
#include "pack.h"
#include "send_process.h"


static int32_t PackAndSendCertVerify(TLS_Ctx *ctx)
{
    int32_t ret;
    HS_Ctx *hsCtx = ctx->hsCtx;
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;

    /** determine whether to assemble a message */
    if (hsCtx->msgLen == 0) {
        HITLS_CERT_Key *privateKey = SAL_CERT_GetCurrentPrivateKey(mgrCtx, false);
        ret = VERIFY_CalcSignData(ctx, privateKey, ctx->negotiatedInfo.signScheme);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        /* assemble message */
        ret = HS_PackMsg(ctx, CERTIFICATE_VERIFY, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15833, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client pack certificate verify msg fail.", 0, 0, 0, 0);
            return ret;
        }
        /** after the signature is used up, the length is set to 0, and the signature is used by the finish */
        hsCtx->verifyCtx->verifyDataSize = 0;
    }

    return HS_SendMsg(ctx);
}

int32_t ClientSendCertVerifyProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    ret = PackAndSendCertVerify(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15834, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "client send certificate verify msg success.", 0, 0, 0, 0);

    /** update the state machine */
    return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
}

int32_t Tls13SendCertVerifyProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    ret = PackAndSendCertVerify(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15835, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send tls1.3 certificate verify msg success.", 0, 0, 0, 0);

    return HS_ChangeState(ctx, TRY_SEND_FINISH);
}
