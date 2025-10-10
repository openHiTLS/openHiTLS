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
#if defined(HITLS_TLS_HOST_CLIENT) || defined(HITLS_TLS_PROTO_TLS13)
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

    /* determine whether to assemble a message */
    if (hsCtx->msgLen == 0) {
        HITLS_CERT_Key *privateKey = SAL_CERT_GetCurrentPrivateKey(mgrCtx, false);
        ret = VERIFY_CalcSignData(ctx, privateKey, ctx->negotiatedInfo.signScheme);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        /* assemble message */
        ret = HS_PackMsg(ctx, CERTIFICATE_VERIFY);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15833, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client pack certificate verify msg fail.", 0, 0, 0, 0);
            return ret;
        }
        /* after the signature is used up, the length is set to 0, and the signature is used by the finish */
        hsCtx->verifyCtx->verifyDataSize = 0;
    }

    return HS_SendMsg(ctx);
}
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t ClientSendCertVerifyProcess(TLS_Ctx *ctx)
{
    int32_t ret = PackAndSendCertVerify(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15834, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "client send certificate verify msg success.", 0, 0, 0, 0);

    /* update the state machine */
    return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13SendCertVerifyProcess(TLS_Ctx *ctx)
{
    int32_t ret = PackAndSendCertVerify(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15835, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send tls1.3 certificate verify msg success.", 0, 0, 0, 0);

    return HS_ChangeState(ctx, TRY_SEND_FINISH);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_CLIENT || HITLS_TLS_PROTO_TLS13 */