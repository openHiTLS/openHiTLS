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
#if defined(HITLS_TLS_HOST_SERVER) || defined(HITLS_TLS_PROTO_TLS13)
#include <stdint.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_verify.h"
#include "hs_common.h"
#include "hs_msg.h"
#include "recv_process.h"
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t ServerRecvClientCertVerifyProcess(TLS_Ctx *ctx)
{
    int32_t ret = VERIFY_CalcVerifyData(ctx, true, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15871, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server Calculate client finished data error.", 0, 0, 0, 0);
        (void)memset_s(ctx->hsCtx->masterKey, sizeof(ctx->hsCtx->masterKey), 0, sizeof(ctx->hsCtx->masterKey));
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);
    return HS_ChangeState(ctx, TRY_RECV_FINISH);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13RecvCertVerifyProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    if (ctx->hsCtx->readSubState == TLS_PROCESS_STATE_A) {
        /* The signature verification has been completed in the parser part.
        Only the finish data of the peer needs to be calculated. */
        ret = VERIFY_Tls13CalcVerifyData(ctx, !ctx->isClient);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15872, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "calculate finished data fail.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return ret;
        }
        ctx->hsCtx->readSubState = TLS_PROCESS_STATE_B;
    }

    if (ctx->hsCtx->readSubState == TLS_PROCESS_STATE_B) {
        if (ctx->isClient && ctx->hsCtx->isNeedClientCert) {
#ifdef HITLS_TLS_FEATURE_CERT_CB
            ret = ProcessCertCallback(ctx);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
#endif /* HITLS_TLS_FEATURE_CERT_CB */
            CERT_ExpectInfo expectCertInfo = {0};
            expectCertInfo.certType = CERT_TYPE_UNKNOWN;
            expectCertInfo.signSchemeList = ctx->peerInfo.signatureAlgorithms;
            expectCertInfo.signSchemeNum = ctx->peerInfo.signatureAlgorithmsSize;
            expectCertInfo.caList = ctx->peerInfo.caList;
            (void)SAL_CERT_SelectCertByInfo(ctx, &expectCertInfo);
        }
    }
    return HS_ChangeState(ctx, TRY_RECV_FINISH);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_SERVER || HITLS_TLS_PROTO_TLS13 */