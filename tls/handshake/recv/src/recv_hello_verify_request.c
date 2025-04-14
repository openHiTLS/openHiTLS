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
#ifdef HITLS_TLS_HOST_CLIENT
#ifdef HITLS_TLS_PROTO_DTLS12
#include "securec.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "tls_binlog_id.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "rec.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_common.h"

int32_t DtlsClientRecvHelloVerifyRequestProcess(TLS_Ctx *ctx, HS_Msg *msg)
{
    TLS_NegotiatedInfo *negotiatedInfo = &ctx->negotiatedInfo;
    HelloVerifyRequestMsg *helloVerifyReq = &msg->body.helloVerifyReq;

    /* release the old cookie first */
    BSL_SAL_FREE(negotiatedInfo->cookie);

    /* allow zero-length cookies to be received */
    if (helloVerifyReq->cookieLen != 0) {
        negotiatedInfo->cookie = (uint8_t *)BSL_SAL_Dump(helloVerifyReq->cookie, helloVerifyReq->cookieLen);
        if (negotiatedInfo->cookie == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16080, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "cookie malloc fail when process hello verify request.", 0, 0, 0, 0);
            return HITLS_MEMALLOC_FAIL;
        }
    }
    negotiatedInfo->cookieSize = helloVerifyReq->cookieLen;
#ifdef HITLS_BSL_UIO_UDP
    /* clear the retransmission queue */
    REC_RetransmitListClean(ctx->recCtx);
#endif /* HITLS_BSL_UIO_UDP */
    return HS_ChangeState(ctx, TRY_SEND_CLIENT_HELLO);
}
#endif /* HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_CLIENT */