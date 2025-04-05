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
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
#include <stdint.h>
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_msg.h"
#include "hs_kx.h"

int32_t ClientRecvServerKxProcess(TLS_Ctx *ctx, HS_Msg *msg)
{
    int32_t ret;
    /** get the client infomation */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    ServerKeyExchangeMsg *serverKxMsg = &msg->body.serverKeyExchange;
    (void)serverKxMsg;
#ifdef HITLS_TLS_FEATURE_PSK
    if (IsPskNegotiation(ctx)) {
        ret = HS_ProcessServerKxMsgIdentityHint(ctx, serverKxMsg);
        if (ret != HITLS_SUCCESS) {
            // log here
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_PSK */
    /* process key exchange message from the server */
    switch (hsCtx->kxCtx->keyExchAlgo) {
#ifdef HITLS_TLS_SUITE_KX_ECDHE
        case HITLS_KEY_EXCH_ECDHE: // include TLCP
        case HITLS_KEY_EXCH_ECDHE_PSK:
            ret = HS_ProcessServerKxMsgEcdhe(ctx, serverKxMsg);
            break;
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
            ret = HS_ProcessServerKxMsgDhe(ctx, serverKxMsg);
            break;
#endif /* HITLS_TLS_SUITE_KX_DHE */
        case HITLS_KEY_EXCH_PSK:
        case HITLS_KEY_EXCH_RSA_PSK:
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_KEY_EXCH_ECC: // signature is verified at parse time
#endif
            ret = HITLS_SUCCESS;
            break;
        default:
            ret = HITLS_MSG_HANDLE_UNSUPPORT_KX_ALG;
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            break;
    }
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15857, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client process server key exchange msg fail.", 0, 0, 0, 0);
        return ret;
    }

    /* update the state machine */
    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_REQUEST);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_CLIENT */