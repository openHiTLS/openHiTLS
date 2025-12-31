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
#include "rec.h"
#include "hs_ctx.h"
#include "hs_common.h"

int32_t ClientRecvServerHelloDoneProcess(TLS_Ctx *ctx)
{
    /** get client infomation */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    /* clear the retransmission queue */
    REC_RetransmitListClean(ctx->recCtx);
#endif

    /** Certificate messages are sent whenever a server certificate request is received,
        regardless of whether the client has a proper certificate. */
    if (hsCtx->isNeedClientCert) {
        return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE);
    }
    return HS_ChangeState(ctx, TRY_SEND_CLIENT_KEY_EXCHANGE);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_CLIENT */