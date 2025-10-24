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
#include <stdint.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "pack_common.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"

int32_t PackCertificateVerify(const TLS_Ctx *ctx, PackPacket *pkt)
{
    const HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    int32_t ret = HITLS_SUCCESS;
    if (hsCtx->verifyCtx->verifyDataSize == 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15824, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the verify data is illegal.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

#if defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_DTLS12) || defined(HITLS_TLS_PROTO_TLS13)
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP_DTLCP11) {
        ret = PackAppendUint16ToBuf(pkt, (uint16_t)ctx->negotiatedInfo.signScheme);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif

    /* Pack signature data length */
    ret = PackAppendUint16ToBuf(pkt, (uint16_t)hsCtx->verifyCtx->verifyDataSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack signature data */
    return PackAppendDataToBuf(pkt, hsCtx->verifyCtx->verifyData, hsCtx->verifyCtx->verifyDataSize);
}
#endif /* HITLS_TLS_HOST_CLIENT || HITLS_TLS_PROTO_TLS13 */