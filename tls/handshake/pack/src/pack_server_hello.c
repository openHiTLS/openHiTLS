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
#ifdef HITLS_TLS_HOST_SERVER
#include <stdint.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_security.h"
#include "tls.h"
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif
#include "hs_ctx.h"
#include "pack_common.h"
#include "pack_extensions.h"

// Pack the mandatory content of the ServerHello message
static int32_t PackServerHelloMandatoryField(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t negotiatedVersion = ctx->negotiatedInfo.version;

    uint16_t version =
#ifdef HITLS_TLS_PROTO_TLS13
    (negotiatedVersion == HITLS_VERSION_TLS13) ? HITLS_VERSION_TLS12 :
#endif
        negotiatedVersion;
    ret = PackHelloCommonField(ctx, pkt, version, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = PackAppendUint16ToBuf(pkt, ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite); // cipher suite
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = PackAppendUint8ToBuf(pkt, 0); // Compression method, currently supports uncompression
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

// Pack the ServertHello message.
int32_t PackServerHello(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = PackServerHelloMandatoryField(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15863, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack server hello mandatory content fail.", 0, 0, 0, 0);
        return ret;
    }

    ret = PackServerExtension(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15864, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack server hello extension content fail.", 0, 0, 0, 0);
        return ret;
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_SERVER */