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
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_TLS_HOST_CLIENT)
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "parse_common.h"

int32_t ParseHelloVerifyRequest(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg)
{
    HelloVerifyRequestMsg *msg = &hsMsg->body.helloVerifyReq;
    uint32_t bufOffset = 0;
    ParsePacket pkt = {.ctx = ctx, .buf = data, .bufLen = len, .bufOffset = &bufOffset};

    int32_t ret = ParseVersion(&pkt, &msg->version);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return ParseCookie(&pkt, &msg->cookieLen, &msg->cookie);
    /**
     * There is no judgment as to whether the length of the parsed field is the same as the total length of the message
     * The parsing of the message may result in a situation where the main field has been parsed and there are remaining
     * bytes, no corresponding protocol support has been found, and whether an alert should be sent,
     * Therefore, the following bytes may be ignored. If you find the corresponding protocol description, modify it
     */
}

void CleanHelloVerifyRequest(HelloVerifyRequestMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    BSL_SAL_FREE(msg->cookie);
    return;
}
#endif /* HITLS_TLS_HOST_CLIENT */