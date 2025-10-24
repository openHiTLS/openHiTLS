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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hs_msg.h"
#include "parse_common.h"
#include "parse_extensions.h"
#include "parse_msg.h"

int32_t ParseHelloVerifyRequest(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    int32_t ret = HITLS_SUCCESS;
    HelloVerifyRequestMsg *msg = &hsMsg->body.helloVerifyReq;
    uint32_t bufOffset = 0;

    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &bufOffset};
    ret = ParseVersion(&pkt, &msg->version);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = ParseCookie(&pkt, &msg->cookieLen, &msg->cookie);
    if (ret != HITLS_SUCCESS) {
        CleanHelloVerifyRequest(msg);
        return ret;
    }

    // The cookie content is the last field of the helloVerifyRequest message. No other data should follow.
    if (bufLen != bufOffset) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID17335,
            BINGLOG_STR("hello verify request packet length error."), ALERT_DECODE_ERROR);
    }

    return HITLS_SUCCESS;
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