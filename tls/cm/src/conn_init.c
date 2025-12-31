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

#include <stdbool.h>
#include "hitls_build.h"
#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "hitls_type.h"
#include "rec.h"
#include "hs.h"
#include "app.h"
#include "alert.h"
#include "change_cipher_spec.h"
#include "conn_common.h"
#include "hs_ctx.h"
// an instance of unexpectedMsgProcessCb
int32_t ConnUnexpectedMsg(HITLS_Ctx *ctx, uint32_t msgType, const uint8_t *data, uint32_t dataLen, bool isPlain)
{
    (void)isPlain;
    if (ctx == NULL || data == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16509, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    ALERT_ClearWarnCount(ctx, msgType);
    int32_t ret = HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
#ifdef HITLS_TLS_PROTO_TLS13
    if (isPlain) { // tls13
        if (msgType == REC_TYPE_CHANGE_CIPHER_SPEC) {
            return ProcessPlainCCS(ctx, data, dataLen);
        }
        return ProcessPlainAlert(ctx, data, dataLen);
    }
#endif
    switch (msgType) {
        case REC_TYPE_CHANGE_CIPHER_SPEC:
            return ProcessDecryptedCCS(ctx, data, dataLen);
        case REC_TYPE_ALERT:
            return ProcessDecryptedAlert(ctx, data, dataLen);
        default:
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16512, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "unknown msgType", 0, 0, 0, 0);
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
            break;
    }
    return ret;
}

int32_t CONN_Init(TLS_Ctx *ctx)
{
    int32_t ret = REC_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = ALERT_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = CCS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ctx->method.isRecvCCS = CCS_IsRecv;
    ctx->method.sendCCS = CCS_Send;
    ctx->method.ctrlCCS = CCS_Ctrl;
    ctx->method.sendAlert = ALERT_Send;
    ctx->method.clearAlert = ALERT_ClearWarnCount;
    ctx->method.getAlertFlag = ALERT_GetFlag;
    ctx->method.unexpectedMsgProcessCb = ConnUnexpectedMsg;
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
    ctx->keyUpdateType = HITLS_KEY_UPDATE_REQ_END;
    ctx->isKeyUpdateRequest = false;
#endif
    // default value is X509_V_OK(0)
    ctx->peerInfo.verifyResult = 0;
#ifdef HITLS_TLS_CONFIG_STATE
    ctx->rwstate = HITLS_NOTHING;
#endif
    return HITLS_SUCCESS;
}

void CONN_Deinit(TLS_Ctx *ctx)
{
    REC_DeInit(ctx);
    ALERT_Deinit(ctx);
    CCS_DeInit(ctx);
    HS_DeInit(ctx);
}