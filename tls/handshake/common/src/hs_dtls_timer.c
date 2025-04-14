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
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_uio.h"
#include "bsl_errno.h"
#include "sal_time.h"
#include "hitls.h"
#include "hitls_error.h"
#include "tls_config.h"
#include "hs_ctx.h"
#include "hs_dtls_timer.h"

#define DTLS_HS_2MSL_TIMEOUT_VALUE    240000000 /* 2 times the MSL(Maximum Segment Lifetime) time. Unit: us */
#define DTLS_HS_DEFAULT_TIMEOUT_VALUE 1000000
#define DTLS_HS_MAX_TIMEOUT_VALUE     60000000
#define DTLS_HS_MAX_TIMEOUT_NUM       12        /* Maximum Timeout Times */

static int32_t SetDtlsTimerDeadLine(TLS_Ctx *ctx, uint32_t timeoutValue)
{
    int32_t ret = BSL_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
    BSL_TIME curTime = {0};
    ret = (int32_t)BSL_SAL_SysTimeGet(&curTime);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_SYS_TIME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15774, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "BSL_SAL_SysTimeGet fail when start dtls timer.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MSG_HANDLE_SYS_TIME_FAIL;
    }

    ret = (int32_t)BSL_DateTimeAddUs(&hsCtx->deadline, &curTime, timeoutValue);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_SYS_TIME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15775, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "BSL_DateTimeAddUs fail when start dtls timer.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MSG_HANDLE_SYS_TIME_FAIL;
    }
    return HITLS_SUCCESS;
}

int32_t HS_Start2MslTimer(TLS_Ctx *ctx)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        return HITLS_SUCCESS;
    }

    uint32_t timeoutValue = DTLS_HS_2MSL_TIMEOUT_VALUE;
    if (ctx->config.tlsConfig.dtlsPostHsTimeoutVal != 0) {
        timeoutValue = ctx->config.tlsConfig.dtlsPostHsTimeoutVal;
    }

    int32_t ret = SetDtlsTimerDeadLine(ctx, timeoutValue);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    hsCtx->timeoutValue = timeoutValue;
    hsCtx->timeoutNum = 0;
    return HITLS_SUCCESS;
}

int32_t HS_StartTimer(TLS_Ctx *ctx)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        return HITLS_SUCCESS;
    }

    uint32_t timeoutValue = DTLS_HS_DEFAULT_TIMEOUT_VALUE;
    if (ctx->config.tlsConfig.dtlsTimerCb != NULL) {
        timeoutValue = ctx->config.tlsConfig.dtlsTimerCb(ctx, 0);
    }

    int32_t ret = SetDtlsTimerDeadLine(ctx, timeoutValue);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    hsCtx->timeoutValue = timeoutValue;
    hsCtx->timeoutNum = 0;
    return HITLS_SUCCESS;
}

int32_t HS_IsTimeout(TLS_Ctx *ctx, bool *isTimeout)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        *isTimeout = false;
        return HITLS_SUCCESS;
    }

    BSL_TIME curTime = {0};
    int32_t ret = (int32_t)BSL_SAL_SysTimeGet(&curTime);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_SYS_TIME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15776, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "BSL_SAL_SysTimeGet fail when judgment dtls timeout.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MSG_HANDLE_SYS_TIME_FAIL;
    }

    *isTimeout = false;
    /* When the server sends the hello verify request, the timer does not need to be started. In this case, the function
     * returns a failure. Therefore, the failure is not considered as timeout */
    ret = (int32_t)BSL_SAL_DateTimeCompareByUs(&curTime, &hsCtx->deadline);
    if (ret == BSL_TIME_DATE_AFTER) {
        *isTimeout = true;
    }

    return HITLS_SUCCESS;
}

int32_t HS_TimeoutProcess(TLS_Ctx *ctx)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        return HITLS_SUCCESS;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15777, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "dtls timeout, timeoutNum = %u, timeoutValue = %u(us).",
        hsCtx->timeoutNum, hsCtx->timeoutValue, 0, 0);

    uint32_t timeoutValue = hsCtx->timeoutValue;
    if (ctx->config.tlsConfig.dtlsTimerCb != NULL) {
        timeoutValue = ctx->config.tlsConfig.dtlsTimerCb(ctx, timeoutValue);
    } else {
        timeoutValue *= 2; /* 2 indicates that the timeout period for each retransmission is doubled. */
        if (timeoutValue > DTLS_HS_MAX_TIMEOUT_VALUE) {
            /* The maximum timeout duration of the timer is 60s */
            timeoutValue = DTLS_HS_MAX_TIMEOUT_VALUE;
        }
    }

    int32_t ret = SetDtlsTimerDeadLine(ctx, timeoutValue);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16827, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SetDtlsTimerDeadLine fail", 0, 0, 0, 0);
        return ret;
    }

    hsCtx->timeoutValue = timeoutValue;
    hsCtx->timeoutNum++;
    if (hsCtx->timeoutNum > DTLS_HS_MAX_TIMEOUT_NUM) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_DTLS_CONNECT_TIMEOUT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15778, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dtls connect timeout.", 0, 0, 0, 0);
        /* There is no need to send an alert to peer after multiple connection failures */
        return HITLS_MSG_HANDLE_DTLS_CONNECT_TIMEOUT;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */