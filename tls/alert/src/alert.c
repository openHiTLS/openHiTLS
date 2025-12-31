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
#include "securec.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "rec.h"
#ifdef HITLS_TLS_FEATURE_FLIGHT
#include "bsl_uio.h"
#include "hitls.h"
#endif
#include "record.h"
#include "alert.h"

#define ALERT_DATA_LEN 2u   /* alert data length */

/** Alert context, which records the sending and receiving information */
struct AlertCtx {
    uint8_t flag;           /* send and receive flags, for details, see ALERT_FLAG */
    bool isFlush;           /* whether the message is sent successfully */
    uint8_t warnCount;      /* count the number of consecutive received warnings */
    uint8_t level;          /* Alert level. For details, see ALERT_Level */
    uint8_t description;    /* Alert description: For details, see ALERT_Description */
    uint8_t reverse;        /* reserve, 4-byte aligned */
};

bool ALERT_GetFlag(const TLS_Ctx *ctx)
{
    return (ctx->alertCtx->flag != ALERT_FLAG_NO);
}

void ALERT_GetInfo(const TLS_Ctx *ctx, ALERT_Info *info)
{
    struct AlertCtx *alertCtx = ctx->alertCtx;
    info->flag = alertCtx->flag;
    info->level = alertCtx->level;
    info->description = alertCtx->description;
}

void ALERT_CleanInfo(const TLS_Ctx *ctx)
{
    uint8_t alertCount = ctx->alertCtx->warnCount;
    (void)memset_s(ctx->alertCtx, sizeof(struct AlertCtx), 0, sizeof(struct AlertCtx));
    ctx->alertCtx->warnCount = alertCount;
}

/* check whether the operation is abnormal */
bool AlertIsAbnormalInput(const struct AlertCtx *alertCtx, ALERT_Level level)
{
    if (level != ALERT_LEVEL_FATAL && level != ALERT_LEVEL_WARNING) {
        return true;
    }
    if (alertCtx->flag != ALERT_FLAG_NO) {
        // a critical alert exists and cannot be overwritten
        if (alertCtx->level == ALERT_LEVEL_FATAL) {
            return true;
        }
        // common alarms are not allowed to overwrite CLOSE NOTIFY
        if (level == ALERT_LEVEL_WARNING &&
            alertCtx->level == ALERT_LEVEL_WARNING &&
            alertCtx->description == ALERT_CLOSE_NOTIFY) {
            return true;
        }
    }
    return false;
}

void ALERT_Send(const TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    struct AlertCtx *alertCtx = ctx->alertCtx;
    // prevent abnormal operations
    if (AlertIsAbnormalInput(alertCtx, level)) {
        return;
    }
    alertCtx->level = (uint8_t)level;
    alertCtx->description = (uint8_t)description;
    alertCtx->flag = ALERT_FLAG_SEND;
    alertCtx->isFlush = false;
}

int32_t ALERT_Flush(TLS_Ctx *ctx)
{
    struct AlertCtx *alertCtx = ctx->alertCtx;
    int32_t ret;
    if (alertCtx->flag != ALERT_FLAG_SEND) {
        BSL_ERR_PUSH_ERROR(HITLS_ALERT_NO_WANT_SEND);
        return HITLS_ALERT_NO_WANT_SEND;
    }
#ifdef HITLS_TLS_PROTO_TLS
    if (REC_GetOutBufPendingSize(ctx) != 0) {
        ret = REC_OutBufFlush(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif
    if (alertCtx->isFlush == false) {
        if (ctx->recCtx != NULL && ctx->recCtx->pendingData != NULL && alertCtx->description == ALERT_CLOSE_NOTIFY) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        uint8_t data[ALERT_DATA_LEN];
        /** obtain the alert level */
        data[0] = alertCtx->level;
        data[1] = alertCtx->description;
        if (ctx->negotiatedInfo.version == HITLS_VERSION_SSL30 && alertCtx->description == ALERT_PROTOCOL_VERSION) {
            data[1] = ALERT_HANDSHAKE_FAILURE;
        }
        /** write the record */
        ret = REC_Write(ctx, REC_TYPE_ALERT, data, ALERT_DATA_LEN);
        if (!IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
            alertCtx->isFlush = true;
        }
        if (ret != HITLS_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16267, "Write fail");
        }
        alertCtx->isFlush = true;
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15768, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "Sent an Alert msg:level[%u] description[%u]", data[0], data[1], 0, 0);
    }
#ifdef HITLS_TLS_FEATURE_FLIGHT
    /* if isFlightTransmitEnable is enabled, the stored handshake information needs to be sent */
    bool isFlightTransmitEnable = false;
    (void)HITLS_GetFlightTransmitSwitch(ctx, &isFlightTransmitEnable);
    if (isFlightTransmitEnable) {
        ret = REC_FlightTransmit(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_FLIGHT */
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_TLS13
static uint32_t ALERT_GetVersion(const TLS_Ctx *ctx)
{
    if (ctx->negotiatedInfo.version > 0) {
        /* the version has been negotiated */
        return ctx->negotiatedInfo.version;
    } else {
        /* if the version is not negotiated, the latest version supported by the local end is returned */
        return ctx->config.tlsConfig.maxVersion;
    }
}
#endif /* HITLS_TLS_PROTO_TLS13 */

int32_t ALERT_Init(TLS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15772, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "ctx null.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    // prevent multi init of ctx->alertCtx
    if (ctx->alertCtx != NULL) {
        return HITLS_SUCCESS;
    }
    ctx->alertCtx = (struct AlertCtx *)BSL_SAL_Malloc(sizeof(struct AlertCtx));
    if (ctx->alertCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15773, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc alert ctx fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memset_s(ctx->alertCtx, sizeof(struct AlertCtx), 0, sizeof(struct AlertCtx));
    return HITLS_SUCCESS;
}

void ALERT_Deinit(TLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_FREE(ctx->alertCtx);
}

int32_t ProcessDecryptedAlert(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    struct AlertCtx *alertCtx = ctx->alertCtx;

    /** if the message lengths are not equal, an error code is returned */
    if (dataLen != ALERT_DATA_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15769, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a alert msg with illegal len %u", dataLen, 0, 0, 0);
        ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }

    /** record the alert message */
    if (data[0] == ALERT_LEVEL_FATAL || data[0] == ALERT_LEVEL_WARNING) {
        // prevent abnormal operations
        if (AlertIsAbnormalInput(alertCtx, data[0]) == true) {
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_REC_NORMAL_RECV_UNEXPECT_MSG, BINLOG_ID16268, "input abnormal");
        }
        alertCtx->flag = ALERT_FLAG_RECV;
        alertCtx->level = data[0];
        alertCtx->description = data[1];
#ifdef HITLS_TLS_PROTO_TLS13
        if (ALERT_GetVersion(ctx) == HITLS_VERSION_TLS13 && alertCtx->description != ALERT_CLOSE_NOTIFY) {
            alertCtx->level = ALERT_LEVEL_FATAL;
        }
#endif
        if (alertCtx->level == ALERT_LEVEL_FATAL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16269, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "alert fatal", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
        }
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15770, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "got a alert msg:level[%u] description[%u]", data[0], data[1], 0, 0);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }

    BSL_ERR_PUSH_ERROR(HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15771, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "get a alert msg with illegal type", 0, 0, 0, 0);
    /** Decoding error. Send an alert. */
    ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
    return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
}
#ifdef HITLS_TLS_PROTO_TLS13
int32_t ProcessPlainAlert(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    if (ctx->isClient == true && REC_HaveReadSuiteInfo(ctx)) {
        return RETURN_ALERT_PROCESS(ctx, HITLS_REC_NORMAL_RECV_UNEXPECT_MSG, BINLOG_ID16270,
            "receive plain alert", ALERT_UNEXPECTED_MESSAGE);
    }
    if (ctx->isClient == false && ctx->plainAlertForbid == true) {
        return RETURN_ALERT_PROCESS(ctx, HITLS_REC_NORMAL_RECV_UNEXPECT_MSG, BINLOG_ID16271,
            "tls1.3 forbid to receive plain alert", ALERT_UNEXPECTED_MESSAGE);
    }
    return ProcessDecryptedAlert(ctx, data, dataLen);
}
#endif /* HITLS_TLS_PROTO_TLS13 */

void ALERT_ClearWarnCount(TLS_Ctx *ctx, uint32_t recordType)
{
    if (recordType != REC_TYPE_ALERT) {
        ctx->alertCtx->warnCount = 0;
    }
}

bool ALERT_HaveExceeded(TLS_Ctx *ctx, uint8_t threshold)
{
    ctx->alertCtx->warnCount += 1;
    return ctx->alertCtx->warnCount >= threshold;
}

#ifdef HITLS_BSL_LOG
int32_t ReturnAlertProcess(TLS_Ctx *ctx, int32_t err, uint32_t logId, const void *logStr,
    ALERT_Description description)
{
    if (logStr != NULL) {
        BSL_LOG_BINLOG_FIXLEN(logId, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, logStr, 0, 0, 0, 0);
    }
    if (description != ALERT_UNKNOWN) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, description);
    }
    return err;
}

int32_t ReturnErrorNumberProcess(int32_t err, uint32_t logId, const void *logStr)
{
    (void)logStr;
    BSL_LOG_BINLOG_FIXLEN(logId, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, logStr, 0, 0, 0, 0);
    return err;
}
#endif /* HITLS_BSL_LOG */