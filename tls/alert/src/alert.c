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

#include "securec.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "rec.h"
#include "bsl_uio.h"
#include "hitls.h"
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
    return;
}

void ALERT_CleanInfo(const TLS_Ctx *ctx)
{
    (void)memset_s(ctx->alertCtx, sizeof(struct AlertCtx), 0, sizeof(struct AlertCtx));
    return;
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

void ALERT_Send(TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
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
    return;
}

int32_t ALERT_Flush(TLS_Ctx *ctx)
{
    struct AlertCtx *alertCtx = ctx->alertCtx;
    int32_t ret;
    if (alertCtx->flag != ALERT_FLAG_SEND) {
        BSL_ERR_PUSH_ERROR(HITLS_ALERT_NO_WANT_SEND);
        return HITLS_ALERT_NO_WANT_SEND;
    }
    if (alertCtx->isFlush == false) {
        uint8_t data[ALERT_DATA_LEN];
        /** obtain the alert level */
        data[0] = alertCtx->level;
        data[1] = alertCtx->description;
        /** write the record */
        ret = REC_Write(ctx, REC_TYPE_ALERT, data, ALERT_DATA_LEN);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        alertCtx->isFlush = true;
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15768, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "Sent an Alert msg:level[%u] description[%u]", data[0], data[1], 0, 0);
    }
    /* if isFlightTransmitEnable is enabled, the stored handshake information needs to be sent */
    uint8_t isFlightTransmitEnable;
    (void)HITLS_GetFlightTransmitSwitch(ctx, &isFlightTransmitEnable);
    if (isFlightTransmitEnable == 1) {
        ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
        if (ret == BSL_UIO_IO_BUSY) {
            BSL_ERR_PUSH_ERROR(HITLS_REC_NORMAL_IO_BUSY);
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        if (ret != BSL_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15778, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "fail to send alert message in bUio.", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_IO_EXCEPTION);
            return HITLS_REC_ERR_IO_EXCEPTION;
        }
    }
    return HITLS_SUCCESS;
}

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


void ALERT_Recv(TLS_Ctx *ctx, const uint8_t *data, uint32_t len)
{
    struct AlertCtx *alertCtx = ctx->alertCtx;

    /** if the message lengths are not equal, an error code is returned */
    if (len != ALERT_DATA_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15769, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a alert msg with illegal len", 0, 0, 0, 0);
        ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return;
    }

    /** record the alert message */
    if (data[0] == ALERT_LEVEL_FATAL || data[0] == ALERT_LEVEL_WARNING) {
        // prevent abnormal operations
        if (AlertIsAbnormalInput(alertCtx, data[0]) == true) {
            return;
        }
        alertCtx->flag = ALERT_FLAG_RECV;
        alertCtx->level = data[0];
        alertCtx->description = data[1];
        if (ALERT_GetVersion(ctx) == HITLS_VERSION_TLS13 && alertCtx->description != ALERT_CLOSE_NOTIFY) {
            alertCtx->level = ALERT_LEVEL_FATAL;
        }
        if (alertCtx->level == ALERT_LEVEL_FATAL) {
            BSL_ERR_PUSH_ERROR(HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
        }
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15770, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "got a alert msg:level[%u] description[%u]", data[0], data[1], 0, 0);
        return;
    }

    BSL_ERR_PUSH_ERROR(HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15771, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "get a alert msg with illegal type", 0, 0, 0, 0);
    /** Decoding error. Send an alert. */
    ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
    return;
}

int32_t ALERT_Init(TLS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15772, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ctx is null.", 0, 0, 0, 0);
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
    return;
}