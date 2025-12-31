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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "rec.h"
#include "rec.h"
#include "record.h"
#include "app.h"

static int32_t ReadAppData(TLS_Ctx *ctx, uint8_t *buf, uint32_t num, uint32_t *readLen)
{
    return REC_Read(ctx, REC_TYPE_APP, buf, readLen, num);
}

int32_t APP_Read(TLS_Ctx *ctx, uint8_t *buf, uint32_t num, uint32_t *readLen)
{
    int32_t ret;
    uint32_t readbytes;

    if (ctx == NULL || buf == NULL || num == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15659, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP: input null pointer or read bufLen is 0.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_APP_ERR_ZERO_READ_BUF_LEN);
        return HITLS_APP_ERR_ZERO_READ_BUF_LEN;
    }
    // read data to the buffer in non-blocking mode
    do {
        ret =  ReadAppData(ctx, buf, num, &readbytes);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    } while (readbytes == 0); // do not exit the loop until data is read

    *readLen = readbytes;
    return HITLS_SUCCESS;
}

int32_t APP_GetMaxWriteSize(const TLS_Ctx *ctx, uint32_t *len)
{
    return REC_GetMaxWriteSize(ctx, len);
}

static int32_t SavePendingData(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
#ifdef HITLS_TLS_PROTO_DTLS
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return HITLS_SUCCESS;
    }
#endif
    RecCtx *recCtx = (RecCtx *)ctx->recCtx;
    // Stores the plaintext data to be sent.
    recCtx->pendingData = data;
    recCtx->pendingDataSize = dataLen;
    return HITLS_SUCCESS;
}

static int32_t CheckDataLen(TLS_Ctx *ctx, const uint8_t *data, uint32_t *sendLen)
{
    int32_t ret = HITLS_SUCCESS;
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    ret = REC_QueryMtu(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */
    ret = REC_RecOutBufReSet(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    RecCtx *recCtx = (RecCtx *)ctx->recCtx;
    if (recCtx->pendingData != NULL) {
        if ((
#ifdef HITLS_TLS_FEATURE_MODE_ACCEPT_MOVING_WRITE_BUFFER
            (ctx->config.tlsConfig.modeSupport & HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER) == 0 &&
#endif
                recCtx->pendingData != data) || recCtx->pendingDataSize > *sendLen) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16241, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "The two buffer addresses are inconsistent.", 0, 0, 0, 0);
            return HITLS_APP_ERR_WRITE_BAD_RETRY;
        }
        *sendLen = recCtx->pendingDataSize;
        return HITLS_SUCCESS;
    }

    uint32_t maxWriteLen = 0u;
    ret = REC_GetMaxWriteSize(ctx, &maxWriteLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15660, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP: Get record max write size fail.", 0, 0, 0, 0);
        return ret;
    }
    if (*sendLen > maxWriteLen) {
        *sendLen = maxWriteLen;
    }

    return SavePendingData(ctx, data, *sendLen);
}

int32_t APP_Write(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t sendLen = dataLen;
    ret = CheckDataLen(ctx, data, &sendLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
	*writeLen = 0;

    ret = REC_Write(ctx, REC_TYPE_APP, data, sendLen);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16274, "Write fail");
    }
#ifdef HITLS_TLS_FEATURE_FLIGHT
    if (ctx->config.tlsConfig.isFlightTransmitEnable) {
        ret = REC_FlightTransmit(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif
    *writeLen = sendLen;
    ctx->recCtx->pendingData = NULL;
    ctx->recCtx->pendingDataSize = 0;
    return HITLS_SUCCESS;
}