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
#include "bsl_list.h"
#include "tls_binlog_id.h"
#include "bsl_uio.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "rec.h"
#include "app_ctx.h"
#include "rec.h"
#include "app.h"

static AppBuf *NewAppBufNode(const uint8_t *data, uint32_t len)
{
    AppBuf *appBufNode = (AppBuf *)BSL_SAL_Malloc(sizeof(AppBuf));
    if (appBufNode == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15945, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP: appBufNode malloc fail when NewAppBufNode.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return NULL;
    }

    appBufNode->buf = (uint8_t *)BSL_SAL_Dump(data, len);
    if (appBufNode->buf == NULL) {
        BSL_SAL_FREE(appBufNode);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15946, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP: appBufNode->buf malloc fail when NewAppBufNode.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return NULL;
    }

    appBufNode->bufSize = len;
    appBufNode->start = 0;
    appBufNode->end = len;

    return appBufNode;
}

void FreeAppBufNode(AppBuf *appBufNode)
{
    if (appBufNode != NULL) {
        BSL_SAL_FREE(appBufNode->buf);
        BSL_SAL_FREE(appBufNode);
    }
    return;
}

int32_t APP_Init(TLS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15445, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ctx is null.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }
    // Prevent multiple init of ctx->appCtx
    if (ctx->appCtx != NULL) {
        return HITLS_SUCCESS;
    }
    APP_Ctx *appCtx = (APP_Ctx *)BSL_SAL_Calloc(1U, sizeof(APP_Ctx));
    uint32_t bufSize = 0;
    if (appCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15655, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP: malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    bufSize = REC_MAX_TLS13_ENCRYPTED_LEN;

    appCtx->appReadBuf.buf = (uint8_t *)BSL_SAL_Malloc(bufSize);
    if (appCtx->appReadBuf.buf == NULL) {
        BSL_SAL_FREE(appCtx);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15656, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP: malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    appCtx->appReadBuf.bufSize = bufSize;
    appCtx->appReadBuf.start = 0;
    appCtx->appReadBuf.end = 0;

    appCtx->appList = BSL_LIST_New(sizeof(AppBuf));
    if (appCtx->appList == NULL) {
        BSL_SAL_FREE(appCtx->appReadBuf.buf);
        BSL_SAL_FREE(appCtx);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15947, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP: appList malloc fail when APP_Init.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    APP_DeInit(ctx);
    ctx->appCtx = appCtx;
    return HITLS_SUCCESS;
}

static void AppBufNodeDestroy(void *data)
{
    FreeAppBufNode((AppBuf *)data);
    return;
}

void APP_DeInit(TLS_Ctx *ctx)
{
    if (ctx->appCtx != NULL) {
        BSL_SAL_FREE(ctx->appCtx->appReadBuf.buf);
        BSL_LIST_FREE(ctx->appCtx->appList, AppBufNodeDestroy);
        BSL_SAL_FREE(ctx->appCtx);
    }

    return;
}

// when the revAppdata->end - revAppdata->start > 0, which means  there is data in the cache, copy data from revAppdata
static int32_t AppBufRead(AppBuf *revAppdata, uint8_t *buf, uint32_t num, uint32_t *readLen)
{
    uint32_t dataSize = revAppdata->end - revAppdata->start;
    uint32_t copyLen = (dataSize > num) ? num : dataSize;

    if (memcpy_s(buf, num, &revAppdata->buf[revAppdata->start], copyLen) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15657, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP: memcpy fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    revAppdata->start += copyLen;
    *readLen = copyLen;
    return HITLS_SUCCESS;
}

static uint32_t GetAppListBufSize(const TLS_Ctx *ctx)
{
    uint32_t totalSize = 0;
    AppList *tmpList = ctx->appCtx->appList;
    AppBuf *appBufNode = (AppBuf *)BSL_LIST_GET_FIRST(tmpList);
    while (appBufNode != NULL) {
        totalSize += appBufNode->end - appBufNode->start;
        appBufNode = (AppBuf *)BSL_LIST_GET_NEXT(tmpList);
    }
    return totalSize;
}

static int32_t AppListBufRead(TLS_Ctx *ctx, uint8_t *buf, uint32_t num, uint32_t *readLen)
{
    AppList *tmpList = ctx->appCtx->appList;
    AppBuf *appBufNode = NULL;
    appBufNode = (AppBuf *)BSL_LIST_GET_FIRST(tmpList);
    if (appBufNode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    uint32_t dataSize = appBufNode->end - appBufNode->start;
    uint32_t copyLen = (dataSize > num) ? num : dataSize;

    if (memcpy_s(buf, num, &appBufNode->buf[appBufNode->start], copyLen) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15948, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP: memcpy fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    appBufNode->start += copyLen;

    if (appBufNode->start == appBufNode->end) {
        BSL_LIST_DeleteCurrent(tmpList, AppBufNodeDestroy);
    }

    *readLen = copyLen;
    return HITLS_SUCCESS;
}

static int32_t AppReadData(TLS_Ctx *ctx, uint8_t *buf, uint32_t num, uint32_t *readLen)
{
    int32_t ret;
    uint32_t readbytes = 0;
    AppBuf *revAppdata = NULL;

    if (ctx->appCtx == NULL || ctx->appCtx->appReadBuf.buf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15658, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP: error null pointer.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }

    revAppdata = &ctx->appCtx->appReadBuf;

    /* Check whether there is data in the cache. */
    if (revAppdata->end > revAppdata->start) {
        return AppBufRead(revAppdata, buf, num, readLen);
    }

    /* Check whether there is data in the cache of unexpected messages. */
    if (BSL_LIST_COUNT(ctx->appCtx->appList) > 0) {
        return AppListBufRead(ctx, buf, num, readLen);
    }

    /* If there is no data in the cache and the size of the user buffer is greater than the maximum size of the record,
       the app read cache is not used. */
    if (num >= REC_MAX_TLS13_ENCRYPTED_LEN) {
        return REC_Read(ctx, REC_TYPE_APP, buf, readLen, num);
    }
    // read data from the uio of the CTX to revAppdata
    ret = REC_Read(ctx, REC_TYPE_APP, revAppdata->buf, &readbytes, revAppdata->bufSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    revAppdata->start = 0;
    revAppdata->end = readbytes;

    if (revAppdata->end > revAppdata->start) {
        return AppBufRead(revAppdata, buf, num, readLen);
    }

    /* read an app record with 0 byte */
    *readLen = 0;
    return HITLS_SUCCESS;
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
        ret =  AppReadData(ctx, buf, num, &readbytes);
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

int32_t APP_Write(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    uint32_t maxWriteLen = 0u;
    int32_t ret = REC_GetMaxWriteSize(ctx, &maxWriteLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15660, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP:Get record max write size fail.", 0, 0, 0, 0);
        return ret;
    }
    if (dataLen > maxWriteLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15661, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "APP:write length is too big: max length-%u.", maxWriteLen, 0, 0, 0);
        return HITLS_APP_ERR_TOO_LONG_TO_WRITE;
    }

    ret = REC_Write(ctx, REC_TYPE_APP, data, dataLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (ctx->config.tlsConfig.isFlightTransmitEnable) {
        ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
        if (ret == BSL_UIO_IO_BUSY) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        if (ret != BSL_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15888, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "fail to send handshake message in bUio.", 0, 0, 0, 0);
            return HITLS_REC_ERR_IO_EXCEPTION;
        }
    }
    return HITLS_SUCCESS;
}

void APP_RecvUnexpectedMsgProcess(TLS_Ctx *ctx, const uint8_t *data, uint32_t len)
{
    /* if the message length is 0, a message is returned */
    if (len == 0u) {
        return;
    }

    /* if the buffer is full, discard the newly received messages */
    APP_Ctx *appCtx = ctx->appCtx;
    if (BSL_LIST_COUNT(appCtx->appList) >= UNPROCESSED_APP_MSG_COUNT_MAX) {
        return;
    }

    /* cache received unexpected app messages */
    AppBuf *appBufNode = NewAppBufNode(data, len);
    if (appBufNode == NULL) {
        return;
    }

    /* insert the message to the end of the linked list */
    if (BSL_LIST_AddElement(appCtx->appList, appBufNode, BSL_LIST_POS_END) != BSL_SUCCESS) {
        FreeAppBufNode(appBufNode);
        return;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15949, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "APP: recv unexpected app msg.", 0, 0, 0, 0);
    return;
}

uint32_t APP_GetReadPendingBytes(const TLS_Ctx *ctx)
{
    if ((ctx == NULL) || (ctx->appCtx == NULL)) {
        return 0;
    }

    AppBuf *revAppdata = &ctx->appCtx->appReadBuf;
    uint32_t totalSize = revAppdata->end - revAppdata->start;
    totalSize += GetAppListBufSize(ctx); /* the cache size must be added to the cache of unexpected messages */

    return totalSize;
}
