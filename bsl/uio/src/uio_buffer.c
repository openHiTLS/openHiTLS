/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_BSL_UIO_BUFFER

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_uio.h"
#include "uio_abstraction.h"

// The write behavior must be the same.
#define UIO_BUFFER_DEFAULT_SIZE     4096

typedef struct {
    uint32_t outSize;
    // This variable will make the write() logic consistent with the ossl. Reason:
    // 1) The handshake logic is complex.
    // 2) The behavior consistency problem of the handshake logic is difficult to locate.
    uint32_t outOff;
    uint32_t outLen;
    uint8_t *outBuf;
} BufferCtx;

static int32_t BufferCreate(BSL_UIO *uio)
{
    if (uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BufferCtx *ctx = BSL_SAL_Calloc(1, sizeof(BufferCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ctx->outSize = UIO_BUFFER_DEFAULT_SIZE;
    ctx->outBuf = (uint8_t *)BSL_SAL_Malloc(UIO_BUFFER_DEFAULT_SIZE);
    if (ctx->outBuf == NULL) {
        BSL_SAL_FREE(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    BSL_UIO_SetCtx(uio, ctx);
    uio->init = 1;
    return BSL_SUCCESS;
}

static int32_t BufferDestroy(BSL_UIO *uio)
{
    if (uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BufferCtx *ctx = BSL_UIO_GetCtx(uio);
    if (ctx != NULL) {
        BSL_SAL_FREE(ctx->outBuf);
        BSL_SAL_FREE(ctx);
        BSL_UIO_SetCtx(uio, NULL);
    }
    uio->flags = 0;
    uio->init = 0;
    return BSL_SUCCESS;
}

static int32_t BufferFlushInternal(BSL_UIO *uio)
{
    BufferCtx *ctx = BSL_UIO_GetCtx(uio);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    while (ctx->outLen > 0) {
        uint32_t tmpWriteLen = 0;
        int32_t ret = BSL_UIO_Write(uio->next, &ctx->outBuf[ctx->outOff], ctx->outLen, &tmpWriteLen);
        if (ret != BSL_SUCCESS) {
            uio->flags = uio->next->flags;
            return ret;
        }
        if (tmpWriteLen == 0) {
            BSL_ERR_PUSH_ERROR(BSL_UIO_IO_BUSY);
            return BSL_UIO_IO_BUSY;
        }
        ctx->outOff += tmpWriteLen;
        ctx->outLen -= tmpWriteLen;
    }
    ctx->outOff = 0;
    ctx->outLen = 0;
    return BSL_SUCCESS;
}

static int32_t BufferFlush(BSL_UIO *uio, int32_t larg, void *parg)
{
    bool invalid = (uio == NULL) || (uio->next == NULL) || (uio->ctx == NULL);
    if (invalid) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BufferCtx *ctx = BSL_UIO_GetCtx(uio);
    if (ctx->outLen == 0) { // invoke the flush of the next UIO object
        return BSL_UIO_Ctrl(uio->next, BSL_UIO_FLUSH, larg, parg);
    }
    (void)BSL_UIO_ClearFlags(uio, (BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY));
    int32_t ret = BufferFlushInternal(uio);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return BSL_UIO_Ctrl(uio->next, BSL_UIO_FLUSH, larg, parg);
}

static int32_t BufferReset(BSL_UIO *uio)
{
    if (uio == NULL || uio->ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BufferCtx *ctx = uio->ctx;
    ctx->outLen = 0;
    ctx->outOff = 0;

    if (uio->next == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    return BSL_UIO_Ctrl(uio->next, BSL_UIO_RESET, 0, NULL);
}

static int32_t BufferCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    switch (cmd) {
        case BSL_UIO_FLUSH:
            return BufferFlush(uio, larg, parg);
        case BSL_UIO_RESET:
            return BufferReset(uio);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    return BSL_UIO_FAIL;
}

// Add data to the remaining space.
static int32_t TryCompleteBuffer(BufferCtx *ctx, const void *in, uint32_t remain, uint32_t *writeLen)
{
    const uint32_t freeSpace = ctx->outSize - (ctx->outOff + ctx->outLen);
    if (freeSpace == 0) {
        return BSL_SUCCESS;
    }
    const uint32_t real = (freeSpace < remain) ? freeSpace : remain;
    if (memcpy_s(&ctx->outBuf[ctx->outOff + ctx->outLen], freeSpace, in, real) != EOK) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    ctx->outLen += real;
    *writeLen += real;
    return BSL_SUCCESS;
}

static int32_t BufferWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    bool invalid = (uio == NULL) || (buf == NULL) || (writeLen == NULL) || (uio->next == NULL);
    if (invalid) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    *writeLen = 0;
    BufferCtx *ctx = BSL_UIO_GetCtx(uio);
    invalid = (ctx == NULL) || (ctx->outBuf == NULL);
    if (invalid) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    (void)BSL_UIO_ClearFlags(uio, (BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY));
    const uint8_t *in = buf;
    uint32_t remain = len;
    while (remain > 0) {
        const uint32_t freeSpace = ctx->outSize - (ctx->outOff + ctx->outLen);
        if (freeSpace >= remain) { // If the space is sufficient, cache the data.
            return TryCompleteBuffer(ctx, in, remain, writeLen);
        }
        // else: space is insufficient
        if (ctx->outLen > 0) {  // buffer already has data, need to send the existing data first.
            int32_t ret = BufferFlushInternal(uio);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        }
        ctx->outOff = 0;
        while (remain >= ctx->outSize) {
            uint32_t tmpWriteLen = 0;
            int32_t ret = BSL_UIO_Write(uio->next, in, remain, &tmpWriteLen);
            if (ret != BSL_SUCCESS) {
                uio->flags = uio->next->flags;
                return ret;
            }
            *writeLen += tmpWriteLen;
            in = &in[tmpWriteLen];
            remain -= tmpWriteLen;
        }
    }
    return BSL_SUCCESS;
}

const BSL_UIO_Method *BSL_UIO_BufferMethod(void)
{
    static const BSL_UIO_Method m = {
        BSL_UIO_BUFFER,
        BufferWrite,
        NULL,
        BufferCtrl,
        NULL,
        NULL,
        BufferCreate,
        BufferDestroy,
    };
    return &m;
}
#endif /* HITLS_BSL_UIO_BUFFER */
