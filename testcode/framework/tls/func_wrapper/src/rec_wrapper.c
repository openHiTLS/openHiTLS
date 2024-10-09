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
#include "hs_ctx.h"
#include "rec_wrapper.h"

#define MAX_BUF 16384
static RecWrapper g_recWrapper;
static bool g_enableWrapper;
static __thread uint8_t g_locBuffer[MAX_BUF] = { 0 };

void RegisterWrapper(RecWrapper wrapper)
{
    g_enableWrapper = true;
    g_recWrapper = wrapper;
}

void ClearWrapper(void)
{
    g_enableWrapper = false;
}

extern int32_t __real_REC_Read(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num);

extern int32_t __real_REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num);

extern int32_t __wrap_REC_Read(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num)
{
    int32_t ret = __real_REC_Read(ctx, recordType, data, readLen, num);
    if (!g_enableWrapper || ret != 0 || !g_recWrapper.isRecRead || g_recWrapper.recordType != recordType) {
        return ret;
    }
    if (g_recWrapper.recordType == REC_TYPE_HANDSHAKE && ctx->hsCtx->state != g_recWrapper.ctrlState) {
        return ret;
    }
    g_recWrapper.func(ctx, data, readLen, num, g_recWrapper.userData);
    return ret;
}

extern int32_t __wrap_REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    // Length that can be manipulated in wrapper
    uint32_t manipulateLen = num;
    if (!g_enableWrapper || g_recWrapper.isRecRead || g_recWrapper.recordType != recordType) {
        return __real_REC_Write(ctx, recordType, data, manipulateLen);
    }
    if (g_recWrapper.recordType == REC_TYPE_HANDSHAKE && ctx->hsCtx->state != g_recWrapper.ctrlState) {
        return __real_REC_Write(ctx, recordType, data, manipulateLen);
    }
    (void)memcpy_s(g_locBuffer, MAX_BUF, data, num);
    // The value of manipulateLen can be greater than or smaller than num
    g_recWrapper.func(ctx, g_locBuffer, &manipulateLen, MAX_BUF, g_recWrapper.userData);
    if (ctx->hsCtx->bufferLen < manipulateLen) {
        exit(-1);
    }
    (void)memcpy_s(ctx->hsCtx->msgBuf, ctx->hsCtx->bufferLen, g_locBuffer, manipulateLen);
    ctx->hsCtx->msgLen = manipulateLen;
    return __real_REC_Write(ctx, recordType, g_locBuffer, manipulateLen);
}