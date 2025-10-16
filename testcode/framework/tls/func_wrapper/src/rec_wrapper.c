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
#include "hitls_build.h"
#include "rec_crypto.h"
#include "hs_ctx.h"
#include "stub_replace.h"
#include "rec_wrapper.h"
#define MAX_BUF 16384
static RecWrapper g_recWrapper;
static bool g_enableWrapper;

// Platform-specific wrapper function declarations
#if defined(HITLS_BSL_SAL_LINUX)
// GNU ld --wrap functions (only available on Linux with --wrap flags)
static __thread uint8_t g_locBuffer[MAX_BUF] = { 0 };
extern int32_t __real_REC_Read(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num);

extern int32_t __real_REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num);

extern int32_t __wrap_REC_Read(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num)
{
    return __real_REC_Read(ctx, recordType, data, readLen, num);
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
        uint8_t *tmp = BSL_SAL_Realloc(ctx->hsCtx->msgBuf, manipulateLen, ctx->hsCtx->bufferLen);
        if (tmp == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        ctx->hsCtx->bufferLen = manipulateLen;
        ctx->hsCtx->msgBuf = tmp;
    }

    if (recordType == REC_TYPE_HANDSHAKE) {
        (void)memcpy_s(ctx->hsCtx->msgBuf, ctx->hsCtx->bufferLen, g_locBuffer, manipulateLen);
        ctx->hsCtx->msgLen = manipulateLen;
    }
    int32_t ret = __real_REC_Write(ctx, recordType, g_locBuffer, manipulateLen);
    if (recordType == REC_TYPE_HANDSHAKE && ret == HITLS_SUCCESS) {
        ctx->hsCtx->msgOffset = manipulateLen - num;
    }
    return ret;
}
#elif defined(HITLS_BSL_SAL_DARWIN)
// macOS/Darwin does not support GNU ld --wrap flag
// Use direct function calls instead of __real_/__wrap_ symbols should add later for full support
static uint8_t g_locBuffer[MAX_BUF] = { 0 };
extern int32_t REC_Read(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num);

extern int32_t REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num);

// Note: On macOS, these wrapper functions are not automatically invoked by the linker
// Direct function call interception would require different mechanisms (e.g., dyld interposing)
#else
#error "Unsupported platform: REC wrapper functions require either HITLS_BSL_SAL_LINUX or HITLS_BSL_SAL_DARWIN"
#endif

RecCryptoFunc g_aeadFuncs;
RecCryptoFunc g_cbcFuncs;
RecCryptoFunc g_plainFuncs;

void FRAME_InitRecCrypto(void)
{
    g_plainFuncs = *RecGetCryptoFuncs(NULL);
    RecConnSuitInfo info = {0};
    info.cipherType = HITLS_AEAD_CIPHER;
    g_aeadFuncs = *RecGetCryptoFuncs(&info);
    info.cipherType = HITLS_CBC_CIPHER;
    g_cbcFuncs = *RecGetCryptoFuncs(&info);
}

static RecCryptoFunc *RecGetOriginCryptFuncs(RecConnSuitInfo *suiteInfo)
{
    if (suiteInfo == NULL) {
        return &g_plainFuncs;
    }
    switch (suiteInfo->cipherType) {
        case HITLS_AEAD_CIPHER:
            return &g_aeadFuncs;
        case HITLS_CBC_CIPHER:
            return &g_cbcFuncs;
        default:
            return &g_plainFuncs;
    }
    return &g_plainFuncs;
}

static int32_t WrapperDecryptFunc(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    int32_t ret = RecGetOriginCryptFuncs(state->suiteInfo)->decrypt(ctx, state, cryptMsg, data, dataLen);
    if (ret == HITLS_SUCCESS && IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) && g_recWrapper.isRecRead) {
        if (g_recWrapper.recordType != cryptMsg->type) {
            return ret;
        }
        if (g_recWrapper.recordType == REC_TYPE_HANDSHAKE) {
            if (ctx->hsCtx == NULL || ctx->hsCtx->state != g_recWrapper.ctrlState) {
                return ret;
            }
        }
        g_recWrapper.func(ctx, data, dataLen, *dataLen, g_recWrapper.userData);
    }
    return ret;
}

static int32_t WrapperDecryptPostProcess(TLS_Ctx *ctx, RecConnSuitInfo *suitInfo, REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    int32_t ret =  RecGetOriginCryptFuncs(suitInfo)->decryptPostProcess(ctx, suitInfo, cryptMsg, data, dataLen);
    if (ret == HITLS_SUCCESS && g_recWrapper.isRecRead) {
        if (g_recWrapper.recordType != cryptMsg->type) {
            return ret;
        }
        if (g_recWrapper.recordType == REC_TYPE_HANDSHAKE) {
            if (ctx->hsCtx == NULL || ctx->hsCtx->state != g_recWrapper.ctrlState) {
                return ret;
            }
        }
        g_recWrapper.func(ctx, data, dataLen, *dataLen, g_recWrapper.userData);
    }
    return ret;
}

static int32_t WrapperCalPlantextBufLenFunc(TLS_Ctx *ctx, RecConnSuitInfo *suitInfo,
    uint32_t ciphertextLen, uint32_t *offset, uint32_t *plainLen)
{
    (void)ctx;
    (void)suitInfo;
    (void)ciphertextLen;
    (void)offset;
    *plainLen = 16384 + 2048;
    return HITLS_SUCCESS;
}

static RecCryptoFunc *Stub_RecCrypto(RecConnSuitInfo *suiteInfo)
{
    static RecCryptoFunc recCryptoFunc = { 0 };
    recCryptoFunc = *RecGetOriginCryptFuncs(suiteInfo);
    recCryptoFunc.calPlantextBufLen = WrapperCalPlantextBufLenFunc;
    recCryptoFunc.decrypt = WrapperDecryptFunc;
    recCryptoFunc.decryptPostProcess = WrapperDecryptPostProcess;
    return &recCryptoFunc;
}
FuncStubInfo g_stubRecFuncs;

void RegisterWrapper(RecWrapper wrapper)
{
    if (g_enableWrapper) {
        ClearWrapper();
    }
    FRAME_InitRecCrypto();
    STUB_Init();
    STUB_Replace(&g_stubRecFuncs, (void *)RecGetCryptoFuncs, (void *)Stub_RecCrypto);
    g_enableWrapper = true;
    g_recWrapper = wrapper;
}

void ClearWrapper(void)
{
    STUB_Reset(&g_stubRecFuncs);
    g_enableWrapper = false;
}
