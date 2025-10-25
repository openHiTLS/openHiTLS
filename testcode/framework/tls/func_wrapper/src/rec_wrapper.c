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
#include "hs_ctx.h"
#include "bsl_sal.h"
#include "record.h"  // Include official RecCtx definition
#include "rec.h"     // REC_Init API
#include "rec_wrapper.h"
#include "rec_crypto.h"  // For read wrapper support via STUB
#include "stub_utils.h"  // For STUB mechanism (new framework)
#include <pthread.h>

#define MAX_BUF 16384
#define MAX_CONNECTIONS 1024

// Define stub for RecGetCryptoFuncs using new framework
// Signature: const RecCryptoFunc *RecGetCryptoFuncs(const RecConnSuitInfo *suiteInfo)
STUB_DEFINE_RET1(const RecCryptoFunc *, RecGetCryptoFuncs, const RecConnSuitInfo *);

// Global wrapper configuration (set by RegisterWrapper)
// Note: g_recWrapper.func == NULL indicates no active wrapper
static RecWrapper g_recWrapper;
static bool g_enableWrapper = false;  // Enable flag for STUB-based wrappers

// STUB-based read wrapper support - crypto function caches
RecCryptoFunc g_aeadFuncs;
RecCryptoFunc g_cbcFuncs;
RecCryptoFunc g_plainFuncs;

// Per-connection wrapper context
typedef struct {
    RecWrapper config;
    REC_WriteFunc originalRecWrite;  // Use official REC_WriteFunc type
    bool enabled;
} WrapperContext;

// Global mapping table: TLS_Ctx* -> WrapperContext*
typedef struct {
    TLS_Ctx *ctx;
    WrapperContext *wrapper;
} CtxWrapperMapping;

static CtxWrapperMapping g_ctxMappings[MAX_CONNECTIONS];
static int g_mappingCount = 0;
static pthread_mutex_t g_mappingMutex = PTHREAD_MUTEX_INITIALIZER;

// Global connection tracking list (for late wrapper application)
static TLS_Ctx *g_allConnections[MAX_CONNECTIONS];
static int g_connectionCount = 0;
static pthread_mutex_t g_connectionMutex = PTHREAD_MUTEX_INITIALIZER;

// Helper functions for context mapping
static WrapperContext *GetWrapperContext(TLS_Ctx *ctx)
{
    pthread_mutex_lock(&g_mappingMutex);
    for (int i = 0; i < g_mappingCount; i++) {
        if (g_ctxMappings[i].ctx == ctx) {
            WrapperContext *result = g_ctxMappings[i].wrapper;
            pthread_mutex_unlock(&g_mappingMutex);
            return result;
        }
    }
    pthread_mutex_unlock(&g_mappingMutex);
    return NULL;
}

static void SetWrapperContext(TLS_Ctx *ctx, WrapperContext *wrapper)
{
    pthread_mutex_lock(&g_mappingMutex);

    // Check if already exists
    for (int i = 0; i < g_mappingCount; i++) {
        if (g_ctxMappings[i].ctx == ctx) {
            g_ctxMappings[i].wrapper = wrapper;
            pthread_mutex_unlock(&g_mappingMutex);
            return;
        }
    }

    // Add new mapping
    if (g_mappingCount < MAX_CONNECTIONS) {
        g_ctxMappings[g_mappingCount].ctx = ctx;
        g_ctxMappings[g_mappingCount].wrapper = wrapper;
        g_mappingCount++;
    }

    pthread_mutex_unlock(&g_mappingMutex);
}

static void RemoveWrapperContext(TLS_Ctx *ctx)
{
    pthread_mutex_lock(&g_mappingMutex);

    for (int i = 0; i < g_mappingCount; i++) {
        if (g_ctxMappings[i].ctx == ctx) {
            // Free wrapper context
            if (g_ctxMappings[i].wrapper != NULL) {
                BSL_SAL_Free(g_ctxMappings[i].wrapper);
            }

            // Shift remaining mappings
            for (int j = i; j < g_mappingCount - 1; j++) {
                g_ctxMappings[j] = g_ctxMappings[j + 1];
            }
            g_mappingCount--;
            break;
        }
    }

    pthread_mutex_unlock(&g_mappingMutex);
}

// Function pointer wrapper that intercepts REC_Write calls
static int32_t WrapperRecWrite(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    if (ctx == NULL || ctx->recCtx == NULL) {
        return HITLS_NULL_INPUT;
    }

    // Get wrapper context from global mapping table
    WrapperContext *wctx = GetWrapperContext(ctx);
    if (wctx == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    if (!wctx->enabled) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    RecWrapper *wrapper = &wctx->config;
    REC_WriteFunc originalFunc = wctx->originalRecWrite;

    // Check if wrapper applies to this record type
    if (wrapper->isRecRead || wrapper->recordType != recordType) {
        return originalFunc(ctx, recordType, data, num);
    }

    // Check handshake state if this is a handshake record
    if (wrapper->recordType == REC_TYPE_HANDSHAKE) {
        if (ctx->hsCtx == NULL) {
            return originalFunc(ctx, recordType, data, num);
        }
        if (ctx->hsCtx->state != wrapper->ctrlState) {
            return originalFunc(ctx, recordType, data, num);
        }
    }

    // Apply message modification
    uint8_t locBuffer[MAX_BUF];
    uint32_t manipulateLen = num;

    (void)memcpy_s(locBuffer, MAX_BUF, data, num);
    wrapper->func(ctx, locBuffer, &manipulateLen, MAX_BUF, wrapper->userData);

    // Reallocate buffer if needed
    if (recordType == REC_TYPE_HANDSHAKE && ctx->hsCtx->bufferLen < manipulateLen) {
        uint8_t *tmp = BSL_SAL_Realloc(ctx->hsCtx->msgBuf, manipulateLen, ctx->hsCtx->bufferLen);
        if (tmp == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        ctx->hsCtx->bufferLen = manipulateLen;
        ctx->hsCtx->msgBuf = tmp;
    }

    // Update handshake context
    if (recordType == REC_TYPE_HANDSHAKE) {
        (void)memcpy_s(ctx->hsCtx->msgBuf, ctx->hsCtx->bufferLen, locBuffer, manipulateLen);
        ctx->hsCtx->msgLen = manipulateLen;
    }

    // Temporarily restore original recWrite to prevent recursion
    // But calling REC_Write() with wrapper still installed would cause infinite recursion
    // because REC_Write internally calls ctx->recCtx->recWrite (which is WrapperRecWrite)
    ctx->recCtx->recWrite = originalFunc;

    // Call REC_Write by symbol to honor STUB_REPLACE from callbacks
    int32_t ret = REC_Write(ctx, recordType, locBuffer, manipulateLen);

    // Restore wrapper
    ctx->recCtx->recWrite = WrapperRecWrite;

    if (recordType == REC_TYPE_HANDSHAKE && ret == HITLS_SUCCESS) {
        ctx->hsCtx->msgOffset = manipulateLen - num;
    }

    return ret;
}

// Internal function to apply wrapper to a specific connection
// This is called by the HLT framework after creating each connection
void ApplyWrapperToConnection(TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->recCtx == NULL || g_recWrapper.func == NULL) {
        return;
    }

    RecCtx *recCtx = ctx->recCtx;  // Use official RecCtx type

    // Check if wrapper already applied
    WrapperContext *existingWrapper = GetWrapperContext(ctx);
    if (existingWrapper != NULL) {
        return;
    }

    // Allocate wrapper context
    WrapperContext *wctx = (WrapperContext *)BSL_SAL_Calloc(1, sizeof(WrapperContext));
    if (wctx == NULL) {
        return;
    }

    // Store configuration and original function pointer
    wctx->config = g_recWrapper;
    wctx->originalRecWrite = recCtx->recWrite;
    wctx->enabled = true;

    // Add to mapping table
    SetWrapperContext(ctx, wctx);

    // Install wrapper function pointer
    recCtx->recWrite = WrapperRecWrite;
}

// Early wrapper application - initializes recCtx if needed
// This solves the timing issue: wrapper must be applied BEFORE first HITLS_Connect
void ApplyWrapperToConnectionEarly(TLS_Ctx *ctx)
{
    if (ctx == NULL || g_recWrapper.func == NULL) {
        return;
    }

    // If recCtx not yet initialized, initialize it now
    if (ctx->recCtx == NULL) {
        int32_t ret = REC_Init(ctx);
        if (ret != HITLS_SUCCESS) {
            return;
        }
    }

    // Now recCtx is guaranteed to be initialized, apply wrapper
    ApplyWrapperToConnection(ctx);
}

// Internal function to remove wrapper from a connection
void RemoveWrapperFromConnection(TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->recCtx == NULL) {
        return;
    }

    RecCtx *recCtx = ctx->recCtx;  // Use official RecCtx type
    WrapperContext *wctx = GetWrapperContext(ctx);

    if (wctx == NULL) {
        return;
    }

    // Restore original function pointer
    recCtx->recWrite = wctx->originalRecWrite;

    // Remove from mapping table (also frees wctx)
    RemoveWrapperContext(ctx);
}

// Check if wrapper is enabled
bool IsWrapperEnabled(void)
{
    return g_recWrapper.func != NULL;
}

// Connection tracking functions
void RegisterConnection(TLS_Ctx *ctx)
{
    pthread_mutex_lock(&g_connectionMutex);

    // Prevent duplicate registration
    for (int i = 0; i < g_connectionCount; i++) {
        if (g_allConnections[i] == ctx) {
            pthread_mutex_unlock(&g_connectionMutex);
            return;
        }
    }

    // Add to global tracking list
    if (g_connectionCount < MAX_CONNECTIONS) {
        g_allConnections[g_connectionCount] = ctx;
        g_connectionCount++;
    }

    pthread_mutex_unlock(&g_connectionMutex);
}

void UnregisterConnection(TLS_Ctx *ctx)
{
    pthread_mutex_lock(&g_connectionMutex);

    // Remove from list (compact array)
    for (int i = 0; i < g_connectionCount; i++) {
        if (g_allConnections[i] == ctx) {
            for (int j = i; j < g_connectionCount - 1; j++) {
                g_allConnections[j] = g_allConnections[j + 1];
            }
            g_connectionCount--;
            break;
        }
    }

    pthread_mutex_unlock(&g_connectionMutex);
}

// ============================================================================
// STUB-based Read Wrapper Support
// ============================================================================

// Initialize crypto function tables for STUB mechanism
void FRAME_InitRecCrypto(void)
{
    g_plainFuncs = *RecGetCryptoFuncs(NULL);
    RecConnSuitInfo info = {0};
    info.cipherType = HITLS_AEAD_CIPHER;
    g_aeadFuncs = *RecGetCryptoFuncs(&info);
    info.cipherType = HITLS_CBC_CIPHER;
    g_cbcFuncs = *RecGetCryptoFuncs(&info);
}

// Get original crypto functions based on suite info
static RecCryptoFunc *RecGetOriginCryptFuncs(const RecConnSuitInfo *suiteInfo)
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

// Wrapper for decrypt function - intercepts incoming messages during decryption
static int32_t WrapperDecryptFunc(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    int32_t ret = RecGetOriginCryptFuncs(state->suiteInfo)->decrypt(ctx, state, cryptMsg, data, dataLen);

    // FIXED: Removed IS_SUPPORT_DATAGRAM check to support TLS (not just DTLS)
    if (ret == HITLS_SUCCESS && g_enableWrapper && g_recWrapper.isRecRead) {
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

// Wrapper for decrypt post-process - additional message modification point
static int32_t WrapperDecryptPostProcess(TLS_Ctx *ctx, RecConnSuitInfo *suitInfo, REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    int32_t ret = RecGetOriginCryptFuncs((const RecConnSuitInfo *)suitInfo)->decryptPostProcess(ctx, suitInfo, cryptMsg, data, dataLen);

    // No DTLS restriction here - supports both TLS and DTLS
    if (ret == HITLS_SUCCESS && g_enableWrapper && g_recWrapper.isRecRead) {
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

// Wrapper for plaintext buffer length calculation
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

// STUB replacement for RecGetCryptoFuncs - returns modified function table
static const RecCryptoFunc *Stub_RecCrypto(const RecConnSuitInfo *suiteInfo)
{
    static RecCryptoFunc recCryptoFunc = { 0 };
    recCryptoFunc = *RecGetOriginCryptFuncs(suiteInfo);
    recCryptoFunc.calPlantextBufLen = WrapperCalPlantextBufLenFunc;
    recCryptoFunc.decrypt = WrapperDecryptFunc;
    recCryptoFunc.decryptPostProcess = WrapperDecryptPostProcess;
    return &recCryptoFunc;
}

// ============================================================================
// Framework API
// ============================================================================

void RegisterWrapper(RecWrapper wrapper)
{
    // If there's already an active wrapper, clear it first
    if (g_recWrapper.func != NULL) {
        ClearWrapper();
    }

    // Store wrapper configuration globally
    g_recWrapper = wrapper;

    // Choose mechanism based on wrapper type
    if (wrapper.isRecRead) {
        // READ wrappers: Use STUB mechanism to intercept decrypt functions
        FRAME_InitRecCrypto();
        STUB_REPLACE(RecGetCryptoFuncs, Stub_RecCrypto);  // New framework API
        g_enableWrapper = true;
    } else {
        // WRITE wrappers: Use function pointer replacement
        // Apply to all existing connections (enables late registration)
        pthread_mutex_lock(&g_connectionMutex);
        for (int i = 0; i < g_connectionCount; i++) {
            ApplyWrapperToConnectionEarly(g_allConnections[i]);
        }
        pthread_mutex_unlock(&g_connectionMutex);
    }
}

void ClearWrapper(void)
{
    // Reset STUB mechanism (if active for read wrappers)
    if (g_enableWrapper) {
        STUB_RESTORE(RecGetCryptoFuncs);
        g_enableWrapper = false;
    }

    // Clear all per-connection wrapper contexts from mapping table
    pthread_mutex_lock(&g_mappingMutex);
    for (int i = 0; i < g_mappingCount; i++) {
        if (g_ctxMappings[i].wrapper != NULL) {
            // Restore original function pointer if recCtx still exists
            if (g_ctxMappings[i].ctx != NULL && g_ctxMappings[i].ctx->recCtx != NULL) {
                g_ctxMappings[i].ctx->recCtx->recWrite = g_ctxMappings[i].wrapper->originalRecWrite;
            }
            // Free wrapper context
            BSL_SAL_Free(g_ctxMappings[i].wrapper);
            g_ctxMappings[i].wrapper = NULL;
        }
    }
    g_mappingCount = 0;
    pthread_mutex_unlock(&g_mappingMutex);

    // Clear global wrapper configuration (sets func to NULL)
    (void)memset(&g_recWrapper, 0, sizeof(RecWrapper));
}

void ClearConnectionList(void)
{
    // Clear the connection tracking list to prevent state leakage between tests
    pthread_mutex_lock(&g_connectionMutex);
    g_connectionCount = 0;
    (void)memset(g_allConnections, 0, sizeof(g_allConnections));
    pthread_mutex_unlock(&g_connectionMutex);
}
