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

#ifndef REC_WRAPPER_H
#define REC_WRAPPER_H
#include "rec.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief REC_read, REC_write read/write callback
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN/OUT] Read/write buffer
 * @param   bufLen [IN/OUT] Reads and writes len bytes
 * @param   bufSize [IN] Maximum buffer size
 * @param   userData [IN/OUT] User-defined data
 */
typedef void (*WrapperFunc)(TLS_Ctx *ctx, uint8_t *buf, uint32_t *bufLen, uint32_t bufSize, void* userData);

typedef struct {
    HITLS_HandshakeState ctrlState;
    REC_Type recordType;
    bool isRecRead;
    void *userData;
    WrapperFunc func;
} RecWrapper;

void RegisterWrapper(RecWrapper wrapper);
void ClearWrapper(void);

// Apply registered wrapper to a specific TLS connection
// Called internally by HLT framework after creating each connection
void ApplyWrapperToConnection(TLS_Ctx *ctx);

// Early wrapper application - initializes recCtx if needed before first HITLS_Connect
// This solves the timing issue: wrapper applied BEFORE ClientHello is sent
void ApplyWrapperToConnectionEarly(TLS_Ctx *ctx);

// Remove wrapper from a specific TLS connection
// Called when connection is destroyed to clean up resources
void RemoveWrapperFromConnection(TLS_Ctx *ctx);

// Register a connection for late wrapper application
// Called by FRAME_CreateLink to enable RegisterWrapper to apply to existing connections
void RegisterConnection(TLS_Ctx *ctx);

// Unregister a connection from tracking
// Called by FRAME_FreeLink during cleanup
void UnregisterConnection(TLS_Ctx *ctx);

// Check if wrapper is currently enabled
// Returns true if RegisterWrapper has been called and wrapper is active
bool IsWrapperEnabled(void);

// Clear connection tracking list - called during test cleanup to prevent state leakage
// This should be called by HLT_FreeAllProcess() to clear connections between tests
void ClearConnectionList(void);

#ifdef __cplusplus
}
#endif

#endif // REC_WRAPPER_H