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

#ifndef CONN_ASYNC_H
#define CONN_ASYNC_H

#include "hitls_build.h"

#ifdef HITLS_TLS_FEATURE_MODE_ASYNC

#include <stdint.h>
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Internal workers: the bodies of the public protocol entries, executed on the
 * async task stack (or synchronously when the async mode is off). */
int32_t HITLS_ConnectInternal(HITLS_Ctx *ctx);
int32_t HITLS_AcceptInternal(HITLS_Ctx *ctx);
int32_t HITLS_DoHandShakeInternal(HITLS_Ctx *ctx);
int32_t HITLS_ReadInternal(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen);
int32_t HITLS_PeekInternal(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen);
int32_t HITLS_WriteInternal(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen);

/* Async outer controller: called by the public wrappers with the unified args.
 * Starts or resumes the BSL task when the async mode is on, dispatches
 * directly otherwise. */
int32_t HITLS_AsyncRun(const HITLS_ASYNC_ARGS *args);

/* Internal bridge adapting the BSL wakeup callback convention (non-zero on
 * successful posting) to the application HITLS_AsyncCallback. */
int32_t HITLS_AsyncNotifyBridge(void *arg);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_TLS_FEATURE_MODE_ASYNC */

#endif /* CONN_ASYNC_H */
