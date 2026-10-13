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

/**
 * @defgroup hitls_async
 * @ingroup tls
 * @brief TLS transparent async interfaces
 */

#ifndef HITLS_ASYNC_H
#define HITLS_ASYNC_H

#include <stdint.h>
#include "hitls_type.h"
#include "bsl_async.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_async
 * @brief   Application completion callback of the transparent async mode.
 *
 * Unlike BSL_ASYNC_NotifyCallback, this callback receives the connection
 * handle; the protocol layer installs an internal bridge that adapts the two
 * conventions. The callback only posts the connection to the application
 * queue; it must be short and non-blocking, must not resume the task nor call
 * any HITLS API.
 */
typedef int32_t (*HITLS_AsyncCallback)(HITLS_Ctx *ctx, void *arg);

/**
 * @ingroup hitls_async
 * @brief   Set the completion callback of the transparent async mode.
 *
 * @param   ctx  [IN] TLS connection Handle.
 * @param   callback  [IN] Callback to install; NULL clears it together with arg.
 * @param   arg  [IN] Argument passed through to the callback; must be NULL when callback is NULL.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 * @retval  HITLS_INVALID_INPUT, callback is NULL while arg is not.
 * @retval  HITLS_ASYNC_ERR_OPERATION_BUSY, an outstanding async task exists.
 * @attention Must be called while no async task is outstanding on the connection.
 */
int32_t HITLS_SetAsyncCallback(HITLS_Ctx *ctx, HITLS_AsyncCallback callback, void *arg);

/**
 * @ingroup hitls_async
 * @brief   Query the completion callback of the transparent async mode.
 *
 * @param   ctx  [IN] TLS connection Handle.
 * @param   callback  [OUT] Current callback; NULL when not configured.
 * @param   arg  [OUT] Current callback argument; NULL when not configured.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, a mandatory parameter is null.
 */
int32_t HITLS_GetAsyncCallback(const HITLS_Ctx *ctx, HITLS_AsyncCallback *callback, void **arg);

/**
 * @ingroup hitls_async
 * @brief   Query the submit status published by the crypto producer before the pause.
 *
 * The output uses the unified BSL submit-status macros
 * (BSL_ASYNC_NOTIFY_STATUS_UNSUPPORTED / _ERR / _OK / _EAGAIN).
 *
 * @param   ctx  [IN] TLS connection Handle.
 * @param   status  [OUT] Submit status of the current request.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, a mandatory parameter is null.
 * @retval  HITLS_ASYNC_ERR_NOT_PAUSED, no async task is paused on the connection.
 * @attention Valid after a protocol API returned HITLS_ASYNC_ERR_PAUSED.
 */
int32_t HITLS_GetAsyncStatus(const HITLS_Ctx *ctx, int32_t *status);

/**
 * @ingroup hitls_async
 * @brief   List all async notify handles of the connection.
 *
 * @param   ctx  [IN] TLS connection Handle.
 * @param   handleList  [OUT] BSL unified output list; handles == NULL only counts the required number.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, a mandatory parameter is null.
 * @retval  HITLS_INVALID_INPUT, handles is NULL while capacity is not 0.
 * @retval  HITLS_ASYNC_ERR_NOT_PAUSED, no async task is paused on the connection.
 * @retval  HITLS_ASYNC_ERR_SMALL_BUFFER, capacity is insufficient; numHandles carries the need.
 */
int32_t HITLS_GetAllAsyncNotifyHandles(const HITLS_Ctx *ctx, BSL_ASYNC_NotifyHandleList *handleList);

/**
 * @ingroup hitls_async
 * @brief   Read the current change window of the async notify handles.
 *
 * @param   ctx  [IN] TLS connection Handle.
 * @param   addList  [OUT] BSL unified list receiving added handles; handles == NULL only counts.
 * @param   delList  [OUT] BSL unified list receiving removed handles; handles == NULL only counts.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, a mandatory parameter is null.
 * @retval  HITLS_ASYNC_ERR_NOT_PAUSED, no async task is paused on the connection.
 * @retval  HITLS_ASYNC_ERR_SMALL_BUFFER, a list capacity is insufficient; numHandles carries the need.
 */
int32_t HITLS_GetChangedAsyncNotifyHandles(const HITLS_Ctx *ctx, BSL_ASYNC_NotifyHandleList *addList,
                                           BSL_ASYNC_NotifyHandleList *delList);

/**
 * @ingroup hitls_async
 * @brief   Set the async completion callback inherited by connections created from this config.
 * @param   config  [IN] Config handle.
 * @param   callback  [IN] Callback to install; NULL clears it together with arg.
 * @param   arg  [IN] Argument passed through to the callback; must be NULL when callback is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 * @retval  HITLS_INVALID_INPUT, callback is NULL while arg is not.
 */
int32_t HITLS_CFG_SetAsyncCallback(HITLS_Config *config, HITLS_AsyncCallback callback, void *arg);

/**
 * @ingroup hitls_async
 * @brief   Query the async completion callback of the config.
 * @param   config  [IN] Config handle.
 * @param   callback  [OUT] Current callback; NULL when not configured.
 * @param   arg  [OUT] Current callback argument; NULL when not configured.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, a mandatory parameter is null.
 */
int32_t HITLS_CFG_GetAsyncCallback(const HITLS_Config *config, HITLS_AsyncCallback *callback, void **arg);

#ifdef __cplusplus
}
#endif

#endif
