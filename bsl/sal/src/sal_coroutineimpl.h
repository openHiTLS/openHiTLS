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

#ifndef SAL_COROUTINEIMPL_H
#define SAL_COROUTINEIMPL_H

#include <stdint.h>
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Internal constants of the coroutine backends. Not part of any public
 * contract: the bsl async core passes the concrete stack size of its
 * execution domain (the caller's BSL_ASYNC_InitThread parameter, with 0
 * already resolved to the bsl async internal default of 32 KiB), and the
 * backend defends itself with these bounds (values below the internal minimum or above the internal maximum fail
 * with BSL_INVALID_ARG).
 *
 * The minimum is one 4 KiB page so that "page size + 1" stays acceptable on
 * every POSIX page size (4 KiB Linux up to 16 KiB Apple Silicon); the mapping
 * is always rounded up to whole pages plus two guard pages anyway.
 */
#define BSL_SAL_COROUTINE_MIN_STACK_SIZE ((uint32_t)4096)
#define BSL_SAL_COROUTINE_MAX_STACK_SIZE ((uint32_t)(8 * 1024 * 1024))

/*
 * Backend-local default for a direct zero-sized request. The framework
 * always passes its concrete value, so this only covers SAL-internal callers.
 */
#define BSL_SAL_COROUTINE_DEFAULT_STACK_SIZE ((uint32_t)(32 * 1024))

/*
 * Callback backend of the coroutine dispatch layer: a platform registers
 * this set through BSL_SAL_CallBack_Ctrl to replace the built-in backend
 * (for example a fiber or RTOS task implementation where no ucontext
 * backend is built). The set is one backend and takes effect only when
 * complete: while any callback is unregistered the built-in backend keeps
 * serving, and BSL_ASYNC_Coroutine objects belong to the backend that
 * created them and cannot be mixed across backends.
 */
typedef struct {
    BslSalCoroutineIsSupported pfIsSupported;
    BslSalCoroutineInitCurrent pfInitCurrent;
    BslSalCoroutineCreate pfCreate;
    BslSalCoroutineSwitch pfSwitch;
    BslSalCoroutineDestroy pfDestroy;
} BSL_SAL_CoroutineCallback;

/**
 * @brief Register or clear one coroutine backend callback.
 * @param type [IN] Callback function type, one of the
 * BSL_SAL_COROUTINE_*_CB_FUNC values.
 * @param funcCb [IN] Pointer to the callback function; NULL clears it.
 * @return BSL_SUCCESS on success, BSL_SAL_ERR_BAD_PARAM when type is outside
 * the coroutine callback group.
 * @note The set takes effect only when all five callbacks are registered;
 * clearing any one slot deactivates the whole set.
 */
int32_t SAL_CoroutineCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);

#ifdef __cplusplus
}
#endif

#endif
