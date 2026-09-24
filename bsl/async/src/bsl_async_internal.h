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

#ifndef BSL_ASYNC_INTERNAL_H
#define BSL_ASYNC_INTERNAL_H

#include "hitls_build.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*
 * Internal constants of the bsl async core. Nothing here is part of the
 * public contract in include/bsl/bsl_async.h: callers pass 0 as stackSize to
 * use the default and learn the accepted range only through BSL_INVALID_ARG.
 */

/** Expected task coroutine stack size in bytes, used when BSL_ASYNC_InitThread
 * receives stackSize == 0; matches the OpenSSL POSIX backend's fixed value.
 * The actual size, alignment, guard pages and release remain owned by the SAL
 * coroutine backend. */
#define BSL_ASYNC_DEFAULT_STACK_SIZE (32 * 1024)

/**
 * @ingroup bsl_async
 * @brief   Upper limit of the task argument copy in bytes
 */
#define BSL_ASYNC_MAX_ARGS_SIZE 1024
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // BSL_ASYNC_INTERNAL_H
