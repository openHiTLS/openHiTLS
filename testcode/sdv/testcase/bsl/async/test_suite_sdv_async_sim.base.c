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

/*
 * Shared base of the async simulation provider SDV suites. Spliced into every
 * generated group source through the INCLUDE_BASE directive; only includes,
 * macros and non-static fixtures live here.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "bsl_async.h"
#include "frame_async.h"
#include "hitls_session.h"
#include "hitls_error.h"
#include "sim_prov_ctrl.h"
#include "crypto_test_util.h"

/* Feature guard: suites under this base require the dynamic provider path */
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER)
#define ASYNC_SIM_SKIP() SKIP_TEST()
#else
#define ASYNC_SIM_SKIP()
#endif

/* Coroutine backend availability for the pause-path cases */
#define ASYNC_SIM_BACKEND_READY() (BSL_ASYNC_IsSupported())

/* Config factory for every suite under this base: the server issues no session
 * ticket, so a handshake leaves no post-handshake flight behind. The memory UIO
 * keeps one pending blob per direction, and the suites drive the pair to
 * TLS_CONNECTED without settling that flight afterwards. */
static inline HITLS_Config *AsyncSimNewTls13Config(CRYPT_EAL_LibCtx *libCtx)
{
    HITLS_Config *config = HITLS_CFG_ProviderNewTLS13Config(libCtx, FRAME_ASYNC_PROVIDER_ATTR);
    if (config == NULL) {
        return NULL;
    }
    if (HITLS_CFG_SetTicketNums(config, 0) != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    return config;
}

/* Shared-state wrapper: the TaskParam snapshot copies the pointer value only
 * (one-way), so every fixture that must exchange data with its host across a
 * scheduling boundary receives this wrapper and dereferences it, instead of
 * relying on inline fields of the snapshot itself (those flow caller-to-task
 * only and are never copied back). */
typedef struct {
    void *shared;
} ArgRef;

/* Load the provider with the compiled-in output path and bring the thread up.
 * Also initializes the DRBG globally and on the frame libCtx: delegated key
 * generation (ECDH/ECDSA/RSA) draws randomness through the global channel
 * because the delegate layer runs with a NULL libCtx (no recursion). */
static int32_t AsyncSimSetup(uint32_t maxTasks, uint32_t initialTasks)
{
    int32_t ret = FRAME_ASYNC_InitThread(maxTasks, initialTasks);
    if (ret != FRAME_ASYNC_SUCCESS) {
        return ret;
    }
    ret = FRAME_ASYNC_LoadProvider(NULL);
    if (ret != FRAME_ASYNC_SUCCESS) {
        (void)FRAME_ASYNC_CleanupThread();
        return ret;
    }
    if (TestRandInit() != 0) {
        (void)FRAME_ASYNC_UnloadProvider();
        (void)FRAME_ASYNC_CleanupThread();
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    if (TestRandInitEx(FRAME_ASYNC_GetLibCtx()) != 0) {
        (void)FRAME_ASYNC_UnloadProvider();
        (void)FRAME_ASYNC_CleanupThread();
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    return FRAME_ASYNC_SUCCESS;
}

static void AsyncSimTeardown(void)
{
    (void)FRAME_ASYNC_UnloadProvider();
    (void)FRAME_ASYNC_CleanupThread();
}
