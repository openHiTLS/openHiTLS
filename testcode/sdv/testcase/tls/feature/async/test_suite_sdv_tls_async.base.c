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

/* Shared helpers of the protocol-async interface suites. Functional
 * pause/resume cases are deferred until the async test framework is ready;
 * this group only exercises the public interface contracts. */

#include "hitls_build.h"

#include <stdint.h>
#include "bsl_async.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_sal.h"
#include "frame_tls.h"

static int32_t TestAsyncCallbackOne(HITLS_Ctx *ctx, void *arg)
{
    (void)ctx;
    (void)arg;
    return HITLS_SUCCESS;
}

static int32_t TestAsyncCallbackTwo(HITLS_Ctx *ctx, void *arg)
{
    (void)ctx;
    (void)arg;
    return HITLS_SUCCESS;
}
