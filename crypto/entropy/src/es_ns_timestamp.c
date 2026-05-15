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

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "es_health_test.h"
#include "es_noise_source.h"

#define TIME_STAMP_ENTROPY_RCT_CUT_OFF 5
#define TIME_STAMP_ENTROPY_APT_WINDOW_SIZE 512
#define TIME_STAMP_ENTROPY_APT_CUT_OFF 20
#define TIME_STAMP_STARTUP_TEST_SIZE 1024

typedef struct {
    ES_HealthTest state;
} ES_TimeStampState;

static int32_t ES_TimeStampHealthCheck(ES_HealthTest *state, uint8_t data)
{
    int32_t ret = ES_HealthTestRct(state, data);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return ES_HealthTestApt(state, data);
}

static void *ES_TimeStampInit(void *para)
{
    (void)para;
    ES_TimeStampState *state = BSL_SAL_Calloc(1, sizeof(ES_TimeStampState));
    if (state == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    state->state.rctCutoff = TIME_STAMP_ENTROPY_RCT_CUT_OFF;
    state->state.aptCutOff = TIME_STAMP_ENTROPY_APT_CUT_OFF;
    state->state.aptWindowSize = TIME_STAMP_ENTROPY_APT_WINDOW_SIZE;

    for (uint32_t i = 0; i < TIME_STAMP_STARTUP_TEST_SIZE; i++) {
        uint8_t data = BSL_SAL_TIME_GetNSec() & 0xFF;
        int32_t ret = ES_TimeStampHealthCheck(&state->state, data);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_FREE(state);
            return NULL;
        }
    }
    return state;
}

static void ES_TimeStampDeinit(void *ctx)
{
    BSL_SAL_FREE(ctx);
}

static int32_t ES_TimeStampRead(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    ES_TimeStampState *state = (ES_TimeStampState *)ctx;
    (void)timeout;
    if (state == NULL || buf == NULL || bufLen == 0) {
        return CRYPT_NULL_INPUT;
    }

    for (uint32_t i = 0; i < bufLen; i++) {
        buf[i] = BSL_SAL_TIME_GetNSec() & 0xFF;
        int32_t ret = ES_TimeStampHealthCheck(&state->state, buf[i]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

ES_NoiseSource *ES_TimeStampGetCtx(void)
{
    ES_NoiseSource *ctx = BSL_SAL_Malloc(sizeof(ES_NoiseSource));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(ES_NoiseSource), 0, sizeof(ES_NoiseSource));
    uint32_t len = strlen("timestamp");
    ctx->name = BSL_SAL_Malloc(len + 1);
    if (ctx->name == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    (void)strncpy_s(ctx->name, len + 1, "timestamp", len);

    ctx->autoTest = true;
    ctx->para = NULL;
    ctx->init = ES_TimeStampInit;
    ctx->read = ES_TimeStampRead;
    ctx->deinit = ES_TimeStampDeinit;
    ctx->minEntropy = 5; // one byte bring 5 bits entropy
    ctx->state.rctCutoff = TIME_STAMP_ENTROPY_RCT_CUT_OFF;
    ctx->state.aptCutOff = TIME_STAMP_ENTROPY_APT_CUT_OFF;
    ctx->state.aptWindowSize = TIME_STAMP_ENTROPY_APT_WINDOW_SIZE;
    return ctx;
}
#endif