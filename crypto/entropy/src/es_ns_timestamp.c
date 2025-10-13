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
#include "es_noise_source.h"

#define TIME_STAMP_ENTROPY_RCT_CUT_OFF 5
#define TIME_STAMP_ENTROPY_APT_WINDOW_SIZE 512
#define TIME_STAMP_ENTROPY_APT_CUT_OFF 39

static int32_t ES_TimeStampRead(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    if (buf == NULL || bufLen == 0) {
        return -1;
    }
    (void)ctx;
    (void)timeout;
    for (uint32_t i = 0; i < bufLen; i++) {
        buf[i] = BSL_SAL_TIME_GetNSec() & 0xFF;
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

    ctx->para = NULL;
    ctx->init = NULL;
    ctx->read = ES_TimeStampRead;
    ctx->deinit = NULL;
    ctx->minEntropy = 5; // one byte bring 5 bits entropy
    ctx->state.rctCutoff = TIME_STAMP_ENTROPY_RCT_CUT_OFF;
    ctx->state.aptCutOff = TIME_STAMP_ENTROPY_APT_CUT_OFF;
    ctx->state.aptWindowSize = TIME_STAMP_ENTROPY_APT_WINDOW_SIZE;
    return ctx;
}
#endif