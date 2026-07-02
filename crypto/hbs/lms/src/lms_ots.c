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
#ifdef HITLS_CRYPTO_HSS_LMS

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "lms_internal.h"

int32_t LmOtsChain(uint8_t *buffer, uint32_t start, uint32_t steps, const LmsOtsCtx *ctx, uint32_t k)
{
    for (uint32_t j = start; j < start + steps; j++) {
        int32_t ret = ctx->hashFuncs->chainHash(ctx, k, j, buffer, buffer);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return CRYPT_SUCCESS;
}

uint32_t LmOtsCoef(const uint8_t *Q, uint32_t i, uint32_t w)
{
    uint32_t index = (i * w) / LMS_BITS_PER_BYTE;
    uint32_t digitsPerByte = LMS_BITS_PER_BYTE / w;
    uint32_t shift = w * (~i & (digitsPerByte - 1));
    uint32_t mask = (1 << w) - 1;

    return (Q[index] >> shift) & mask;
}

static uint16_t LmOtsComputeChecksum(const uint8_t *Q, uint32_t qLen, uint32_t w, uint32_t ls)
{
    uint32_t sum = 0;
    uint32_t u = LMS_BITS_PER_BYTE * qLen / w;
    uint32_t maxDigit = (1 << w) - 1;

    for (uint32_t i = 0; i < u; i++) {
        sum += maxDigit - LmOtsCoef(Q, i, w);
    }

    return (uint16_t)(sum << ls);
}

uint32_t LmOtsGetSigLen(uint32_t otsType)
{
    LmOtsParams params;
    if (LmOtsLookupParamSet(otsType, &params) != CRYPT_SUCCESS) {
        return 0;
    }
    return LMS_TYPE_LEN + params.n + params.p * params.n;
}

int32_t LmOtsComputeQ(uint8_t *Q, const LmsOtsCtx *ctx, const uint8_t *C, const uint8_t *message,
    uint32_t messageLen)
{
    if (messageLen > LMS_MAX_MESSAGE_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    LmsTreeCtx treeCtx = {.I = ctx->I, .n = ctx->n, .hashFuncs = ctx->hashFuncs};

    int32_t ret = ctx->hashFuncs->msgHash(&treeCtx, ctx->q, C, message, messageLen, Q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Uint16ToByte(LmOtsComputeChecksum(Q, ctx->n, ctx->w, ctx->ls), &Q[ctx->n]);
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_HSS_LMS */
