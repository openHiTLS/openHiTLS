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

#include "ecc_local.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"

#define FLAG_EMPTY_MASK 1
#define FLAG_ACC_MODE_MASK 2

typedef struct MSM_ContextStruct {
    ECC_Para *para;
    ECC_Point **buckets;
    ECC_Point **afpoints;
    const BN_BigNum **scalars;
    const ECC_Point **points;
    ECC_Point *acc;
    ECC_Point *running;
    uint8_t *empty_flags;

    uint32_t n;
    uint32_t w;
    uint32_t bits;
    uint32_t numBuckets;

    uint8_t acc_empty;
} MSM_Ctx_t;

uint32_t BN_WindowGet(const BN_BigNum *a, uint32_t offset, uint32_t w)
{
    uint32_t val = 0;
    for (uint32_t i = 0; i < w; i++) {
        if (BN_GetBit(a, offset + i)) {
            val |= (1u << i);
        }
    }
    return val;
}

static double estimate_total_ops(uint32_t bits, size_t n, uint32_t w)
{
    double epsilon = 1e-5;
    double windows = (bits + w - 1) / ((double)(w) + epsilon);
    double expectedNonzero = (double)n * (1.0 - 1.0 / (double)(1u << w));
    double buckets = (double)(1u << w);
    return (double)windows * (expectedNonzero + buckets);
}

/* choose w in [1, max_w] that minimizes the estimate */
static uint32_t choose_window(uint32_t bits, size_t n)
{
    const uint32_t max_w = 12; /* limit to reasonable window sizes; tune if necessary */
    uint32_t best_w = 1;
    double bestScore = estimate_total_ops(bits, n, best_w);
    for (uint32_t w = 2; w <= max_w; ++w) {
        double s = estimate_total_ops(bits, n, w);
        if (s < bestScore) {
            bestScore = s;
            best_w = w;
        }
    }
    return best_w;
}

static int32_t build_ctx(MSM_Ctx_t *ctx)
{
    int32_t ret = CRYPT_SUCCESS;

    ctx->acc_empty = FLAG_EMPTY_MASK | FLAG_ACC_MODE_MASK;
    ctx->bits = ECC_ParaBits(ctx->para);
    ctx->w = choose_window(ctx->bits, ctx->n);
    ctx->numBuckets = (1u << ctx->w);

    ctx->empty_flags = (uint8_t *)BSL_SAL_Malloc(ctx->numBuckets);
    ctx->acc = ECC_NewPoint(ctx->para);
    ctx->running = ECC_NewPoint(ctx->para);
    ctx->buckets = (ECC_Point **)BSL_SAL_Calloc(ctx->numBuckets, sizeof(ECC_Point *));
    ctx->afpoints = (ECC_Point **)BSL_SAL_Calloc(ctx->n, sizeof(ECC_Point *));

    if (ctx->acc == NULL || ctx->running == NULL
    || ctx->empty_flags == NULL || ctx->buckets == NULL || ctx->afpoints == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
    }

    return ret;
}

static int32_t init_buckets_afpoints(MSM_Ctx_t *ctx)
{
    ECC_Para *para = ctx->para;
    ECC_Point **buckets = ctx->buckets;
    ECC_Point **afpoints = ctx->afpoints;
    const ECC_Point **points = ctx->points;
    uint32_t n = ctx->n;
    uint32_t numBuckets = ctx->numBuckets;

    if (para == NULL || buckets == NULL || afpoints == NULL || points == NULL || n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_SUCCESS;
    
    for (uint32_t i = 0; i < numBuckets; i++) {
        buckets[i] = ECC_NewPoint(para);
        if (buckets[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    for (uint32_t i = 0; i < n; i++) {
        afpoints[i] = ECC_NewPoint(para);
        if (afpoints[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        GOTO_ERR_IF_EX(para->method->point2Affine(para, afpoints[i], points[i]), ret);
    }

ERR:
    return ret;
}

int32_t accumulate_point(ECC_Para *para, ECC_Point *acc, ECC_Point *pt, uint8_t *flag)
{
    int32_t ret = CRYPT_SUCCESS;
    uint8_t f = *flag;
    if (f & FLAG_EMPTY_MASK) {
        GOTO_ERR_IF_EX(ECC_CopyPoint(acc, pt), ret);
        *flag = (f & 0xFE);
    } else {
        if (f & FLAG_ACC_MODE_MASK) {
            GOTO_ERR_IF_EX(para->method->pointAdd(para, acc, acc, pt), ret);
        } else {
            GOTO_ERR_IF_EX(para->method->pointAdd(para, acc, pt, acc), ret);
        }
    }

ERR:
    return ret;
}

static int32_t process_single_window(MSM_Ctx_t *ctx, int32_t k)
{
    int32_t ret = CRYPT_SUCCESS;
    ECC_Para *para = ctx->para;
    ECC_Point *acc = ctx->acc;
    ECC_Point *running = ctx->running;
    ECC_Point **buckets = ctx->buckets;
    ECC_Point **afpoints = ctx->afpoints;
    const BN_BigNum **scalars = ctx->scalars;
    
    uint8_t *empty_flags = ctx->empty_flags;
    
    uint32_t n = ctx->n;
    uint32_t numBuckets = ctx->numBuckets;

    uint32_t cur_w;
    uint32_t start;
    if ((int32_t)k > (int32_t)ctx->w) {
        start = (uint32_t)(k - (int32_t)ctx->w);
        cur_w = ctx->w;
    } else {
        start = 0;
        cur_w = (uint32_t)k;
    }

    // shift accumulator by 2^cur_wf
    for (uint32_t d = (ctx->acc_empty & FLAG_EMPTY_MASK) ? cur_w : 0; d < cur_w; d++) {
        GOTO_ERR_IF_EX(para->method->pointDouble(para, acc, acc), ret); // doubling
    }

    /* initialize buckets as empty */
    for (uint32_t i = 1; i < numBuckets; i++) {
        empty_flags[i] = FLAG_EMPTY_MASK | FLAG_ACC_MODE_MASK; /* 1 means empty/infinity */
    }

    /* fill buckets according to window digits */
    for (uint32_t i = 0; i < n; i++) {
        uint32_t digit = BN_WindowGet(scalars[i], start, cur_w);
        if (digit == 0) continue;
        GOTO_ERR_IF_EX(accumulate_point(para, buckets[digit], afpoints[i], &empty_flags[digit]), ret);
    }

    // scan buckets high->low
    uint8_t running_empty = FLAG_EMPTY_MASK;
    for (uint32_t b = numBuckets - 1; b > 0; b--) {
        if ((empty_flags[b] & FLAG_EMPTY_MASK) == 0) {
            GOTO_ERR_IF_EX(accumulate_point(para, running, buckets[b], &running_empty), ret);
            GOTO_ERR_IF_EX(para->method->point2Affine(para, running, running), ret);
        }

        // add running to accumulator
        if ((running_empty & FLAG_EMPTY_MASK) == 0) {
            GOTO_ERR_IF_EX(accumulate_point(para, acc, running, &ctx->acc_empty), ret);
        }
    }
    // end window

ERR:
    return ret;
}

static void destroy_ctx(MSM_Ctx_t *ctx)
{
    uint32_t numBuckets = ctx->numBuckets;
    uint32_t n = ctx->n;
    
    if (ctx->buckets != NULL) {
        for (uint32_t i = 0; i < numBuckets; i++) {
            ECC_FreePoint(ctx->buckets[i]);
        }
    }
    if (ctx->afpoints != NULL) {
        for (uint32_t i = 0; i < n; i++) {
            ECC_FreePoint(ctx->afpoints[i]);
        }
    }

    BSL_SAL_FREE(ctx->buckets);
    BSL_SAL_FREE(ctx->afpoints);
    BSL_SAL_FREE(ctx->empty_flags);
    ECC_FreePoint(ctx->acc);
    ECC_FreePoint(ctx->running);
}

int32_t ECC_MSM(ECC_Para *para, ECC_Point *r,
                const BN_BigNum **scalars, const ECC_Point **points, uint32_t n)
{
    if (para == NULL || r == NULL || scalars == NULL || points == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    int32_t ret = CRYPT_SUCCESS;

    MSM_Ctx_t ctx = {
        .para = para,
        .scalars = scalars,
        .points = points,
        .n = n
    };
    GOTO_ERR_IF_EX(build_ctx(&ctx), ret);

    GOTO_ERR_IF_EX(init_buckets_afpoints(&ctx), ret);

    // Process scalars in windows
    int32_t w = (int32_t)ctx.w;
    for (int32_t k = (int32_t)ctx.bits; k > 0; k -= w) {
        GOTO_ERR_IF_EX(process_single_window(&ctx, k), ret);
    }

    // copy accumulator to output r
    if ((ctx.acc_empty & FLAG_EMPTY_MASK) == 0) {
        GOTO_ERR_IF_EX(para->method->point2Affine(para, r, ctx.acc), ret);
    } else {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        ret = CRYPT_ECC_POINT_AT_INFINITY;
    }

ERR:
    destroy_ctx(&ctx);
    return ret;
}
