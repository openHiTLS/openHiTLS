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
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)

#include <stdint.h>
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "es_noise_source.h"
#include "es_ns_delta_common.h"
/* The workload hash is part of the measured physics and stays in this TU. The
   ES layer conditions the emitted raw samples. The workload runs the
   build-selected SHA3-256 implementation, so min-entropy evidence is collected
   per build and platform. */
#if !defined(HITLS_CRYPTO_SHA3)
#error "hash-loop source requires HITLS_CRYPTO_SHA3 (software Keccak for the pinned workload)"
#endif
#include "crypt_sha3.h"

#ifndef HITLS_HASHLOOP_ITERATIONS
/* Back-to-back SHA3-256 compressions per measurement; each is one software Keccak
   permutation plus its state cleanse. 8 iterations keeps the weakest supported
   platform above the h = 1/3 claim with margin and spans enough ticks of the
   coarsest supported timer for the delta to resolve. In-order cores may need
   more; override for those. */
#define HITLS_HASHLOOP_ITERATIONS 8
#endif
#if (HITLS_HASHLOOP_ITERATIONS < 1) || (HITLS_HASHLOOP_ITERATIONS > 1024)
#error "HITLS_HASHLOOP_ITERATIONS must be in the range [1, 1024]"
#endif

/*
 * Oversampling rate: claimed min-entropy h = 1/HITLS_HASHLOOP_OSR bit per
 * credited delta; same semantics, ladder direction and per-osr cutoff table
 * as es_ns_jitter.c, calibrated independently per source. The default osr = 3
 * sits at the claim ceiling (h = 1/3, NS_DELTA_OSR_MIN) and holds on the
 * weakest supported platform with margin.
 */
#if defined(HITLS_HASHLOOP_MINENTROPY) || defined(HITLS_HASHLOOP_CLAIM_FLOOR) || \
    defined(HITLS_HASHLOOP_RCT_CUT_OFF) || defined(HITLS_HASHLOOP_APT512_CUT_OFF)
#error "per-byte claim config retired: define HITLS_HASHLOOP_OSR (deltas per entropy bit) instead"
#endif
#ifndef HITLS_HASHLOOP_OSR
#define HITLS_HASHLOOP_OSR 3
#endif
#if (HITLS_HASHLOOP_OSR < NS_DELTA_OSR_MIN) || (HITLS_HASHLOOP_OSR > NS_DELTA_OSR_MAX)
#error "HITLS_HASHLOOP_OSR must be in the range [3, 15] (claims are capped at h = 1/3)"
#endif
#ifndef HITLS_HASHLOOP_OSR_MAX
#define HITLS_HASHLOOP_OSR_MAX NS_DELTA_OSR_MAX
#endif
#if (HITLS_HASHLOOP_OSR_MAX < HITLS_HASHLOOP_OSR) || (HITLS_HASHLOOP_OSR_MAX > NS_DELTA_OSR_MAX)
#error "HITLS_HASHLOOP_OSR_MAX must be in the range [HITLS_HASHLOOP_OSR, 15]"
#endif

#define HASHLOOP_WORK_SIZE 32

typedef struct ES_HashLoopState {
    ES_DeltaNs ns; /* shared delta health state; must stay first */
    uint8_t work[HASHLOOP_WORK_SIZE]; /* CPU-bound workload state */
} ES_HashLoopState;

/* CPU-bound workload. The optnone/O0 attribute keeps the measured loop intact
   where the compiler supports it. Each iteration is one complete SHA3-256: a
   32-byte input stays below the 136-byte rate, so Update absorbs nothing and the
   single Keccak permutation happens in the finalization, whose execution time is
   the measured noise. Neither the hashed value nor the digest earns entropy
   credit; the write-back chains the iterations so they cannot overlap. */
#if defined(__clang__)
static void __attribute__((optnone)) HashLoopWorkload(ES_HashLoopState *e)
#elif defined(__GNUC__)
static void __attribute__((optimize("O0"))) HashLoopWorkload(ES_HashLoopState *e)
#else
static void HashLoopWorkload(ES_HashLoopState *e)
#endif
{
    CRYPT_SHA3_256_Ctx ctx;
    for (uint32_t i = 0; i < HITLS_HASHLOOP_ITERATIONS; i++) {
        uint32_t len = HASHLOOP_WORK_SIZE;
        (void)CRYPT_SHA3_256_Init(&ctx);
        (void)CRYPT_SHA3_Update(&ctx, e->work, HASHLOOP_WORK_SIZE);
        (void)CRYPT_SHA3_Final(&ctx, e->work, &len);
    }
    BSL_SAL_CleanseData(&ctx, sizeof(ctx));
}

/* One measurement: the timed window stays source-local so the compiled
   tick-workload-tick path is untouched by the shared pipeline. */
static void HashLoopMeasure(void *ctx)
{
    ES_HashLoopState *e = (ES_HashLoopState *)ctx;
    uint64_t tick1 = ES_NsTickGet();
    HashLoopWorkload(e);
    uint64_t tick2 = ES_NsTickGet();
    ES_DeltaNsProcessRawDelta(&e->ns, tick2 - tick1);
}

static uint64_t HashLoopRawDelta(void *ctx);

static int32_t ES_HashLoopRecover(void *usrdata)
{
    if (usrdata == NULL) {
        return CRYPT_NULL_INPUT;
    }
    ES_HashLoopState *e = (ES_HashLoopState *)usrdata;
    return ES_DeltaNsRecoveryWindow(&e->ns, HashLoopRawDelta, HashLoopMeasure, e);
}

static int32_t ES_HashLoopRead(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)timeout;
    if (ctx == NULL || buf == NULL || bufLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    return ES_DeltaNsRead(&((ES_HashLoopState *)ctx)->ns, HashLoopMeasure, ctx, buf, bufLen);
}

static void ES_HashLoopFree(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_ClearFree(ctx, sizeof(ES_HashLoopState));
}

/* Raw delta of one workload run, the timer-check sampler. */
static uint64_t HashLoopRawDelta(void *ctx)
{
    uint64_t tick1 = ES_NsTickGet();
    HashLoopWorkload((ES_HashLoopState *)ctx);
    uint64_t tick2 = ES_NsTickGet();
    return tick2 - tick1;
}

/* Allocate a calibrated state: the next measurement after this is the first
   production sample, no output has been derived yet. */
static int32_t HashLoopStateNew(ES_HashLoopState **out)
{
    ES_HashLoopState *e = (ES_HashLoopState *)BSL_SAL_Malloc(sizeof(ES_HashLoopState));
    if (e == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memset(e, 0, sizeof(ES_HashLoopState));
    int32_t ret = ES_DeltaNsTimerQualify(&e->ns, HashLoopRawDelta, e, HITLS_HASHLOOP_OSR);
    if (ret != CRYPT_SUCCESS) {
        ES_HashLoopFree(e);
        return ret;
    }
    *out = e;
    return CRYPT_SUCCESS;
}

/* Initialize one hash-loop state and select a supported oversampling rate.
   Failures keep their verdict: timer verdicts from calibration, walk exhaustion
   from the osr ladder, allocation errors from setup. */
static int32_t ES_HashLoopInitAt(void *para, uint32_t startOsr, void **usrdata)
{
    (void)para;
    ES_HashLoopState *e = NULL;
    int32_t ret = HashLoopStateNew(&e);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = ES_DeltaNsOsrWalk(&e->ns, startOsr, HITLS_HASHLOOP_OSR_MAX, HashLoopMeasure, e);
    if (ret != CRYPT_SUCCESS) {
        ES_HashLoopFree(e);
        return ret;
    }
    *usrdata = e;
    return CRYPT_SUCCESS;
}

uint32_t ES_HashLoopOsrGet(const void *usrdata)
{
    if (usrdata == NULL) {
        return 0;
    }
    return ((const ES_HashLoopState *)usrdata)->ns.osr;
}

ES_NoiseSource *ES_HashLoopGetCtx(void)
{
    ES_NoiseSource *ctx = BSL_SAL_Malloc(sizeof(ES_NoiseSource));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    memset(ctx, 0, sizeof(ES_NoiseSource));
    uint32_t len = strlen("Hash-Loop");
    ctx->name = BSL_SAL_Malloc(len + 1);
    if (ctx->name == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    (void)strcpy(ctx->name, "Hash-Loop");
    ctx->autoTest = true;
    ctx->para = NULL;
    ctx->read = ES_HashLoopRead;
    ctx->deinit = ES_HashLoopFree;
    ctx->osrGet = ES_HashLoopOsrGet;
    ctx->initAt = ES_HashLoopInitAt;
    ctx->recover = ES_HashLoopRecover;
    ctx->osr = HITLS_HASHLOOP_OSR;
    ctx->osrMax = HITLS_HASHLOOP_OSR_MAX;
    ctx->sampleBytes = NS_DELTA_RECORD_BYTES;
    ctx->claimBitsPerOsr = 1; /* numerator of the 1/osr raw-sample claim */
    ctx->credited = true;
    return ctx;
}

#endif
