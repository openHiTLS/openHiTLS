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
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)

#include <stdint.h>
#include <string.h>
#if defined(HITLS_BSL_SAL_DARWIN)
#include <sys/sysctl.h>
#else
#include <unistd.h>
#endif
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "es_noise_source.h"
#include "es_ns_delta_common.h"

#ifndef HITLS_CACHE_LINE_SIZE
#define HITLS_CACHE_LINE_SIZE 64
#endif
/* Iteration anchor for NS_CACHE_WALK_LOOPS; region size is set by
   ES_CpuJitterRegionBytes. */
#ifndef HITLS_CACHE_ROW_COUNT
#define HITLS_CACHE_ROW_COUNT 1025
#endif
#if (HITLS_CACHE_LINE_SIZE == 0)
#error "HITLS_CACHE_LINE_SIZE must be greater than 0"
#endif
#if (HITLS_CACHE_LINE_SIZE % 2) != 0
#error "HITLS_CACHE_LINE_SIZE must be even: the walk stride (line size - 1) must be odd to cover a power-of-two region fully"
#endif
#if (HITLS_CACHE_ROW_COUNT == 0)
#error "HITLS_CACHE_ROW_COUNT must be greater than 0"
#endif

/* Claimed min-entropy h = 1/HITLS_JITTER_OSR bit per delta; default 3 holds
   the weakest supported platform with margin. Cutoffs come from the per-osr
   table in ES_DeltaOsrCutoffs (alpha = 2^-20). */
#if defined(HITLS_JITTER_MINENTROPY) || defined(HITLS_JITTER_CLAIM_FLOOR) || \
    defined(HITLS_JITTER_RCT_CUT_OFF) || defined(HITLS_JITTER_APT512_CUT_OFF) || \
    defined(HITLS_JITTER_APT_CUT_OFF)
#error "per-byte claim config retired: define HITLS_JITTER_OSR (deltas per entropy bit) instead"
#endif
#ifndef HITLS_JITTER_OSR
#define HITLS_JITTER_OSR 3
#endif
#if (HITLS_JITTER_OSR < NS_DELTA_OSR_MIN) || (HITLS_JITTER_OSR > NS_DELTA_OSR_MAX)
#error "HITLS_JITTER_OSR must be in the range [3, 15] (claims are capped at h = 1/3)"
#endif
#ifndef HITLS_JITTER_OSR_MAX
#define HITLS_JITTER_OSR_MAX NS_DELTA_OSR_MAX
#endif
#if (HITLS_JITTER_OSR_MAX < HITLS_JITTER_OSR) || (HITLS_JITTER_OSR_MAX > NS_DELTA_OSR_MAX)
#error "HITLS_JITTER_OSR_MAX must be in the range [HITLS_JITTER_OSR, 15]"
#endif

#ifdef HITLS_JITTER_MEM_BYTES
#if (HITLS_JITTER_MEM_BYTES & (HITLS_JITTER_MEM_BYTES - 1)) != 0
#error "HITLS_JITTER_MEM_BYTES must be a power of two"
#endif
#if (HITLS_JITTER_MEM_BYTES < 0x1000) || (HITLS_JITTER_MEM_BYTES > 0x100000)
#error "HITLS_JITTER_MEM_BYTES must be in [4KiB, 1MiB]"
#endif
#endif

/* Detected-L1d path: floor and cap bounding the 2 x L1d rule. */
#define NS_MEM_REGION_FLOOR (64U * 1024U)
#define NS_MEM_REGION_CAP (1024U * 1024U)
/* No-detection fallback: fixed 256 KiB region when L1d size is unknown. */
#define NS_MEM_REGION_DEFAULT (256U * 1024U)

typedef struct ES_JitterState {
    ES_DeltaNs ns; /* shared delta health state; must stay first */
    uint8_t *mem; /* walk region, memSize bytes, power of two */
    uint32_t memSize;
    volatile uint32_t mID;
} ES_JitterState;

/* L1d probe for the walk region, module-local like ES_NsTickGet: the measured
   workload owns its platform detail. Zero means no detection path exists and
   the caller falls back to the fixed default region. */
uint32_t ES_CpuJitterL1dCacheSize(void)
{
#if defined(HITLS_BSL_SAL_DARWIN)
    /* Prefer the performance-core value on heterogeneous SoCs: the walk
       region must exceed the largest L1d it may be scheduled onto; plain
       hw.l1dcachesize reports the efficiency-core size on Apple Silicon. */
    uint64_t bytes = 0;
    size_t len = sizeof(bytes);
    if (sysctlbyname("hw.perflevel0.l1dcachesize", &bytes, &len, NULL, 0) != 0 || bytes == 0) {
        bytes = 0;
        len = sizeof(bytes);
        (void)sysctlbyname("hw.l1dcachesize", &bytes, &len, NULL, 0);
    }
    return (bytes > UINT32_MAX) ? UINT32_MAX : (uint32_t)bytes;
#elif defined(_SC_LEVEL1_DCACHE_SIZE)
    /* glibc extension with real detection on x86 (CPUID) only: aarch64 glibc
       reports 0 and musl leaves the selector undefined, so on those targets
       zero falls through to the fixed default region size. */
    long v = sysconf(_SC_LEVEL1_DCACHE_SIZE);
    if (v <= 0) {
        return 0;
    }
    return ((uint64_t)v > UINT32_MAX) ? UINT32_MAX : (uint32_t)v;
#else
    return 0;
#endif
}

uint32_t ES_CpuJitterRegionBytes(uint32_t l1dBytes)
{
#ifdef HITLS_JITTER_MEM_BYTES
    (void)l1dBytes;
    return HITLS_JITTER_MEM_BYTES;
#else
    if (l1dBytes == 0) {
        return NS_MEM_REGION_DEFAULT;
    }
    /* A region equal to L1d fits the walk entirely in-cache and the
       miss-driven timing variance collapses; 2 x L1d keeps every access
       window in the L1-miss/L2-hit band where the variance peaks. */
    uint64_t target = (uint64_t)l1dBytes * 2;
    uint32_t size = NS_MEM_REGION_FLOOR;
    while (size < target && size < NS_MEM_REGION_CAP) {
        size <<= 1;
    }
    return size;
#endif
}

#define NS_MOVE_LEVEL 128

/* Fixed workload length: the measured duration must vary only through
   microarchitectural wait states, never through an input-derived loop bound. */
#define NS_CACHE_WALK_LOOPS (HITLS_CACHE_ROW_COUNT + NS_MOVE_LEVEL)

/* O0 guard keeps the timed walk intact under any optimizer/LTO. */
#if defined(__clang__)
static void __attribute__((optnone)) EntropyMemeryAccess(ES_JitterState *e)
#elif defined(__GNUC__)
static void __attribute__((optimize("O0"))) EntropyMemeryAccess(ES_JitterState *e)
#else
static void EntropyMemeryAccess(ES_JitterState *e)
#endif
{
    uint8_t *mem = e->mem;
    uint32_t wrap = e->memSize;

    for (uint32_t i = 0; i < NS_CACHE_WALK_LOOPS; i++) {
        /* The odd stride stays coprime to the region so every byte is
           visited. */
        volatile uint8_t *volatile cur = mem + e->mID;
        *cur = (uint8_t)((*cur + 1) & 0xff);
        e->mID = (e->mID + HITLS_CACHE_LINE_SIZE - 1) % wrap;
    }
}

/* One measurement: the timed window stays source-local so the compiled
   tick-workload-tick path is untouched by the shared pipeline. */
static void JitterMeasure(void *ctx)
{
    ES_JitterState *e = (ES_JitterState *)ctx;
    uint64_t tick1 = ES_NsTickGet();
    EntropyMemeryAccess(e);
    uint64_t tick2 = ES_NsTickGet();
    ES_DeltaNsProcessRawDelta(&e->ns, tick2 - tick1);
}

static uint64_t JitterRawDelta(void *ctx);

static int32_t ES_CpuJitterRecover(void *usrdata)
{
    if (usrdata == NULL) {
        return CRYPT_NULL_INPUT;
    }
    ES_JitterState *e = (ES_JitterState *)usrdata;
    return ES_DeltaNsRecoveryWindow(&e->ns, JitterRawDelta, JitterMeasure, e);
}

static int32_t ES_CpuJitterRead(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)timeout;
    if (ctx == NULL || buf == NULL || bufLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    return ES_DeltaNsRead(&((ES_JitterState *)ctx)->ns, JitterMeasure, ctx, buf, bufLen);
}

static void ES_CpuJitterFree(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ES_JitterState *e = (ES_JitterState *)ctx;
    if (e->mem != NULL) {
        BSL_SAL_ClearFree(e->mem, e->memSize);
    }
    BSL_SAL_ClearFree(e, sizeof(ES_JitterState));
}

/* Raw delta of one workload run, the timer-check sampler. */
static uint64_t JitterRawDelta(void *ctx)
{
    uint64_t tick1 = ES_NsTickGet();
    EntropyMemeryAccess((ES_JitterState *)ctx);
    uint64_t tick2 = ES_NsTickGet();
    return tick2 - tick1;
}

/* Allocate a calibrated state: the next measurement after this is the first
   production sample, no output has been derived yet. */
static int32_t JitterStateNew(ES_JitterState **out)
{
    ES_JitterState *e = (ES_JitterState *)BSL_SAL_Malloc(sizeof(ES_JitterState));
    if (e == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memset(e, 0, sizeof(ES_JitterState));
    e->memSize = ES_CpuJitterRegionBytes(ES_CpuJitterL1dCacheSize());
    e->mem = BSL_SAL_Malloc(e->memSize);
    if (e->mem == NULL) {
        ES_CpuJitterFree(e);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    /* Zero-fill doubles as page pre-touch so first measurements see cache
       misses, never demand-paging faults. */
    memset(e->mem, 0, e->memSize);
    int32_t ret = ES_DeltaNsTimerQualify(&e->ns, JitterRawDelta, e, HITLS_JITTER_OSR);
    if (ret != CRYPT_SUCCESS) {
        ES_CpuJitterFree(e);
        return ret;
    }
    *out = e;
    return CRYPT_SUCCESS;
}

/* Initialize one cpu-jitter state and select a supported oversampling rate.
   Failures keep their verdict: timer verdicts from calibration, walk
   exhaustion from the osr ladder, allocation errors from setup. */
static int32_t ES_CpuJitterInitAt(void *para, uint32_t startOsr, void **usrdata)
{
    (void)para;
    ES_JitterState *e = NULL;
    int32_t ret = JitterStateNew(&e);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = ES_DeltaNsOsrWalk(&e->ns, startOsr, HITLS_JITTER_OSR_MAX, JitterMeasure, e);
    if (ret != CRYPT_SUCCESS) {
        ES_CpuJitterFree(e);
        return ret;
    }
    *usrdata = e;
    return CRYPT_SUCCESS;
}

uint32_t ES_CpuJitterOsrGet(const void *usrdata)
{
    if (usrdata == NULL) {
        return 0;
    }
    return ((const ES_JitterState *)usrdata)->ns.osr;
}

ES_NoiseSource *ES_CpuJitterGetCtx(void)
{
    ES_NoiseSource *ctx = BSL_SAL_Malloc(sizeof(ES_NoiseSource));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    memset(ctx, 0, sizeof(ES_NoiseSource));
    uint32_t len = strlen("CPU-Jitter");
    ctx->name = BSL_SAL_Malloc(len + 1);
    if (ctx->name == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    (void)strcpy(ctx->name, "CPU-Jitter");
    ctx->autoTest = true;
    ctx->para = NULL;
    ctx->read = ES_CpuJitterRead;
    ctx->deinit = ES_CpuJitterFree;
    ctx->osrGet = ES_CpuJitterOsrGet;
    ctx->initAt = ES_CpuJitterInitAt;
    ctx->recover = ES_CpuJitterRecover;
    ctx->osr = HITLS_JITTER_OSR;
    ctx->osrMax = HITLS_JITTER_OSR_MAX;
    ctx->sampleBytes = NS_DELTA_RECORD_BYTES;
    ctx->claimBitsPerOsr = 1; /* numerator of the 1/osr raw-sample claim */
    ctx->credited = true;
    return ctx;
}

#endif
