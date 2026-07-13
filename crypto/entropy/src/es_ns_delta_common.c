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
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))

#include <stdint.h>
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "es_ns_delta_common.h"

/* Developer-defined continuous test (SP800-90B 4.3 1(c)) counting consecutive
   stuck samples: delta == 0 (frozen timer), delta2 == 0 (constant delta),
   delta3 == 0 (linear ramp). The union predicate has no approved RCT alpha
   model; the per-osr cutoff is an engineering bound, intermittent tier only. */
/* The first intermittent verdict keeps its code, a permanent verdict
   overrides any intermittent one, and nothing downgrades. */
static void DeltaRecordVerdict(ES_DeltaNs *e, int8_t verdict)
{
    if (e->testFailure == NS_ENTROPY_PERMANENT_FAILURE) {
        return;
    }
    if (e->testFailure == CRYPT_SUCCESS || verdict == NS_ENTROPY_PERMANENT_FAILURE) {
        e->testFailure = verdict;
    }
}

/* Absolute value keeps the third-order term meaningful: on a zigzag like
   (100, 110, 100) the two first differences are equal in magnitude and
   opposite in sign, so |d[i] - d[i-1]| drives delta3 to zero and the stuck
   test catches the period-2 alternation. */
static uint64_t DeltaAbsDiff(uint64_t a, uint64_t b)
{
    return a > b ? a - b : b - a;
}

static void DeltaHealthStuck(ES_DeltaNs *e, uint64_t delta)
{
    uint64_t delta2 = DeltaAbsDiff(delta, e->lastDelta);
    uint64_t delta3 = DeltaAbsDiff(delta2, e->lastDelta2);
    int stuck = (delta == 0 || delta2 == 0 || delta3 == 0);
    e->lastDelta = delta;
    e->lastDelta2 = delta2;
    if (stuck == 0) {
        /* A non-stuck sample breaks the run: alarm only at the cutoff-th
           consecutive stuck sample. */
        e->stuckCount = 0;
        return;
    }
    /* Intermittent tier only; persistent degradation retires the source
       through repeated recovery. */
    if (e->stuckCutoff != 0 && e->stuckCount < e->stuckCutoff) {
        e->stuckCount++;
    }
    if (e->stuckCutoff != 0 && e->stuckCount >= e->stuckCutoff) {
        DeltaRecordVerdict(e, NS_ENTROPY_RCT_FAILURE);
    }
}

void ES_DeltaNsProcessRawDelta(ES_DeltaNs *e, uint64_t rawDelta)
{
    /* Stuck stays on the full delta: its first and second differences are only
       meaningful before truncation. */
    DeltaHealthStuck(e, rawDelta);
    uint8_t symbol = (uint8_t)(rawDelta & NS_DELTA_SYMBOL_MASK);
    if (ES_HealthTestRct(&e->rct, symbol) != CRYPT_SUCCESS) {
        DeltaRecordVerdict(e, NS_ENTROPY_RCT_FAILURE);
    }
    if (e->rct.count >= e->rctPermCutoff) {
        DeltaRecordVerdict(e, NS_ENTROPY_PERMANENT_FAILURE);
    }
    if (ES_HealthTestApt(&e->apt, symbol) != CRYPT_SUCCESS) {
        DeltaRecordVerdict(e, NS_ENTROPY_APT_FAILURE);
    }
    /* Every osr yields a non-zero bound, so a zero here means the engine was
       never configured, not a disabled tier. */
    if (e->aptPermCutoff != 0 && e->apt.count >= e->aptPermCutoff) {
        DeltaRecordVerdict(e, NS_ENTROPY_PERMANENT_FAILURE);
    }
    if (e->testFailure == NS_ENTROPY_PERMANENT_FAILURE) {
        BSL_SAL_CleanseData(&e->lastDelta, sizeof(e->lastDelta));
        BSL_SAL_CleanseData(&e->lastDelta2, sizeof(e->lastDelta2));
        BSL_SAL_CleanseData(&e->rct.lastData, sizeof(e->rct.lastData));
        BSL_SAL_CleanseData(&e->apt.base, sizeof(e->apt.base));
    }
}

static int32_t DeltaFailurePublic(int32_t ret)
{
    if (ret == NS_ENTROPY_RCT_FAILURE) {
        return CRYPT_ENTROPY_RCT_FAILURE;
    }
    if (ret == NS_ENTROPY_APT_FAILURE) {
        return CRYPT_ENTROPY_APT_FAILURE;
    }
    if (ret == NS_ENTROPY_PERMANENT_FAILURE) {
        return CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
    }
    return ret;
}

int32_t ES_DeltaNsRead(ES_DeltaNs *e, ES_DeltaMeasureFn measure, void *srcCtx, uint8_t *buf, uint32_t bufLen)
{
    /* A recorded verdict or an unconfigured engine refuses service before
       another source measurement is taken. */
    if (e->testFailure != CRYPT_SUCCESS) {
        return DeltaFailurePublic(e->testFailure);
    }
    if (e->stuckCutoff == 0) {
        return CRYPT_ENTROPY_RCT_FAILURE;
    }
    if (bufLen == 0 || (bufLen % NS_DELTA_RECORD_BYTES) != 0) {
        return CRYPT_ENTROPY_CTRL_INVALID_PARAM;
    }
    for (uint32_t off = 0; off < bufLen; off += NS_DELTA_RECORD_BYTES) {
        measure(srcCtx);
        if (e->testFailure != CRYPT_SUCCESS) {
            return DeltaFailurePublic(e->testFailure);
        }
        /* Little-endian serialization fixes the record layout across
           platforms; the evidence pipeline depends on it. */
        PUT_UINT64_LE(e->lastDelta, buf, off);
    }
    return CRYPT_SUCCESS;
}

void ES_DeltaNsOsrApply(ES_DeltaNs *e, uint32_t osr)
{
    /* Validate, then commit: an out-of-range osr records a failure and
       leaves the previous configuration untouched, so a later startup reset
       cannot clear it into a zero-cutoff (disabled-tests) state. */
    ES_DeltaCutoffs cutoffs = {0};
    if (ES_DeltaOsrCutoffs(osr, &cutoffs) != CRYPT_SUCCESS) {
        e->testFailure = NS_ENTROPY_RCT_FAILURE;
        return;
    }
    e->osr = osr;
    e->stuckCutoff = cutoffs.rctCutoff;
    e->rct.cutoff = cutoffs.rctCutoff;
    e->apt.cutoff = cutoffs.aptCutoff;
    e->apt.windowSize = NS_APT_DELTA_WINDOW_SIZE;
    e->rctPermCutoff = cutoffs.rctPermCutoff;
    e->aptPermCutoff = cutoffs.aptPermCutoff;
}

void ES_DeltaNsStartupReset(ES_DeltaNs *e)
{
    e->testFailure = 0;
    e->rct.count = 0;
    e->rct.lastData = 0;
    e->apt.baseSet = 0;
    e->apt.count = 0;
    e->apt.observed = 0;
    e->apt.base = 0;
    e->stuckCount = 0;
    e->lastDelta = 0;
    e->lastDelta2 = 0;
}

int32_t ES_DeltaNsTryOsr(ES_DeltaNs *e, uint32_t osr, ES_DeltaMeasureFn measure, void *srcCtx)
{
    ES_DeltaNsStartupReset(e);
    ES_DeltaNsOsrApply(e, osr);
    if (e->testFailure != CRYPT_SUCCESS) {
        return DeltaFailurePublic(e->testFailure);
    }
    /* The startup window judges health verdicts only; the measured deltas
       are discarded, so no output buffer is staged. */
    for (uint32_t i = 0; i < ES_STARTUP_TEST_SAMPLES; i++) {
        measure(srcCtx);
        if (e->testFailure != CRYPT_SUCCESS) {
            return DeltaFailurePublic(e->testFailure);
        }
    }
    return CRYPT_SUCCESS;
}

int32_t ES_DeltaNsTimerQualify(ES_DeltaNs *e, ES_DeltaSampleFn sample, void *srcCtx, uint32_t osr)
{
    e->timerCheckOsr = osr;
    int32_t ret = ES_DeltaTimerCheck(sample, srcCtx, ES_STARTUP_TEST_SAMPLES, osr);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ES_DeltaNsOsrApply(e, osr);
    return DeltaFailurePublic(e->testFailure);
}

int32_t ES_DeltaNsRecoveryWindow(ES_DeltaNs *e, ES_DeltaSampleFn rawSample, ES_DeltaMeasureFn measure, void *srcCtx)
{
    /* Recovery is at least as strict as startup: the timer check
       re-runs first, so lost resolution cannot re-arm through the health
       soak alone; DEAD/COARSE stays structural. */
    int32_t ret = ES_DeltaTimerCheck(rawSample, srcCtx, ES_STARTUP_TEST_SAMPLES, e->timerCheckOsr);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ES_DeltaNsStartupReset(e);
    ES_DeltaNsOsrApply(e, e->osr);
    if (e->stuckCutoff == 0) {
        return CRYPT_ENTROPY_RCT_FAILURE;
    }
    int8_t worst = CRYPT_SUCCESS;
    for (uint32_t i = 0; i < ES_STARTUP_TEST_SAMPLES; i++) {
        measure(srcCtx);
        if (e->testFailure == NS_ENTROPY_PERMANENT_FAILURE) {
            return CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
        }
        if (e->testFailure != CRYPT_SUCCESS) {
            if (worst == CRYPT_SUCCESS) {
                worst = e->testFailure;
            }
            /* Soak past the alarm: clearing the verdict keeps the window
               sampling while the counters keep marching toward the
               permanent bounds; the recorded alarm still fails the window. */
            e->testFailure = CRYPT_SUCCESS;
        }
    }
    if (worst != CRYPT_SUCCESS) {
        e->testFailure = worst;
        return DeltaFailurePublic(worst);
    }
    return CRYPT_SUCCESS;
}

int32_t ES_DeltaNsOsrWalk(ES_DeltaNs *e, uint32_t startOsr, uint32_t osrMax,
    ES_DeltaMeasureFn measure, void *srcCtx)
{
    int32_t last = CRYPT_ENTROPY_ES_NS_NOT_AVA;
    for (uint32_t osr = startOsr; osr <= osrMax; osr++) {
        int32_t ret = ES_DeltaNsTryOsr(e, osr, measure, srcCtx);
        if (ret == CRYPT_SUCCESS) {
            return CRYPT_SUCCESS;
        }
        last = ret;
    }
    /* Ladder exhausted: keep the final rung's specific verdict. */
    return last;
}

#endif
