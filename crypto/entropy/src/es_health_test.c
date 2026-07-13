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
#include <stddef.h>
#include "crypt_errno.h"
#include "es_health_test.h"

int32_t ES_HealthTestRct(ES_RctState *state, uint8_t data)
{
    if (data == state->lastData) {
        state->count++;
        if (state->count >= state->cutoff) {
            /* No error-stack push: osr walk candidates call this speculatively
               and would flood it. The collection transaction pushes the verdict
               it acts on. */
            return CRYPT_ENTROPY_RCT_FAILURE;
        }
    } else {
        state->lastData = data;
        state->count = 1;
    }

    return CRYPT_SUCCESS;
}

int32_t ES_HealthTestApt(ES_AptState *state, uint8_t data)
{
    if (state->baseSet == 0) { /* NIST SP800-90B section 4.4.2 step 1/2 */
        state->baseSet = 1;
        state->base = data;
        state->count = 1;
        state->observed = 1;
        return CRYPT_SUCCESS;
    }

    int32_t ret = CRYPT_SUCCESS;
    if (state->base == data) {
        state->count++;
        if (state->count >= state->cutoff) {
            /* Latch, do not return: the bookkeeping below must still run so the
               permanent tier reads a single-window count. No error-stack push;
               the collection transaction pushes the verdict it acts on. */
            ret = CRYPT_ENTROPY_APT_FAILURE;
        }
    }

    state->observed++;
    if (state->observed >= state->windowSize) {
        state->baseSet = 0;
    }
    return ret;
}

void ES_HealthTestReset(ES_HealthTest *state)
{
    state->rct.count = 0;
    state->rct.lastData = 0;
    state->apt.baseSet = 0;
    state->apt.count = 0;
    state->apt.observed = 0;
    state->apt.base = 0;
}

int32_t ES_DeltaOsrCutoffs(uint32_t osr, ES_DeltaCutoffs *cutoffs)
{
    /* Null count = 1 + Binomial(511, 2^(-1/osr)) (the base sample matches
       itself; "comment #10b"). Cutoff = smallest C with P[count >= C] <=
       2^-20, osr = 1..15; every entry stays below the 512 window (C <= W). */
    static const uint32_t aptCutoffTable[15] = {
        311, 411, 449, 468, 480, 488, 493, 497, 500, 502, 504, 505, 507, 508, 508
    };
    /* Same model at alpha = 2^-60. From osr = 9 the bound exceeds the
       window (all-equal is 2^(-511/osr) > 2^-60), so entries clamp to 512:
       armed, false-positive looser than nominal. */
    static const uint32_t aptPermCutoffTable[15] = {
        355, 447, 479, 494, 502, 507, 510, 512, 512, 512, 512, 512, 512, 512, 512
    };
    if (cutoffs == NULL || osr == 0 || osr > 15) {
        return CRYPT_ENTROPY_CTRL_INVALID_PARAM;
    }
    /* 1 + ceil(-log2(alpha) / h) with alpha = 2^-20 and h = 1/osr. */
    cutoffs->rctCutoff = 1 + 20 * osr;
    cutoffs->aptCutoff = aptCutoffTable[osr - 1];
    cutoffs->rctPermCutoff = 1 + 60 * osr;
    cutoffs->aptPermCutoff = aptPermCutoffTable[osr - 1];
    return CRYPT_SUCCESS;
}

int32_t ES_DeltaTimerCheck(ES_DeltaSampleFn sample, void *ctx, uint32_t count, uint32_t osr)
{
    if (osr == 0) {
        return CRYPT_ENTROPY_CTRL_INVALID_PARAM;
    }
    if (count == 0) {
        return CRYPT_ENTROPY_ES_DEAD_TIMER;
    }
    /* h = 1/osr credited per delta needs total adjacent-delta variation of
       at least ceil(count / osr) across the window; the sum saturates at
       the target so it cannot wrap. */
    uint64_t variationTarget = (uint64_t)(count / osr) + ((count % osr) != 0);
    uint64_t previous = 0;
    uint64_t variation = 0;
    uint8_t lsbVaried = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t delta = sample(ctx);
        if (delta == 0) {
            return CRYPT_ENTROPY_ES_COARSE_TIMER;
        }
        if (i > 0 && (uint8_t)delta != (uint8_t)previous) {
            lsbVaried = 1;
        }
        if (i > 0 && variation < variationTarget) {
            uint64_t difference = delta >= previous ? delta - previous : previous - delta;
            uint64_t remaining = variationTarget - variation;
            variation += difference < remaining ? difference : remaining;
        }
        previous = delta;
    }
    /* Timer resolution and variation are platform properties, qualified
       once before credit begins. Deltas all sharing one low byte pin the
       assessment symbol to a constant, so that window is coarse too. */
    if (variation < variationTarget || (count > 1 && lsbVaried == 0)) {
        return CRYPT_ENTROPY_ES_COARSE_TIMER;
    }
    return CRYPT_SUCCESS;
}

#endif
