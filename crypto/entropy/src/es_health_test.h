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

#ifndef ES_HEALTH_TEST_H
#define ES_HEALTH_TEST_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The tested symbol is the 8-bit value the entropy claim is assessed on
   (SP800-90B 6.4 alphabet reduction); wider sources project onto it. */
typedef struct {
    uint32_t cutoff;
    uint32_t count;
    uint8_t lastData;
} ES_RctState;

typedef struct {
    uint32_t cutoff;
    uint32_t windowSize;
    uint32_t baseSet;    /* whether base holds the current window's first sample */
    uint32_t count;
    uint32_t observed;   /* samples seen in the current window */
    uint8_t base;
} ES_AptState;

/* Aggregate for sources that run the standard RCT + APT pair on one stream. */
typedef struct {
    ES_RctState rct;
    ES_AptState apt;
} ES_HealthTest;

/* Repetition Count Test */
int32_t ES_HealthTestRct(ES_RctState *state, uint8_t data);

/* Adaptive Proportion Test */
int32_t ES_HealthTestApt(ES_AptState *state, uint8_t data);

/* Clear the run-time state of one RCT + APT pair while keeping the configured
   cutoffs and window size: no repetition run or proportion window may carry
   over into a fresh startup-test window. */
void ES_HealthTestReset(ES_HealthTest *state);

/* Startup health tests and the timer check draw at least 1024 consecutive
   samples (SP800-90B 4.3, GM/T 0105-2021 5.5). */
#define ES_STARTUP_TEST_SAMPLES 1024

/* One raw delta produced by the noise source's own workload. */
typedef uint64_t (*ES_DeltaSampleFn)(void *ctx);

/* Timer check run at startup and recovery: draws count deltas from the
   source's own workload and decides whether the time source can carry the
   claimed rate h = 1/osr.
   CRYPT_ENTROPY_ES_DEAD_TIMER: no samples at all.
   CRYPT_ENTROPY_ES_COARSE_TIMER: a zero delta, too little delta-to-delta
   variation, or a low byte that never changes. */
int32_t ES_DeltaTimerCheck(ES_DeltaSampleFn sample, void *ctx, uint32_t count, uint32_t osr);

typedef struct {
    uint32_t rctCutoff; /* SP800-90B 4.4.1: 1 + ceil(-log2(alpha) / h), alpha = 2^-20 */
    uint32_t aptCutoff; /* SP800-90B 4.4.2, comment #10b: count = 1 + Bin(511, 2^-h)
                           (base sample self-matches), cutoff at alpha = 2^-20 */
    /* Permanent tier at alpha = 2^-60: a run this extreme is treated as a
       platform fault rather than a statistical alarm, so governance retires
       the source without waiting for repeated recovery failures. */
    uint32_t rctPermCutoff; /* 1 + ceil(60 / h) */
    uint32_t aptPermCutoff; /* same count model at alpha = 2^-60, clamped to the
                               512 window from osr >= 9 (where the derived bound
                               exceeds the window because an all-equal window,
                               probability 2^(-511/osr), is likelier than 2^-60);
                               the tier stays armed at a looser-than-nominal
                               false-positive (C <= W) */
} ES_DeltaCutoffs;

/* Cutoff pair for a claimed min-entropy of h = 1/osr bit per credited delta
   (oversampling rate: osr deltas per entropy bit), osr in [1, 15]. Source
   configs additionally cap claims at NS_DELTA_OSR_MIN (h <= 1/3). */
int32_t ES_DeltaOsrCutoffs(uint32_t osr, ES_DeltaCutoffs *cutoffs);

#ifdef __cplusplus
}
#endif

#endif

#endif
