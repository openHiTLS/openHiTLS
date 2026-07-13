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

#ifndef ES_NS_DELTA_COMMON_H
#define ES_NS_DELTA_COMMON_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))

#include <stdint.h>
#include "es_health_test.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Shared health-test state for delta-based noise sources. */

#define NS_APT_DELTA_WINDOW_SIZE 512

/* Delta-source claims are capped at h = 1/3 bit per delta (osr >= 3): no
   source may claim better than one entropy bit per three measurements.
   The supported adaptive ladder is capped at osr = 15. */
#define NS_DELTA_OSR_MIN 3
#define NS_DELTA_OSR_MAX 15

/* One emitted record per accepted measurement: the raw 64-bit delta,
   little-endian. The conditioner absorbs exactly this record. */
#define NS_DELTA_RECORD_BYTES 8

/* SP800-90B 6.4 alphabet reduction: the assessed symbol is the low 8 bits of
   the delta, which caps the per-sample credit at 8 bit and keeps the health
   tests and the entropy estimate in one domain. */
#define NS_DELTA_SYMBOL_MASK 0xffU

/* Compact health-test verdicts normalized at the source read boundary. The
   permanent verdict targets a nominal alpha = 2^-60 run (a fault, not an
   alarm); from osr >= 9 the APT bound is clamped to the window, so its
   effective probability is the looser 2^(-511/osr). */
#define NS_ENTROPY_RCT_FAILURE (-1)
#define NS_ENTROPY_APT_FAILURE (-2)
#define NS_ENTROPY_PERMANENT_FAILURE (-3)

typedef struct ES_DeltaNs ES_DeltaNs;

/* Engine state; must be the first member of the embedding source state. */
struct ES_DeltaNs {
    int8_t testFailure;
    uint32_t stuckCount; /* consecutive stuck-sample run length */
    uint32_t stuckCutoff; /* per-osr RCT bound applied to the stuck run */
    ES_RctState rct; /* SP800-90B 4.4.1 RCT over the assessed 8-bit symbol */
    ES_AptState apt; /* SP800-90B 4.4.2 APT over the assessed 8-bit symbol */
    uint32_t rctPermCutoff; /* nominal alpha = 2^-60 permanent bound over the RCT run only */
    uint32_t aptPermCutoff; /* nominal alpha = 2^-60 permanent bound over the APT count,
                               clamped to the 512 window from osr >= 9 (effective 2^(-511/osr)); it is
                               non-zero after OsrApply and never a disabled tier */
    uint64_t lastDelta; /* previous delta (first-difference basis) */
    uint64_t lastDelta2; /* previous first difference (second-difference basis) */
    uint32_t osr; /* settled oversampling rate: claimed h = 1/osr bit per delta */
    uint32_t timerCheckOsr; /* osr the startup timer check ran at; recovery reuses
                         it so its timer gate is exactly as strict as startup */
};

/* One timed production measurement of the embedding source; it must bracket
   its workload with the time source and hand the raw delta to
   ES_DeltaNsProcessRawDelta. */
typedef void (*ES_DeltaMeasureFn)(void *srcCtx);

/* Apply source-local health tests to one raw delta. */
void ES_DeltaNsProcessRawDelta(ES_DeltaNs *ns, uint64_t rawDelta);

/* Emit one NS_DELTA_RECORD_BYTES little-endian raw-delta record per
   successful measurement; bufLen must be a positive record multiple. */
int32_t ES_DeltaNsRead(ES_DeltaNs *ns, ES_DeltaMeasureFn measure, void *srcCtx, uint8_t *buf, uint32_t bufLen);

/* Bind an oversampling rate and its cutoff pair from the per-osr table. */
void ES_DeltaNsOsrApply(ES_DeltaNs *ns, uint32_t osr);

/* Fresh startup attempt: clear health and difference state. */
void ES_DeltaNsStartupReset(ES_DeltaNs *ns);

/* Single startup attempt at one oversampling rate: reset health/output state,
   bind the rate's cutoffs and run a 1024-sample health-test window. */
int32_t ES_DeltaNsTryOsr(ES_DeltaNs *ns, uint32_t osr, ES_DeltaMeasureFn measure, void *srcCtx);

/* Startup timer qualification at the claimed rate: records the osr the
   check ran at (recovery replays it), runs the check over the startup
   window, then arms the per-osr cutoffs. */
int32_t ES_DeltaNsTimerQualify(ES_DeltaNs *e, ES_DeltaSampleFn sample, void *srcCtx, uint32_t osr);

/* Recovery after a runtime alarm, at the settled rate: re-runs the startup
   timer check, then soaks 1024 samples past intermittent alarms.
   CRYPT_SUCCESS re-arms; RCT/APT_FAILURE reports a repeated alarm;
   ES_PERMANENT_FAILURE reports a permanent bound and exits early. */
int32_t ES_DeltaNsRecoveryWindow(ES_DeltaNs *ns, ES_DeltaSampleFn rawSample, ES_DeltaMeasureFn measure, void *srcCtx);

/* Select a supported rate from startOsr up to osrMax (each step claims less
   entropy per delta). The settled rate is stored in ns->osr. */
int32_t ES_DeltaNsOsrWalk(ES_DeltaNs *ns, uint32_t startOsr, uint32_t osrMax,
    ES_DeltaMeasureFn measure, void *srcCtx);

#ifdef __cplusplus
}
#endif

#endif

#endif
