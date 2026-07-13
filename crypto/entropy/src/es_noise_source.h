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

#ifndef ES_NOISE_SOURCE_H
#define ES_NOISE_SOURCE_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>
#include "bsl_list.h"
#include "bsl_sal.h"
#include "es_health_test.h"
#include "crypt_types.h"
#include "crypt_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A source failing init health at the ladder's weakest rate (osrMax) this
   many consecutive cycles is retired for the record's lifetime. Retirement
   policy, not a derived probability bound. */
#define NS_PERMANENT_FAIL_STREAK 4

/* Registration capacity of one ES noise-source list. */
#define ES_NS_MAX_SIZE 16

/* ES-side governance record for one registered noise source. The noise source
   instance lives behind usrdata and is rebuilt on each init; this record keeps
   registration callbacks, claim bounds and health-test state. */
typedef struct {
    /* Whether to enable the health test */
    bool enableTest;
    /* Whether the noise source automatically performs the health test */
    bool autoTest;
    /* Whether the noise source is available */
    bool isEnable;
    /* Whether the noise source is initialized */
    bool isInit;
    /* Noise source name, which must be unique. */
    char *name;
    /* Initialization parameters of the noise source */
    void *para;
    /* Noise Source Handle */
    void *usrdata;
    /* Noise Source Initialization Interface. */
    void *(*init)(void *para);
    /* Interface for Obtaining Noise Sources. */
    int32_t (*read)(void *usrdata, uint32_t timeout, uint8_t *buf, uint32_t bufLen);
    /* Noise Source Deinitialization Interface. */
    void (*deinit)(void *usrdata);
    /* Optional readback of the per-instance settled oversampling rate after
       init; NULL keeps the registered osr. */
    uint32_t (*osrGet)(const void *usrdata);
    /* Optional adaptive init walking the osr ladder up from startOsr on one
       calibrated state; NULL selects the fixed-claim init path. RCT/APT
       verdicts are floor-level health failures by contract. */
    int32_t (*initAt)(void *para, uint32_t startOsr, void **usrdata);
    /* Instance-lifetime oversampling bounds; only meaningful with initAt.
       osr is the current entropy-credit divisor; each demotion step increases
       it towards osrMax (claiming less entropy per delta). Zero gives fixed
       sources their integer claimBitsPerOsr claim. */
    uint32_t osr;
    uint32_t osrMax;
    /* Consecutive init cycles that failed health testing at the ladder's
       weakest rate (osrMax). */
    uint32_t floorFailStreak;
    /* Optional runtime recovery at the unchanged settled rate.
       NULL means fail-closed: a runtime health alarm suspends the source for
       the record's lifetime. */
    int32_t (*recover)(void *usrdata);
    /* Suspended by a runtime health alarm; the next gather must pass the
       recovery window before this source rejoins collection. */
    bool needRecovery;
    /* Re-armed by a recovery window but not yet vindicated by a real
       transaction: the failure streak is not cleared until the source
       completes one full credited gather, so a source that keeps alarming
       right after every recovery still marches toward retirement. */
    bool onProbation;
    /* Failed recovery windows since the last vindicated success; reaching
       NS_PERMANENT_FAIL_STREAK retires the source. */
    uint32_t recoveryFailStreak;
    /* Terminal state: the source is skipped by every subsequent init cycle
       for the lifetime of this record; a new ES instance starts clean. */
    bool permanentFailure;
    /* Bytes one sample record occupies in the read stream (nonzero and
       divides the startup window; enforced at source init). Quota, health
       accounting and the startup window count
       sample records; byte counts derive from this factor. Delta sources emit
       NS_DELTA_RECORD_BYTES-wide raw records; plain byte sources use 1. */
    uint32_t sampleBytes;
    /* Credited claim numerator: bits claimed per osr quota-eligible samples
       (per-sample min-entropy = claimBitsPerOsr / osr; byte source osr=1). */
    uint32_t claimBitsPerOsr;
    /* Whether this source's entropy claim is credited in pool accounting.
       Non-credited sources are still mixed into the conditioner but add zero credit. */
    bool credited;
    ES_HealthTest state;
} ES_NoiseSource;

/* Gather-internal read: this layer returns its verdict without pushing it on
   the error stack. A source-supplied read callback may still push its own. */
int32_t ES_NsRead(ES_NoiseSource *ns, uint8_t *buf, uint32_t bufLen);

/* 1024-sample startup verification window over ns->read with the generic
   RCT + APT pair. Runtime recovery is source-level only: a source
   without a recover op keeps its fail-closed suspension. */
int32_t ES_NoiseSourceStartupTest(ES_NoiseSource *ns);

/* The two governance answers to a failed source, keyed on its verdict code.

   Retire: a dead or too-coarse timer, a broken primitive, or a permanent-tier
   health run. Claiming less entropy cannot repair any of them, so the source
   is dropped for the record's lifetime. */
static inline bool ES_NsVerdictRetires(int32_t ret)
{
    return ret == CRYPT_ENTROPY_ES_DEAD_TIMER || ret == CRYPT_ENTROPY_ES_COARSE_TIMER ||
        ret == CRYPT_ENTROPY_CONDITION_FAILURE || ret == CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
}

/* Demote: an ordinary RCT or APT alarm. The source may still hold at a weaker
   claim, so it gets another osr rung at startup or a recovery window later. */
static inline bool ES_NsVerdictDemotes(int32_t ret)
{
    return ret == CRYPT_ENTROPY_RCT_FAILURE || ret == CRYPT_ENTROPY_APT_FAILURE;
}

/* Canonical terminal transition: a retired source latches permanent failure and
   drops any pending recovery, probation or enablement, so every gate reports
   the permanent verdict cleanly regardless of which path retired it. */
static inline void ES_NsRetire(ES_NoiseSource *ns)
{
    ns->permanentFailure = true;
    ns->needRecovery = false;
    ns->onProbation = false;
    ns->isEnable = false;
}

/* Architecture counter for delta timing; units are platform dependent and
   only differences are meaningful. Reads are deliberately unserialized:
   out-of-order and speculative execution are part of the measured noise. */
static inline uint64_t ES_NsTickGet(void)
{
#if defined(HITLS_BSL_SAL_DARWIN)
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#elif defined(__x86_64__) || defined(__i386__)
    uint32_t lo = 0;
    uint32_t hi = 0;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t cnt = 0;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(cnt));
    return cnt;
#elif defined(__riscv) && (__riscv_xlen == 64)
    uint64_t cnt = 0;
    __asm__ __volatile__("rdtime %0" : "=r"(cnt));
    return cnt;
#else
    /* Generic clock for unlisted architectures (e.g. armv7); coarse timers
       are rejected by the startup timer check. */
    return BSL_SAL_TIME_GetNSec();
#endif
}

/* Noise Source List create. */
BslList *ES_NsListCreat(void);

/* Noise Source List Initialization. */
int32_t ES_NsListInit(BslList *nsList, bool enableTest);

/* Noise Source List deinitialization. */
void ES_NsListDeinit(BslList *nsList);

/* Noise Source List release. */
void ES_NsListFree(BslList *nsList);

/**
 * @brief add ns
 *
 * @param nsList [IN] noise source list
 * @param name [IN] Noise source name, which must be unique.
 * @param autoTest [IN] Whether the noise source automatically performs the health test.
 * @param claimBitsPerOsr [IN] claim numerator: bits per osr samples (byte source osr=1 => bits/byte).
 * @param method [IN] noise source callback Interface.
 * @param para [IN] noise source health test parameter.
 *
 * @return CRYPT_SUCCESS succeeded.
 * For other error codes, see crypt_error.h.
 */
int32_t ES_NsAdd(BslList *nsList, const char *name, bool autoTest, uint32_t claimBitsPerOsr,
    const CRYPT_EAL_NsMethod *method, const CRYPT_EAL_NsTestPara *para);

/**
 * @brief remove ns
 *
 * @param nsList [IN] noise source list
 * @param name [IN] Noise source name, which must be unique.
 *
 * @return CRYPT_SUCCESS succeeded.
 * For other error codes, see crypt_error.h.
 */
int32_t ES_NsRemove(BslList *nsList, const char *name);

/* Raise the adaptive oversampling rate after an RCT/APT rejection by one
   step towards osrMax. Returns true when the rate changed. */
bool ES_NsOsrDemote(ES_NoiseSource *ns);

/* Obtains the handle of the cpu-jiiter. */
ES_NoiseSource *ES_CpuJitterGetCtx(void);

/* Obtains the handle of the hash-loop source (software-Keccak CPU-bound timing). */
ES_NoiseSource *ES_HashLoopGetCtx(void);

/* Region sizing policy for the cpu-jitter memory walk: 2 x L1d rounded up to
   a power of two, clamped to [64 KiB, 1 MiB]. Unknown L1d falls back to
   256 KiB. HITLS_JITTER_MEM_BYTES pins the size at compile time. */
uint32_t ES_CpuJitterL1dCacheSize(void);
uint32_t ES_CpuJitterRegionBytes(uint32_t l1dBytes);

/* Settled oversampling rate (claimed h = 1/osr bit per delta) of an
   initialized state. */
uint32_t ES_CpuJitterOsrGet(const void *usrdata);

uint32_t ES_HashLoopOsrGet(const void *usrdata);

#ifdef __cplusplus
}
#endif

#endif

#endif
