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

#ifndef HITLS_CACHE_LINE_SIZE
    #define HITLS_CACHE_LINE_SIZE 64
#endif
#ifndef HITLS_CACHE_ROW_COUNT
    #define HITLS_CACHE_ROW_COUNT 1025
#endif
#ifndef HITLS_JITTER_APT_CUT_OFF
/**
 * Binary WINDOW 1024, 0.8 Entropy CUT off 664 0.6 Entropy CUT off 748
 * reference to SP800-90B sec 4.4.2
 */
    #define HITLS_JITTER_APT_CUT_OFF 592
#endif
#ifndef HITLS_JITTER_RCT_CUT_OFF
/**
 * C = 1 + ceil(-log_2(alpha)/H), H = 1(MIN_ENTROPY), alpha = 2^(-20)
 * alpha value reference SP800-90B sec 4.4.1
 * following SP800-90B. Thus C = ceil(-log_2(alpha)/H) = 20.
 */
#define HITLS_JITTER_RCT_CUT_OFF 20
#endif
#ifndef HITLS_JITTER_MINENTROPY
/**
 * HITLS_JITTER_RCT_CUT_OFF and HITLS_JITTER_APT_CUT_OFF are calculated based on HITLS_JITTER_MINENTROPY.
 * If HITLS_JITTER_MINENTROPY is configured manually, HITLS_JITTER_RCT_CUT_OFF and must be
 * configured simultaneously.
 */
    #define HITLS_JITTER_MINENTROPY 5
#endif

#define NS_APT_BIN_WINDOW_SIZE 1024

#define NS_ENTROPY_HASH_SIZE 32                            // hash size
#define NS_ENTROPY_DATA_SIZE (NS_ENTROPY_HASH_SIZE * 4)  // 4 * 32， 128 bytes，1024 bits，one APT window

/* Mainstream CPU cache access unit (cache line) 32 或者64 */
#define NS_CACHE_SIZE (HITLS_CACHE_LINE_SIZE * HITLS_CACHE_ROW_COUNT) // total operation memory size
#define NS_CACHE_MIN_SIZE 33                                          // minimum Length

#define NS_ENTROPY_RCT_FAILURE (-1)
#define NS_ENTROPY_APT_FAILURE (-2)

#define NS_ENTROPY_MAX_LIFE 30       // maximum lifetime of entropy data: 30 seconds

typedef struct ES_JitterState {
    int8_t testFailure;
    uint8_t rctCount;
    uint8_t aptBase;
    uint8_t aptBaseSet;
    uint16_t aptCount;
    uint16_t aptObservations;
    uint8_t data[NS_ENTROPY_DATA_SIZE];
    uint64_t lastDelta;
    uint32_t remainCount;
    uint32_t memLocation;
    uint8_t mem[HITLS_CACHE_ROW_COUNT][HITLS_CACHE_LINE_SIZE];
    volatile uint32_t mID;
    uint64_t lastTime;
    void (*hashFunc)(uint8_t *, int, uint8_t *, int);
} ES_JitterState;

static void UpdateRctHealth(ES_JitterState *e, int stuck)
{
    if (e->rctCount > HITLS_JITTER_RCT_CUT_OFF) {
        return;
    }
    if (stuck > 0) {
        e->rctCount++;
        if (e->rctCount > HITLS_JITTER_RCT_CUT_OFF) {
            e->testFailure = NS_ENTROPY_RCT_FAILURE;  // If the RCT test fails, the entropy source can be restarted.
        }
    } else {
        e->rctCount = 0;
    }
}
static void UpdateAptHealth(ES_JitterState *e, uint8_t data)
{
    if (e->aptBaseSet == 0) {
        e->aptBase = data;
        e->aptBaseSet = 1;
        e->aptCount = 1;
        e->aptObservations = 1;
        return;
    }
    if (e->aptBase == data) {
        e->aptCount++;
        if (e->aptCount > HITLS_JITTER_APT_CUT_OFF) {
            e->testFailure = NS_ENTROPY_APT_FAILURE;  // If APT detection fails, the entropy source can be restarted.
        }
    }
    e->aptObservations++;
    if (e->aptObservations >= NS_APT_BIN_WINDOW_SIZE) {
        e->aptBaseSet = 0;
    }
}

#define NS_MOVE_LEVEL 128

// GCC uses optimize("O0"), Clang/AppleClang uses optnone
#if defined(__clang__)
static void __attribute__((optnone)) EntropyMemeryAccess(ES_JitterState *e, uint8_t det)
#elif defined(__GNUC__)
static void __attribute__((optimize("O0"))) EntropyMemeryAccess(ES_JitterState *e, uint8_t det)
#else
static void EntropyMemeryAccess(ES_JitterState *e, uint8_t det)
#endif
{
    /*
     * 1. Random read/write start position
     * 2. Read and write position change by position value
     * 3. Multiple data reads and writes
     * 4. branch prediction mitigation
     */
    e->mID = (e->mID + det) % NS_CACHE_SIZE;
    uint32_t bound = HITLS_CACHE_ROW_COUNT + det;
    for (uint32_t i = 0; i < bound; i++) {
        // c, l Calculate the row and column coordinate points.
        uint32_t c = e->mID / HITLS_CACHE_LINE_SIZE;
        uint32_t l = e->mID % HITLS_CACHE_LINE_SIZE;
        volatile uint8_t *volatile cur = e->mem[c] + l;
        *cur ^= det;
        e->memLocation = (e->memLocation + (*cur & 0x0f) + NS_CACHE_MIN_SIZE) % NS_CACHE_SIZE;
    }
}

/**
 * Get a random position: keep moving right until there is a non-zero bit in the lower eight bits,
 * then return the lower eight bits
 */
static uint8_t GetUChar(uint64_t tick)
{
    size_t i;
    volatile uint64_t data = tick;
    for (i = 0; i < sizeof(uint64_t); i++) {
        if ((data & 1) == 1) {
            return (uint8_t)data;
        }
        data >>= 1;
    }
    return (uint8_t)((data % HITLS_CACHE_LINE_SIZE) + NS_CACHE_MIN_SIZE);
}

static void EntropyMeasure(ES_JitterState *e, int32_t index)
{
    uint8_t data = 0;
    int i;
    // One byte has eight bits. Only the status of one bit can be obtained each time the memory is read or written.
    for (i = 0; i < 8; i++) {  // 8 bit
        uint64_t tick1 = BSL_SAL_TIME_GetNSec();
        EntropyMemeryAccess(e, GetUChar(tick1));
        uint64_t tick = BSL_SAL_TIME_GetNSec();
        uint64_t delta = tick - tick1;
        uint8_t bit;
        if (delta & 0x01) {
            bit = (delta >> 3) & 0x01; // 3:4th bits
        } else {
            bit = (delta >> 7) & 0x01; // 7:8th bits
        }
        data = (uint8_t)(data << 1); // Move to the left first to prevent entropy overflow.
        data |= bit;
        UpdateRctHealth(e, e->lastDelta == bit);
        UpdateAptHealth(e, bit);
        e->lastDelta = bit;
    }

    e->data[index] = data;
    data = 0;  // clean
}

static void EntropyProcess(ES_JitterState *e)
{
    int32_t i, start;
    uint8_t buf[NS_ENTROPY_HASH_SIZE + 1];
    for (i = 0; i < NS_ENTROPY_DATA_SIZE; i++) {
        EntropyMeasure(e, i);  // Obtains 1-byte entropy.
        start = (i / NS_ENTROPY_HASH_SIZE) * NS_ENTROPY_HASH_SIZE;
        /**
         * Copy 32 bytes to buf at a time, but only one byte of entropy is added to e-data in each loop. Subsequently,
         * the latest entropy is attached to the tail of the buffer each time, and the 33-byte content is hashed.
         * The hashed content is written to the internal entropy pool of the entropy source.
         */
        (void)memcpy_s(buf, NS_ENTROPY_HASH_SIZE + 1, e->data + start, NS_ENTROPY_HASH_SIZE);
        // The latest entropy 1 byte is placed at the end. The 33-byte data is hashed to form a new 32-byte entropy.
        buf[NS_ENTROPY_HASH_SIZE] = e->data[i];
        e->hashFunc(buf, sizeof(buf), (e->data + start), NS_ENTROPY_HASH_SIZE);
    }
    (void)memset_s(buf, sizeof(buf), 0, sizeof(buf));
}

static int32_t EsCpuJitterGen(ES_JitterState *jitter, uint8_t *buf, uint32_t bufLen)
{
    const uint32_t entropySize = sizeof(jitter->data);
    EntropyProcess(jitter);
    uint8_t *out = buf;
    uint32_t left = bufLen;
    while (left > 0) {
        EntropyProcess(jitter);  // 1024
        if (jitter->testFailure != CRYPT_SUCCESS) {
            jitter->remainCount = 0;
            break;
        }
        uint32_t length = left > entropySize ? entropySize : left;
        (void)memcpy_s(out, length, jitter->data, length);
        left -= length;
        if (left <= 0) {
            jitter->remainCount = entropySize - length;
            jitter->lastTime = BSL_SAL_CurrentSysTimeGet();
            break;
        }
        out += length;
    }
    return jitter->testFailure;
}

static uint32_t EsCpuJitterGet(ES_JitterState *jitter, uint8_t *buf, uint32_t bufLen)
{
    if (jitter->remainCount == 0) {
        return bufLen;
    }
    uint64_t nowTime = BSL_SAL_CurrentSysTimeGet();
    if (nowTime == 0 || nowTime - jitter->lastTime > NS_ENTROPY_MAX_LIFE) {
        return bufLen;
    }
    uint32_t length = (bufLen < jitter->remainCount) ? bufLen : jitter->remainCount;
    (void)memcpy_s(buf, bufLen, jitter->data + (NS_ENTROPY_DATA_SIZE - jitter->remainCount), length);
    jitter->remainCount -= length;
    return bufLen - length;
}

static int32_t ES_CpuJitterRead(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    ES_JitterState *jitter = (ES_JitterState *)ctx;
    (void)timeout;
    if (ctx == NULL || buf == NULL || bufLen <= 0) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t left = EsCpuJitterGet(jitter, buf, bufLen);
    if (left == 0) {
        return CRYPT_SUCCESS;
    }
    return EsCpuJitterGen(jitter, buf + (bufLen -left), left);
}

static void ES_CpuJitterFree(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    (void)memset_s(ctx, sizeof(ES_JitterState), 0, sizeof(ES_JitterState));
    BSL_SAL_FREE(ctx);
}

static void *ES_CpuJitterInit(void *para)
{
    if (para == NULL) {
        return NULL;
    }
    ES_JitterState *e = (ES_JitterState *)BSL_SAL_Malloc(sizeof(ES_JitterState));
    if (e == NULL) {
        return NULL;
    }
    e->rctCount = 0;
    e->aptBaseSet = 0;
    e->mID = 0;
    e->hashFunc = para;
    e->testFailure = CRYPT_SUCCESS;
    // Try to read 32 bytes once to check whether the environment is normal.
    uint8_t data[32] = {0};
    if (ES_CpuJitterRead(e, true, data, sizeof(data)) != CRYPT_SUCCESS) {
        (void)memset_s(data, sizeof(data), 0, 32);  // 32, Zeroed 32-byte array
        ES_CpuJitterFree(e);
        return NULL;
    }
    return e;
}


static void EmptyConditionComp(uint8_t *out, int32_t outLen, uint8_t *in, int32_t inLen)
{
    (void)out;
    (void)outLen;
    (void)in;
    (void)inLen;
}

ES_NoiseSource *ES_CpuJitterGetCtx(void)
{
    ES_NoiseSource *ctx = BSL_SAL_Malloc(sizeof(ES_NoiseSource));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(ES_NoiseSource), 0, sizeof(ES_NoiseSource));
    uint32_t len = strlen("CPU-Jitter");
    ctx->name = BSL_SAL_Malloc(len + 1);
    if (ctx->name == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    (void)strncpy_s(ctx->name, len + 1, "CPU-Jitter", len);
    ctx->autoTest = true;
    ctx->para = (void *)EmptyConditionComp;
    ctx->init = ES_CpuJitterInit;
    ctx->read = ES_CpuJitterRead;
    ctx->deinit = ES_CpuJitterFree;
    ctx->minEntropy = HITLS_JITTER_MINENTROPY; // one byte bring 5 bits entropy
    return ctx;
}
#endif