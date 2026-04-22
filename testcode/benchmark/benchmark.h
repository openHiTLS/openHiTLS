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

#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

static inline uint64_t BenchNowNs(void)
{
#if defined(__APPLE__) && defined(CLOCK_UPTIME_RAW)
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#else
    struct timespec now = {0};
#if defined(CLOCK_MONOTONIC)
    const clockid_t clockId = CLOCK_MONOTONIC;
#else
    const clockid_t clockId = CLOCK_REALTIME;
#endif
    if (clock_gettime(clockId, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
#endif
}

static inline double BenchOpsPerSec(uint64_t count, uint64_t elapsedTime)
{
    if (elapsedTime == 0) {
        return 0.0;
    }
    return ((double)count * 1000000000.0) / (double)elapsedTime;
}

#define BENCH_TIMES(func, rc, ok, len, times, header)                                                    \
    {                                                                                                    \
        uint32_t benchTimes = (uint32_t)(times);                                                         \
        uint64_t start = BenchNowNs();                                                                   \
        for (uint32_t i = 0; i < benchTimes; i++) {                                                      \
            rc = func;                                                                                   \
            if (rc != ok) {                                                                              \
                printf("Error: %s, ret = %08x\n", #func, rc);                                            \
                break;                                                                                   \
            }                                                                                            \
        }                                                                                                \
        uint64_t end = BenchNowNs();                                                                     \
        uint64_t elapsedTime = end - start;                                                              \
        printf("%-35s, %10d, %15u, %16.2f, %20.2f\n", header, len, benchTimes, (double)elapsedTime / 1000000, \
               BenchOpsPerSec(benchTimes, elapsedTime));                                                 \
    }

#define BENCH_TIMES_VA(func, rc, ok, len, times, headerFmt, ...)    \
    {                                                               \
        char header[256] = {0};                                     \
        snprintf(header, sizeof(header), headerFmt, ##__VA_ARGS__); \
        BENCH_TIMES(func, rc, ok, len, times, header);              \
    }

#define BENCH_SECONDS(func, rc, ok, len, secs, header)                                               \
    {                                                                                                \
        uint32_t benchSeconds = (uint32_t)(secs);                                                    \
        uint64_t totalTime = (uint64_t)benchSeconds * 1000000000;                                    \
        uint64_t elapsedTime = 0;                                                                    \
        uint64_t cnt = 0;                                                                            \
        while (elapsedTime < totalTime) {                                                            \
            uint64_t start = BenchNowNs();                                                           \
            rc = func;                                                                               \
            uint64_t end = BenchNowNs();                                                             \
            elapsedTime += end - start;                                                              \
            if (rc != ok) {                                                                          \
                printf("Error: %s, ret = %08x\n", #func, rc);                                        \
                break;                                                                               \
            }                                                                                        \
            cnt++;                                                                                   \
        }                                                                                            \
        printf("%-35s, %10d, %15" PRIu64 ", %16.2f, %20.2f\n", header, len, cnt,                    \
               (double)elapsedTime / 1000000, BenchOpsPerSec(cnt, elapsedTime));                     \
    }

#define BENCH_RUN(func, rc, ok, len, opts, header)                  \
    do {                                                            \
        if ((opts)->seconds != 0) {                                 \
            BENCH_SECONDS(func, rc, ok, len, (opts)->seconds, header); \
        } else {                                                    \
            BENCH_TIMES(func, rc, ok, len, (opts)->times, header);  \
        }                                                           \
    } while (0)

#define BENCH_RUN_VA(func, rc, ok, len, opts, headerFmt, ...)       \
    do {                                                            \
        char header[256] = {0};                                     \
        snprintf(header, sizeof(header), headerFmt, ##__VA_ARGS__); \
        BENCH_RUN(func, rc, ok, len, opts, header);                 \
    } while (0)

#define BENCH_SETUP(ctx, op, ops, algId, paraId)                       \
    do {                                                               \
        int32_t ret;                                                   \
        ret = ops->setUp(&ctx, op, algId, paraId);                     \
        if (ret != CRYPT_SUCCESS) {                                    \
            printf("Failed to setup benchmark testcase: %08x\n", ret); \
            return;                                                    \
        }                                                              \
    } while (0)

#define BENCH_TEARDOWN(ctx, ops) \
    do {                         \
        ops->tearDown(ctx);      \
    } while (0)

// sizeof array
#define SIZEOF(a) (sizeof(a) / sizeof(a[0]))

// Compile-time array size calculation using C99 compound literals with sizeof
// Cross-platform support:
//   - GCC 4.0+:   Supported (tested with -std=c99 -pedantic)
//   - Clang 3.0+: Supported (tested on macOS with -std=c99 -pedantic)
//   - MSVC 2013+: Supported in C mode (requires /std:c11 or /std:c17)
#define COUNT_OPS(...) \
    (sizeof((Operation[]){ __VA_ARGS__ }) / sizeof(Operation))

#define BENCH_LENS_NUM 6

typedef struct BenchSharedData_ {
    int32_t lens[BENCH_LENS_NUM];
    uint8_t plain[16384];
    uint8_t out[16384];
    uint8_t key[32];
    uint8_t iv[16];
} BenchSharedData;

BenchSharedData *BenchGetSharedData(void);

#define BENCH_PLAIN (BenchGetSharedData()->plain)
#define BENCH_OUT (BenchGetSharedData()->out)
#define BENCH_KEY (BenchGetSharedData()->key)
#define BENCH_IV (BenchGetSharedData()->iv)

static inline void Hex2Bin(const char *hex, uint8_t *bin, uint32_t *len)
{
    *len = strlen(hex) / 2;
    for (uint32_t i = 0; i < *len; i++) {
        sscanf(hex + i * 2, "%2hhx", &bin[i]);
    }
}

// 定义命令行选项结构
typedef struct {
    char *algorithm; // -a 选项指定的算法
    uint32_t filteredOps;
    uint32_t times; // -t 选项指定的运行次数
    uint32_t seconds; // -s 选项指定的运行时间
    uint32_t len;
    int32_t paraId;
    int32_t hashId;
} BenchOptions;

typedef struct {
    uint32_t times;
    uint32_t seconds;
    int32_t len;
    int32_t paraId;
    int32_t hashId;
} BenchExecOptions;

typedef struct BenchCtx_ BenchCtx;
typedef struct CtxOps_ CtxOps;
typedef struct Operation_ Operation;
// every benchmark testcase should define "NewCtx" and "FreeCtx"
typedef int32_t (*SetUp)(void **ctx, const Operation *op, int32_t algId, int32_t paraId);
typedef void (*TearDown)(void *ctx);
typedef int32_t (*BenchOpFn)(void *ctx, const BenchExecOptions *opts);

struct Operation_ {
    uint32_t id;
    const char *name;
    BenchOpFn oper;
};

struct CtxOps_ {
    int32_t algId;
    int32_t hashId;
    int32_t opsNum;
    SetUp setUp;
    TearDown tearDown;
    Operation ops[];
};

#define KEY_GEN_ID    1U
#define KEY_DERIVE_ID 2U
#define ENC_ID        4U
#define DEC_ID        8U
#define SIGN_ID       16U
#define VERIFY_ID     32U
#define ONESHOT_ID    64U
#define ENCAPS_ID     128U
#define DECAPS_ID     256U

#define DEFINE_OPER(id, oper) {id, #oper, oper}

// Compiler-calculated operation count using compound literals and sizeof
// Supports Linux (GCC), macOS (Clang), and Windows (MSVC with C99+)
#define DEFINE_OPS(alg, id, hId)                                         \
    enum { alg##_OPS_NUM = COUNT_OPS(                                    \
        DEFINE_OPER(KEY_GEN_ID, alg##KeyGen),                            \
        DEFINE_OPER(KEY_DERIVE_ID, alg##KeyDerive),                      \
        DEFINE_OPER(ENC_ID, alg##Enc),                                   \
        DEFINE_OPER(DEC_ID, alg##Dec),                                   \
        DEFINE_OPER(SIGN_ID, alg##Sign),                                 \
        DEFINE_OPER(VERIFY_ID, alg##Verify)                              \
    ) };                                                                 \
    static const CtxOps alg##CtxOps = {                                  \
        .algId = id,                                                     \
        .hashId = hId,                                                   \
        .opsNum = alg##_OPS_NUM,                                         \
        .setUp = alg##SetUp,                                             \
        .tearDown = alg##TearDown,                                       \
        .ops =                                                           \
            {                                                            \
                DEFINE_OPER(KEY_GEN_ID, alg##KeyGen),                    \
                DEFINE_OPER(KEY_DERIVE_ID, alg##KeyDerive),              \
                DEFINE_OPER(ENC_ID, alg##Enc),                           \
                DEFINE_OPER(DEC_ID, alg##Dec),                           \
                DEFINE_OPER(SIGN_ID, alg##Sign),                         \
                DEFINE_OPER(VERIFY_ID, alg##Verify),                     \
            },                                                           \
    }

#define DEFINE_OPS_SIGN(alg, id, hId)                              \
    enum { alg##_OPS_NUM = COUNT_OPS(                              \
        DEFINE_OPER(KEY_GEN_ID, alg##KeyGen),                      \
        DEFINE_OPER(SIGN_ID, alg##Sign),                           \
        DEFINE_OPER(VERIFY_ID, alg##Verify)                        \
    ) };                                                           \
    static const CtxOps alg##CtxOps = {                            \
        .algId = id,                                               \
        .hashId = hId,                                             \
        .opsNum = alg##_OPS_NUM,                                   \
        .setUp = alg##SetUp,                                       \
        .tearDown = alg##TearDown,                                 \
        .ops =                                                     \
            {                                                      \
                DEFINE_OPER(KEY_GEN_ID, alg##KeyGen),              \
                DEFINE_OPER(SIGN_ID, alg##Sign),                   \
                DEFINE_OPER(VERIFY_ID, alg##Verify),               \
            },                                                     \
    }

#define DEFINE_OPS_CRYPT_SIGN(alg, id, hId)                        \
    enum { alg##_OPS_NUM = COUNT_OPS(                              \
        DEFINE_OPER(KEY_GEN_ID, alg##KeyGen),                      \
        DEFINE_OPER(ENC_ID, alg##Enc),                             \
        DEFINE_OPER(DEC_ID, alg##Dec),                             \
        DEFINE_OPER(SIGN_ID, alg##Sign),                           \
        DEFINE_OPER(VERIFY_ID, alg##Verify)                        \
    ) };                                                           \
    static const CtxOps alg##CtxOps = {                            \
        .algId = id,                                               \
        .hashId = hId,                                             \
        .opsNum = alg##_OPS_NUM,                                   \
        .setUp = alg##SetUp,                                       \
        .tearDown = alg##TearDown,                                 \
        .ops =                                                     \
            {                                                      \
                DEFINE_OPER(KEY_GEN_ID, alg##KeyGen),              \
                DEFINE_OPER(ENC_ID, alg##Enc),                     \
                DEFINE_OPER(DEC_ID, alg##Dec),                     \
                DEFINE_OPER(SIGN_ID, alg##Sign),                   \
                DEFINE_OPER(VERIFY_ID, alg##Verify),               \
            },                                                     \
    }

#define DEFINE_OPS_CIPHER(alg, id)                              \
    enum { alg##_OPS_NUM = COUNT_OPS(                           \
        DEFINE_OPER(ENC_ID, alg##Enc),                          \
        DEFINE_OPER(DEC_ID, alg##Dec)                           \
    ) };                                                        \
    static const CtxOps alg##CtxOps = {                         \
        .algId = id,                                            \
        .hashId = id,                                           \
        .opsNum = alg##_OPS_NUM,                                \
        .setUp = alg##SetUp,                                    \
        .tearDown = alg##TearDown,                              \
        .ops =                                                  \
            {                                                   \
                DEFINE_OPER(ENC_ID, alg##Enc),                  \
                DEFINE_OPER(DEC_ID, alg##Dec),                  \
            },                                                  \
    }

#define DEFINE_OPS_MD(alg)                                            \
    enum { alg##_OPS_NUM = COUNT_OPS(                                 \
        DEFINE_OPER(ONESHOT_ID, alg##OneShot)                         \
    ) };                                                              \
    static const CtxOps alg##CtxOps = {                               \
        .algId = CRYPT_MD_MAX,                                        \
        .hashId = CRYPT_MD_MAX,                                       \
        .opsNum = alg##_OPS_NUM,                                      \
        .setUp = alg##SetUp,                                          \
        .tearDown = alg##TearDown,                                    \
        .ops =                                                        \
            {                                                         \
                DEFINE_OPER(ONESHOT_ID, alg##OneShot),                \
            },                                                        \
    }

#define DEFINE_OPS_KX(alg, id)                                        \
    enum { alg##_OPS_NUM = COUNT_OPS(                                 \
        DEFINE_OPER(KEY_GEN_ID, alg##KeyGen),                         \
        DEFINE_OPER(KEY_DERIVE_ID, alg##KeyDerive)                    \
    ) };                                                              \
    static const CtxOps alg##CtxOps = {                               \
        .algId = id,                                                  \
        .hashId = CRYPT_MD_MAX,                                       \
        .opsNum = alg##_OPS_NUM,                                      \
        .setUp = alg##SetUp,                                          \
        .tearDown = alg##TearDown,                                    \
        .ops =                                                        \
            {                                                         \
                DEFINE_OPER(KEY_GEN_ID, alg##KeyGen),                 \
                DEFINE_OPER(KEY_DERIVE_ID, alg##KeyDerive),           \
            },                                                        \
    }

#define DEFINE_OPS_KEM(alg, id)                                  \
    enum { alg##_OPS_NUM = COUNT_OPS(                            \
        DEFINE_OPER(KEY_GEN_ID, alg##KeyGen),                    \
        DEFINE_OPER(ENCAPS_ID, alg##Encaps),                     \
        DEFINE_OPER(DECAPS_ID, alg##Decaps)                      \
    ) };                                                         \
    static const CtxOps alg##CtxOps = {                          \
        .algId = id,                                             \
        .hashId = CRYPT_MD_MAX,                                  \
        .opsNum = alg##_OPS_NUM,                                 \
        .setUp = alg##SetUp,                                     \
        .tearDown = alg##TearDown,                               \
        .ops =                                                   \
            {                                                    \
                DEFINE_OPER(KEY_GEN_ID, alg##KeyGen),            \
                DEFINE_OPER(ENCAPS_ID, alg##Encaps),             \
                DEFINE_OPER(DECAPS_ID, alg##Decaps),             \
            },                                                   \
    }

typedef struct BenchCtx_ {
    const char *name;
    const CtxOps *ctxOps;
    int32_t *paraIds;
    uint32_t paraIdsNum;
    int32_t *lens;
    uint32_t lensNum;
    int32_t times;
    int32_t seconds;
} BenchCtx;

#define DEFINE_BENCH_CTX_PARA_TIMES_LEN(alg, pId, pIdNum, ts, l, ln) \
    static const BenchCtx g_##alg##BenchCtx = {                     \
        .name = #alg,                                                \
        .ctxOps = &alg##CtxOps,                                      \
        .paraIds = pId,                                              \
        .paraIdsNum = pIdNum,                                        \
        .lens = l,                                                   \
        .lensNum = ln,                                               \
        .times = ts,                                                 \
        .seconds = 0,                                                \
    };                                                               \
    const BenchCtx *BenchmarkGet##alg(void)                          \
    {                                                                \
        return &g_##alg##BenchCtx;                                   \
    }
#define DEFINE_BENCH_CTX_PARA_TIMES(alg, pId, pIdNum, ts) \
    DEFINE_BENCH_CTX_PARA_TIMES_LEN(alg, pId, pIdNum, ts, NULL, BENCH_LENS_NUM)

#define DEFINE_BENCH_CTX_PARA_TIMES_FIXLEN(alg, pId, pIdNum, ts) \
    DEFINE_BENCH_CTX_PARA_TIMES_LEN(alg, pId, pIdNum, ts, NULL, 1)
// default to run 10000 times
#define DEFINE_BENCH_CTX_PARA(alg, pId, pIdNum)        DEFINE_BENCH_CTX_PARA_TIMES(alg, pId, pIdNum, 10000)
#define DEFINE_BENCH_CTX_PARA_FIXLEN(alg, pId, pIdNum) DEFINE_BENCH_CTX_PARA_TIMES_FIXLEN(alg, pId, pIdNum, 10000)
#define DEFINE_BENCH_CTX(alg)                          DEFINE_BENCH_CTX_PARA(alg, NULL, 0)
#define DEFINE_BENCH_CTX_FIXLEN(alg)                   DEFINE_BENCH_CTX_PARA_FIXLEN(alg, NULL, 0)

bool MatchAlgorithm(const char *pattern, const char *name);
const char *GetAlgName(int32_t hashId);

#endif /* BENCHMARK_H */
