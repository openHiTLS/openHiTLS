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

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#define BENCH_TIMES(func, rc, ok, len, times, header)                                                    \
    {                                                                                                    \
        struct timespec start, end;                                                                      \
        clock_gettime(CLOCK_REALTIME, &start);                                                           \
        for (int i = 0; i < times; i++) {                                                                \
            rc = func;                                                                                   \
            if (rc != ok) {                                                                              \
                printf("Error: %s, ret = %08x\n", #func, rc);                                            \
                break;                                                                                   \
            }                                                                                            \
        }                                                                                                \
        clock_gettime(CLOCK_REALTIME, &end);                                                             \
        uint64_t elapsedTime = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec); \
        printf("%-35s, %10d, %15d, %16.2f, %20.2f\n", header, len, times, (double)elapsedTime / 1000000, \
               ((double)times * 1000000000) / elapsedTime);                                              \
    }

#define BENCH_TIMES_VA(func, rc, ok, len, times, headerFmt, ...)    \
    {                                                               \
        char header[256] = {0};                                     \
        snprintf(header, sizeof(header), headerFmt, ##__VA_ARGS__); \
        BENCH_TIMES(func, rc, ok, len, times, header);              \
    }

#define BENCH_SECONDS(func, rc, ok, len, secs, header)                                               \
    {                                                                                                \
        struct timespec start, end;                                                                  \
        uint64_t totalTime = secs * 1000000000;                                                      \
        uint64_t elapsedTime = 0;                                                                    \
        uint64_t cnt = 0;                                                                            \
        while (elapsedTime < totalTime) {                                                            \
            clock_gettime(CLOCK_REALTIME, &start);                                                   \
            rc = func;                                                                               \
            if (rc != ok) {                                                                          \
                printf("Error: %s, ret = %08x\n", #func, rc);                                        \
                break;                                                                               \
            }                                                                                        \
            clock_gettime(CLOCK_REALTIME, &end);                                                     \
            elapsedTime += (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec); \
            cnt++;                                                                                   \
        }                                                                                            \
        printf("%-35s, %10d, %15d, %16.2f, %20.2f\n", header, len, cnt, elapsedTime / 1000000,       \
               ((double)times * 1000000000) / elapsedTime);                                          \
    }

#define BENCH_SETUP(ctx, bench, ops, id)                               \
    do {                                                               \
        int32_t ret;                                                   \
        ret = ops->setUp(&ctx, bench, ops, id);                        \
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

typedef struct BenchCtx_ BenchCtx;
typedef struct CtxOps_ CtxOps;
// every benchmark testcase should define "NewCtx" and "FreeCtx"
typedef int32_t (*SetUp)(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t id);
typedef void (*TearDown)(void *ctx);
typedef int32_t (*KeyGen)(void *ctx, BenchCtx *bench, BenchOptions *opts);
typedef int32_t (*KeyDerive)(void *ctx, BenchCtx *bench, BenchOptions *opts);
typedef int32_t (*Enc)(void *ctx, BenchCtx *bench, BenchOptions *opts);
typedef int32_t (*Dec)(void *ctx, BenchCtx *bench, BenchOptions *opts);
typedef int32_t (*Sign)(void *ctx, BenchCtx *bench, BenchOptions *opts);
typedef int32_t (*Verify)(void *ctx, BenchCtx *bench, BenchOptions *opts);
typedef int32_t (*OneShot)(void *ctx, BenchCtx *bench, BenchOptions *opts);
typedef int32_t (*Encaps)(void *ctx, BenchCtx *bench, BenchOptions *opts);
typedef int32_t (*Decaps)(void *ctx, BenchCtx *bench, BenchOptions *opts);

// return true if not be filetered; else return false.
typedef bool (*ParaFilterCb)(BenchOptions *opts, int32_t paraId);

typedef struct {
    uint32_t id;
    const char *name;
    void *oper;
} Operation;

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

static int32_t g_lens[] = {16, 64, 256, 1024, 8192, 16384};
static uint8_t g_plain[16384];
static uint8_t g_out[16384];
static uint8_t g_key[32] = {1};
static uint8_t g_iv[16];

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
    const char *desc;
    const CtxOps *ctxOps;
    int32_t opsNum;
    int32_t *paraIds;
    uint32_t paraIdsNum;
    int32_t *lens;
    uint32_t lensNum;
    int32_t times;
    int32_t seconds;
} BenchCtx;

#define DEFINE_BENCH_CTX_PARA_TIMES_LEN(alg, pId, pIdNum, ts, l, ln) \
    BenchCtx alg##BenchCtx = {                                       \
        .name = #alg,                                                \
        .desc = #alg " benchmark",                                   \
        .ctxOps = &alg##CtxOps,                                      \
        .opsNum = alg##_OPS_NUM,                                     \
        .paraIds = pId,                                              \
        .paraIdsNum = pIdNum,                                        \
        .lens = l,                                                   \
        .lensNum = ln,                                               \
        .times = ts,                                                 \
        .seconds = 0,                                                \
    }
#define DEFINE_BENCH_CTX_PARA_TIMES(alg, pId, pIdNum, ts) \
    DEFINE_BENCH_CTX_PARA_TIMES_LEN(alg, pId, pIdNum, ts, g_lens, SIZEOF(g_lens))

#define DEFINE_BENCH_CTX_PARA_TIMES_FIXLEN(alg, pId, pIdNum, ts) \
    DEFINE_BENCH_CTX_PARA_TIMES_LEN(alg, pId, pIdNum, ts, g_lens, 1)
// default to run 10000 times
#define DEFINE_BENCH_CTX_PARA(alg, pId, pIdNum)        DEFINE_BENCH_CTX_PARA_TIMES(alg, pId, pIdNum, 10000)
#define DEFINE_BENCH_CTX_PARA_FIXLEN(alg, pId, pIdNum) DEFINE_BENCH_CTX_PARA_TIMES_FIXLEN(alg, pId, pIdNum, 10000)
#define DEFINE_BENCH_CTX(alg)                          DEFINE_BENCH_CTX_PARA(alg, NULL, 0)
#define DEFINE_BENCH_CTX_FIXLEN(alg)                   DEFINE_BENCH_CTX_PARA_FIXLEN(alg, NULL, 0)

bool MatchAlgorithm(const char *pattern, const char *name);
const char *GetAlgName(int32_t hashId);

#endif /* BENCHMARK_H */
