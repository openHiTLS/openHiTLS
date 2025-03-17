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

#define BENCH_TIMES(func, rc, ok, times, header)                                                         \
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
        printf("%-25s, %15ld, %20d, %20.2f\n", header, elapsedTime / 1000000000, times,                  \
               ((double)times * 1000000000) / elapsedTime);                                              \
    }

#define BENCH_SECONDS(func, rc, ok, secs, header)                                                    \
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
        printf("%-25s, %15ld, %20d, %20.2f\n", header, elapsedTime / 1000000000, cnt,                \
               ((double)times * 1000000000) / elapsedTime);                                          \
    }

#define BENCH_SETUP(ctx, ops)                     \
    do                                            \
    {                                             \
        int32_t ret;                              \
        ret = ops->newCtx(&ctx);                  \
        if (ret != CRYPT_SUCCESS) {               \
            printf("Failed to create context\n"); \
            return ret;                           \
        }                                         \
    }                                             \
    while (0)

#define BENCH_TEARDOWN(ctx, ops) \
    do {                         \
        ops->freeCtx(ctx);       \
    } while (0)

static inline void Hex2Bin(const char *hex, uint8_t *bin, uint32_t *len)
{
    *len = strlen(hex) / 2;
    for (uint32_t i = 0; i < *len; i++) {
        sscanf(hex + i * 2, "%2hhx", &bin[i]);
    }
}

typedef struct BenchCtx_ BenchCtx;
// every benchmark testcase should define "NewCtx" and "FreeCtx"
typedef int32_t (*NewCtx)(void **ctx);
typedef void (*FreeCtx)(void *ctx);
typedef int32_t (*KeyGen)(void *ctx, BenchCtx *bench);
typedef int32_t (*KeyDerive)(void *ctx, BenchCtx *bench);
typedef int32_t (*Enc)(void *ctx, BenchCtx *bench);
typedef int32_t (*Dec)(void *ctx, BenchCtx *bench);
typedef int32_t (*Sign)(void *ctx, BenchCtx *bench);
typedef int32_t (*Verify)(void *ctx, BenchCtx *bench);

typedef struct {
    uint32_t id;
    const char *name;
    void *oper;
} Operation;

typedef struct {
    NewCtx newCtx;
    FreeCtx freeCtx;
    Operation ops[];
} CtxOps;

#define DEFINE_OPER(id, oper) {id, #oper, oper}
#define DEFINE_OPS(alg) \
    static const CtxOps alg##CtxOps = { \
        .newCtx = alg##NewCtx, \
        .freeCtx = alg##FreeCtx, \
        .ops = {\
            DEFINE_OPER(1, alg##KeyGen), \
            DEFINE_OPER(2, alg##KeyDerive), \
            DEFINE_OPER(4, alg##Enc), \
            DEFINE_OPER(8, alg##Dec), \
            DEFINE_OPER(16, alg##Sign), \
            DEFINE_OPER(32, alg##Verify), \
        }, \
    }

#define KEY_GEN_ID 1U
#define KEY_DERIVE_ID 2U
#define ENC_ID 4U
#define DEC_ID 8U
#define SIGN_ID 16U
#define VERIFY_ID 32U

typedef struct BenchCtx_ {
    const char *name;
    const char *desc;
    const CtxOps *ctxOps;
    int32_t filteredOpsNum;
    int32_t times;
    int32_t seconds;
    int32_t len;
} BenchCtx;

#define DEFINE_BENCH_CTX(alg) \
    BenchCtx alg##BenchCtx = { \
        .name = #alg, \
        .desc = #alg " benchmark", \
        .ctxOps = &alg##CtxOps, \
        .filteredOpsNum = sizeof(alg##CtxOps.ops) / sizeof(alg##CtxOps.ops[0]), \
        .times = 10000, \
        .seconds = -1, \
    }

#endif /* BENCHMARK_H */