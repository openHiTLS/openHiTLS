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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_rand.h"
#include "benchmark.h"

extern BenchCtx Sm2BenchCtx;

BenchCtx *g_benchs[] = {
    &Sm2BenchCtx,
};

// 定义命令行选项结构
typedef struct {
    char *algorithm;     // -a 选项指定的算法
    uint32_t times;      // -t 选项指定的运行次数
    uint32_t seconds;    // -s 选项指定的运行时间
    uint32_t len;
} BenchOptions;

static void PrintUsage(void)
{
    printf("Usage: openhitls_benchmark [options]\n");
    printf("Options:\n");
    printf("  -a <algorithm>  Specify algorithm to benchmark (e.g., sm2*, sm2-KeyGen, *KeyGen)\n");
    printf("  -t <times>      Number of times to run each benchmark\n");
    printf("  -s <seconds>    Number of seconds to run each benchmark\n");
    printf("  -l <len>        Length of the payload to benchmark\n");
    printf("  -h             Show this help message\n");
}

static void ParseOptions(int argc, char **argv, BenchOptions *opts)
{
    int c;

    while ((c = getopt(argc, argv, "a:t:s:h")) != -1) {
        switch (c) {
            case 'a':
                opts->algorithm = optarg;
                break;
            case 't':
                opts->times = (uint32_t)atoi(optarg);
                break;
            case 's':
                opts->seconds = (uint32_t)atoi(optarg);
                break;
            case 'l':
                opts->len = (uint32_t)atoi(optarg);
                break;
            case 'h':
                PrintUsage();
                exit(0);
            default:
                PrintUsage();
                exit(1);
        }
    }
}

static bool MatchAlgorithm(const char *pattern, const char *name)
{
    if (pattern == NULL) {
        return true;
    }

    size_t patternLen = strlen(pattern);
    size_t nameLen = strlen(name);

    // process wildcard "*"
    if (pattern[0] == '*') {
        return (nameLen >= patternLen - 1) && 
               (strcmp(name + nameLen - (patternLen - 1), pattern + 1) == 0);
    }
    
    // process suffix wildcard (xxx*)
    if (pattern[patternLen - 1] == '*') {
        return strncmp(name, pattern, patternLen - 1) == 0;
    }

    return strcmp(pattern, name) == 0;
}

static void FilterBenchs(BenchOptions *opts, BenchCtx *benchs[], uint32_t *num)
{
    for (int i = 0; i < sizeof(g_benchs) / sizeof(g_benchs[0]); i++) {
        if (!MatchAlgorithm(opts->algorithm, g_benchs[i]->name)) {
            continue;
        }
        benchs[*num] = g_benchs[i];
        benchs[*num]->times = opts->times;
        benchs[*num]->seconds = opts->seconds;
        benchs[*num]->len = opts->len;
        (*num)++;
    }
}

static int32_t InstantOperation(const Operation *op, void *ctx, BenchCtx *bench)
{
    if (op->id & KEY_GEN_ID) {
        return ((KeyGen)op->oper)(ctx, bench);
    }
    if (op->id & KEY_DERIVE_ID) {
        return ((KeyDerive)op->oper)(ctx, bench);
    }
    if (op->id & ENC_ID) {
        return ((Enc)op->oper)(ctx, bench);
    }
    if (op->id & DEC_ID) {
        return ((Dec)op->oper)(ctx, bench);
    }
    if (op->id & SIGN_ID) {
        return ((Sign)op->oper)(ctx, bench);
    }
    if (op->id & VERIFY_ID) {
        return ((Verify)op->oper)(ctx, bench);
    }
}

int main(int argc, char **argv)
{
    int32_t ret;
    BenchOptions opts;
    memset(&opts, 0, sizeof(BenchOptions));

    // default options
    opts.times = 10000;
    opts.seconds = 3;
    opts.len = 1024;
    ParseOptions(argc, argv, &opts);
    
    if (CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) != CRYPT_SUCCESS) {
        printf("Failed to initialize random number generator\n");
        return -1;
    }

    BenchCtx *benchs[sizeof(g_benchs) / sizeof(g_benchs[0])] = {0};
    uint32_t num = 0;
    FilterBenchs(&opts, benchs, &num);

    if (num > 0) {
        printf("%-25s, %15s, %20s, %20s\n", "algorithm operation", "time elapsed(s)", "run times", "ops");
    }

    for (int i = 0; i < num; i++) {
        const CtxOps *ctxOps = benchs[i]->ctxOps;
        void *ctx = NULL;

        BENCH_SETUP(ctx, ctxOps);

        for (int j = 0; j < benchs[i]->filteredOpsNum; j++) {
            const Operation *op = &ctxOps->ops[j];
            ret = InstantOperation(op, ctx, benchs[i]);
            if (ret != CRYPT_SUCCESS) {
                printf("Failed to %s, ret = %08x\n", op->name, ret);
            }
        }

        BENCH_TEARDOWN(ctx, ctxOps);
    }

    return 0;
}