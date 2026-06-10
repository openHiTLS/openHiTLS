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
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
 * PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "benchmark.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"

#define XMSS_NAIVE_SIGN_ID 1024U
#define XMSS_BDS_LONG_SIGN_ID 2048U
#define XMSS_BENCH_MAX_N   64U
#define XMSS_SINGLE_TREE_SIGN_ROUNDS 1024U
#define XMSSMT_LONG_SIGN_ROUNDS 16385U

typedef struct {
    CRYPT_EAL_PkeyCtx *bds;
    CRYPT_EAL_PkeyCtx *naive;
    uint8_t seed[XMSS_BENCH_MAX_N];
    uint8_t prf[XMSS_BENCH_MAX_N];
    uint8_t pubSeed[XMSS_BENCH_MAX_N];
    uint8_t pubRoot[XMSS_BENCH_MAX_N];
    uint8_t *sig;
    uint32_t sigLen;
    int32_t paraId;
    CRYPT_PKEY_AlgId pkeyId;
} XmssBenchCtx;

typedef struct {
    int32_t paraId;
    const char *name;
    uint32_t n;
} XmssBenchPara;

static const XmssBenchPara g_xmssBenchParas[] = {
    {CRYPT_XMSS_SHA2_10_256, "xmss-sha2-10-256", 32},
    {CRYPT_XMSSMT_SHA2_20_2_256, "xmssmt-sha2-20/2-256", 32},
    {CRYPT_XMSSMT_SHA2_20_4_256, "xmssmt-sha2-20/4-256", 32},
};

static int32_t g_paraIds[] = {
    CRYPT_XMSS_SHA2_10_256,
    CRYPT_XMSSMT_SHA2_20_2_256,
    CRYPT_XMSSMT_SHA2_20_4_256,
};

static int32_t g_lens[] = {
    32,
};

static CRYPT_PKEY_AlgId XmssGetPkeyId(int32_t paraId)
{
    return (paraId >= CRYPT_XMSSMT_SHA2_20_2_256) ? CRYPT_PKEY_XMSSMT : CRYPT_PKEY_XMSS;
}

static const char *XmssGetParaName(int32_t paraId)
{
    for (uint32_t i = 0; i < SIZEOF(g_xmssBenchParas); i++) {
        if (g_xmssBenchParas[i].paraId == paraId) {
            return g_xmssBenchParas[i].name;
        }
    }
    return "xmss-unknown";
}

static uint32_t XmssGetParaN(int32_t paraId)
{
    for (uint32_t i = 0; i < SIZEOF(g_xmssBenchParas); i++) {
        if (g_xmssBenchParas[i].paraId == paraId) {
            return g_xmssBenchParas[i].n;
        }
    }
    return 0;
}

static int32_t XmssSetPara(CRYPT_EAL_PkeyCtx *ctx, int32_t paraId)
{
    return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &paraId, sizeof(paraId));
}

static int32_t XmssMakeNaiveCtx(XmssBenchCtx *bench)
{
    uint32_t n = XmssGetParaN(bench->paraId);
    if (n == 0 || n > XMSS_BENCH_MAX_N) {
        return CRYPT_INVALID_ARG;
    }

    bench->naive = CRYPT_EAL_PkeyNewCtx(bench->pkeyId);
    if (bench->naive == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = XmssSetPara(bench->naive, bench->paraId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_EAL_PkeyPrv prv = {
        .id = bench->pkeyId,
        .key.xmssPrv =
            {
                .seed = bench->seed,
                .prf = bench->prf,
                .index = 0,
                .pub =
                    {
                        .seed = bench->pubSeed,
                        .root = bench->pubRoot,
                        .len = n,
                    },
            },
    };

    ret = CRYPT_EAL_PkeyGetPrv(bench->bds, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_EAL_PkeySetPrv(bench->naive, &prv);
}

static int32_t XmssPrepareSignCtx(XmssBenchCtx *bench)
{
    int32_t ret = CRYPT_EAL_PkeyGen(bench->bds);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    bench->sigLen = CRYPT_EAL_PkeyGetSignLen(bench->bds);
    if (bench->sigLen == 0) {
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }
    bench->sig = malloc(bench->sigLen);
    if (bench->sig == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    return XmssMakeNaiveCtx(bench);
}

static int32_t XmssSetUp(void **ctx, const Operation *op, int32_t algId, int32_t paraId)
{
    (void)algId;
    XmssBenchCtx *bench = calloc(1, sizeof(*bench));
    if (bench == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    bench->paraId = paraId;
    bench->pkeyId = XmssGetPkeyId(paraId);
    bench->bds = CRYPT_EAL_PkeyNewCtx(bench->pkeyId);
    if (bench->bds == NULL) {
        free(bench);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = XmssSetPara(bench->bds, paraId);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(bench->bds);
        free(bench);
        return ret;
    }

    if (op->id != KEY_GEN_ID) {
        ret = XmssPrepareSignCtx(bench);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(bench->naive);
            CRYPT_EAL_PkeyFreeCtx(bench->bds);
            free(bench->sig);
            free(bench);
            return ret;
        }
    }

    *ctx = bench;
    return CRYPT_SUCCESS;
}

static void XmssTearDown(void *ctx)
{
    XmssBenchCtx *bench = ctx;
    if (bench == NULL) {
        return;
    }
    CRYPT_EAL_PkeyFreeCtx(bench->naive);
    CRYPT_EAL_PkeyFreeCtx(bench->bds);
    free(bench->sig);
    free(bench);
}

static int32_t XmssKeyGen(void *ctx, const BenchExecOptions *opts)
{
    XmssBenchCtx *bench = ctx;
    int32_t rc = CRYPT_SUCCESS;
    BENCH_RUN_VA(CRYPT_EAL_PkeyGen(bench->bds), rc, CRYPT_SUCCESS, -1, opts, "%s keyGen",
                 XmssGetParaName(opts->paraId));
    return rc;
}

static int32_t XmssSignOnce(CRYPT_EAL_PkeyCtx *ctx, XmssBenchCtx *bench, int32_t msgLen)
{
    uint32_t sigLen = bench->sigLen;
    return CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA256, BENCH_PLAIN, (uint32_t)msgLen, bench->sig, &sigLen);
}

static int32_t XmssSign(void *ctx, const BenchExecOptions *opts)
{
    XmssBenchCtx *bench = ctx;
    int32_t rc = CRYPT_SUCCESS;
    BENCH_RUN_VA(XmssSignOnce(bench->bds, bench, opts->len), rc, CRYPT_SUCCESS, opts->len, opts, "%s bds sign",
                 XmssGetParaName(opts->paraId));
    return rc;
}

/*
 * A short benchmark does not reach an XMSSMT state switch. Run one continuous
 * sequence across multiple higher-layer boundaries so the reported long-run
 * average includes recurring tree-state transition work.
 */
static int32_t XmssBdsLongSign(void *ctx, const BenchExecOptions *opts)
{
    XmssBenchCtx *bench = ctx;
    uint32_t rounds = (bench->pkeyId == CRYPT_PKEY_XMSSMT) ? XMSSMT_LONG_SIGN_ROUNDS :
        XMSS_SINGLE_TREE_SIGN_ROUNDS;
    int32_t rc = CRYPT_SUCCESS;
    BENCH_TIMES_VA(XmssSignOnce(bench->bds, bench, opts->len), rc, CRYPT_SUCCESS, opts->len, rounds,
        "%s bds long-run sign", XmssGetParaName(opts->paraId));
    return rc;
}

static int32_t XmssNaiveSign(void *ctx, const BenchExecOptions *opts)
{
    XmssBenchCtx *bench = ctx;
    int32_t rc = CRYPT_SUCCESS;
    BENCH_RUN_VA(XmssSignOnce(bench->naive, bench, opts->len), rc, CRYPT_SUCCESS, opts->len, opts,
        "%s naive sign sample", XmssGetParaName(opts->paraId));
    return rc;
}

static int32_t XmssVerify(void *ctx, const BenchExecOptions *opts)
{
    XmssBenchCtx *bench = ctx;
    uint32_t sigLen = bench->sigLen;
    int32_t rc = CRYPT_EAL_PkeySign(bench->bds, CRYPT_MD_SHA256, BENCH_PLAIN, (uint32_t)opts->len, bench->sig, &sigLen);
    if (rc != CRYPT_SUCCESS) {
        return rc;
    }

    BENCH_RUN_VA(
        CRYPT_EAL_PkeyVerify(bench->bds, CRYPT_MD_SHA256, BENCH_PLAIN, (uint32_t)opts->len, bench->sig, sigLen), rc,
        CRYPT_SUCCESS, opts->len, opts, "%s verify", XmssGetParaName(opts->paraId));
    return rc;
}

enum {
    XMSS_OPS_NUM = COUNT_OPS(DEFINE_OPER(KEY_GEN_ID, XmssKeyGen), DEFINE_OPER(SIGN_ID, XmssSign),
                             DEFINE_OPER(XMSS_BDS_LONG_SIGN_ID, XmssBdsLongSign),
                             DEFINE_OPER(XMSS_NAIVE_SIGN_ID, XmssNaiveSign), DEFINE_OPER(VERIFY_ID, XmssVerify))
};

static const CtxOps XmssCtxOps = {
    .algId = CRYPT_PKEY_XMSS,
    .hashId = CRYPT_MD_SHA256,
    .opsNum = XMSS_OPS_NUM,
    .setUp = XmssSetUp,
    .tearDown = XmssTearDown,
    .ops =
        {
            DEFINE_OPER(KEY_GEN_ID, XmssKeyGen),
            DEFINE_OPER(SIGN_ID, XmssSign),
            DEFINE_OPER(XMSS_BDS_LONG_SIGN_ID, XmssBdsLongSign),
            DEFINE_OPER(XMSS_NAIVE_SIGN_ID, XmssNaiveSign),
            DEFINE_OPER(VERIFY_ID, XmssVerify),
        },
};

DEFINE_BENCH_CTX_PARA_TIMES_LEN(Xmss, g_paraIds, SIZEOF(g_paraIds), 8, g_lens, SIZEOF(g_lens));
