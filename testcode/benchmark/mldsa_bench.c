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

#include <stddef.h>
#include <string.h>
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_md.h"
#include "benchmark.h"

const char *GetParaName(int32_t paraId)
{
    switch (paraId) {
        case CRYPT_MLDSA_TYPE_MLDSA_44:
            return "mldsa-44";
        case CRYPT_MLDSA_TYPE_MLDSA_65:
            return "mldsa-65";
        case CRYPT_MLDSA_TYPE_MLDSA_87:
            return "mldsa-87";
        default:
            break;
    }
    return "";
}

static int32_t MldsaSetUp(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t paraId)
{
    (void)paraId;
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(ops->algId);
    if (pkeyCtx == NULL) {
        printf("Failed to create pkey context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_PARA_BY_ID, &paraId, sizeof(paraId));
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to set mldsa alg info.\n");
        return ret;
    }
    ret = CRYPT_EAL_PkeyGen(pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to gen mldsa key.\n");
        return ret;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void MldsaTearDown(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t MldsaKeyGen(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    BENCH_TIMES_VA(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts->times, "%s keyGen", GetParaName(opts->paraId));
    return rc;
}

static int32_t GetHashId(BenchCtx *bench, BenchOptions *opts)
{
    int32_t hashId = bench->ctxOps->hashId;
    if (opts->hashId != -1) {
        hashId = opts->hashId;
    }
    return hashId;
}

static int32_t MldsaSignInner(void *ctx, int32_t hashId)
{
    uint8_t plainText[32];
    uint8_t signature[5120]; // ML-DSA can have larger signatures
    uint32_t signatureLen = sizeof(signature);
    return CRYPT_EAL_PkeySign(ctx, hashId, plainText, sizeof(plainText), signature, &signatureLen);
}

static int32_t MldsaSign(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t hashId = GetHashId(bench, opts);
    if (hashId == -1) {
        return -1;
    }
    BENCH_TIMES_VA(MldsaSignInner(ctx, hashId), rc, CRYPT_SUCCESS, -1, opts->times, "%s sign",
                   GetParaName(opts->paraId));
    return rc;
}

static int32_t MldsaVerify(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t hashId = GetHashId(bench, opts);
    if (hashId == -1) {
        return -1;
    }
    uint8_t plainText[32];
    uint8_t signature[5120]; // ML-DSA can have larger signatures
    uint32_t signatureLen = sizeof(signature);
    rc = CRYPT_EAL_PkeySign(ctx, hashId, plainText, sizeof(plainText), signature, &signatureLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to sign\n");
        return rc;
    }
    BENCH_TIMES_VA(CRYPT_EAL_PkeyVerify(ctx, hashId, plainText, sizeof(plainText), signature, signatureLen), rc,
                   CRYPT_SUCCESS, -1, opts->times, "%s verify", GetParaName(opts->paraId));
    return rc;
}

static int32_t g_paraIds[] = {
    CRYPT_MLDSA_TYPE_MLDSA_44,
    CRYPT_MLDSA_TYPE_MLDSA_65,
    CRYPT_MLDSA_TYPE_MLDSA_87,
};

DEFINE_OPS_SIGN(Mldsa, CRYPT_PKEY_ML_DSA, CRYPT_MD_SHA256);
DEFINE_BENCH_CTX_PARA_FIXLEN(Mldsa, g_paraIds, SIZEOF(g_paraIds));