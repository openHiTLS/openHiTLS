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

static int32_t EcdsaSetUp(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t paraId)
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(ops->algId);
    if (pkeyCtx == NULL) {
        printf("Failed to create pkey context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeySetParaById(pkeyCtx, paraId);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to set para: %d.\n", paraId);
        return ret;
    }

    ret = CRYPT_EAL_PkeyGen(pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to gen ecdsa key.\n");
        return ret;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void EcdsaTearDown(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t EcdsaKeyGen(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    int32_t paraId = opts->paraId;
    const char *curve = GetAlgName(paraId);

    BENCH_TIMES_VA(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts->times, "%s keyGen", curve);
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

static int32_t EcdsaSignInner(void *ctx, int32_t hashId, int32_t len)
{
    uint8_t signature[256];
    uint32_t signatureLen = sizeof(signature);
    return CRYPT_EAL_PkeySign(ctx, hashId, g_plain, len, signature, &signatureLen);
}

static int32_t EcdsaSign(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t paraId = opts->paraId;
    const char *curve = GetAlgName(paraId);
    int32_t hashId = GetHashId(bench, opts);
    if (hashId == -1) {
        return -1;
    }
    const char *mdName = GetAlgName(hashId);

    BENCH_TIMES_VA(EcdsaSignInner(ctx, hashId, opts->len), rc, CRYPT_SUCCESS, -1, opts->times, "%s-%s sign", curve,
                   mdName);
    return rc;
}

static int32_t EcdsaVerify(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t paraId = opts->paraId;
    const char *curve = GetAlgName(paraId);
    int32_t hashId = GetHashId(bench, opts);
    if (hashId == -1) {
        return -1;
    }

    uint8_t signature[256];
    uint32_t signatureLen = sizeof(signature);
    rc = CRYPT_EAL_PkeySign(ctx, hashId, g_plain, opts->len, signature, &signatureLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to sign\n");
        return rc;
    }
    const char *mdName = GetAlgName(hashId);

    BENCH_TIMES_VA(CRYPT_EAL_PkeyVerify(ctx, hashId, g_plain, opts->len, signature, signatureLen), rc, CRYPT_SUCCESS,
                   -1, opts->times, "%s-%s verify", curve, mdName);
    return rc;
}

static int32_t g_paraIds[] = {
    CRYPT_ECC_NISTP192, CRYPT_ECC_NISTP224, CRYPT_ECC_NISTP256, CRYPT_ECC_NISTP384, CRYPT_ECC_NISTP521,
    CRYPT_ECC_BRAINPOOLP256R1, CRYPT_ECC_BRAINPOOLP384R1, CRYPT_ECC_BRAINPOOLP512R1,
};

DEFINE_OPS_SIGN(Ecdsa, CRYPT_PKEY_ECDSA, CRYPT_MD_SHA256);
DEFINE_BENCH_CTX_PARA_FIXLEN(Ecdsa, g_paraIds, SIZEOF(g_paraIds));
