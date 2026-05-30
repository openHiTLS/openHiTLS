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
#include "benchmark.h"

static int32_t SlhDsaSetUp(void **ctx, const Operation *op, int32_t algId, int32_t paraId)
{
    (void)op;
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(algId);
    if (pkeyCtx == NULL) {
        printf("Failed to create pkey context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t paraAlgId = paraId;
    int32_t rc = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&paraAlgId, sizeof(paraAlgId));
    if (rc != CRYPT_SUCCESS) {
        return rc;
    }
    rc = CRYPT_EAL_PkeyGen(pkeyCtx);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to gen slhdsa key.\n");
        return rc;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void SlhDsaTearDown(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t SlhDsaKeyGen(void *ctx, const BenchExecOptions *opts)
{
    int32_t rc = CRYPT_SUCCESS;
    BENCH_RUN_VA(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts, "%s keyGen", GetAlgName(opts->paraId));
    return rc;
}

static int32_t GetHashId(const BenchExecOptions *opts)
{
    return opts->hashId;
}

static int32_t SlhDsaSignInner(void *ctx, int32_t hashId, int32_t len)
{
    static uint8_t sign[51200]; // maximum len is 49856
    uint32_t signLen = sizeof(sign);
    return CRYPT_EAL_PkeySign(ctx, hashId, BENCH_PLAIN, len, sign, &signLen);
}

static int32_t SlhDsaSign(void *ctx, const BenchExecOptions *opts)
{
    int32_t rc;
    int32_t hashId = GetHashId(opts);
    BENCH_RUN_VA(SlhDsaSignInner(ctx, hashId, opts->len), rc, CRYPT_SUCCESS, opts->len, opts, "%s sign",
                   GetAlgName(opts->paraId));
    return rc;
}

static int32_t SlhDsaVerify(void *ctx, const BenchExecOptions *opts)
{
    static uint8_t sign[51200]; // maximum len is 49856
    uint32_t signLen = sizeof(sign);
    int32_t hashId = GetHashId(opts);
    int32_t rc = CRYPT_EAL_PkeySign(ctx, hashId, BENCH_PLAIN, opts->len, sign, &signLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to sign\n");
        return rc;
    }
    BENCH_RUN_VA(CRYPT_EAL_PkeyVerify(ctx, hashId, BENCH_PLAIN, opts->len, sign, signLen), rc, CRYPT_SUCCESS,
        opts->len, opts, "%s verify", GetAlgName(opts->paraId));
    return rc;
}

static int32_t g_paraIds[] = {
    CRYPT_SLH_DSA_SHA2_128S, CRYPT_SLH_DSA_SHAKE_128S, CRYPT_SLH_DSA_SHA2_128F, CRYPT_SLH_DSA_SHAKE_128F,
    CRYPT_SLH_DSA_SHA2_192S, CRYPT_SLH_DSA_SHAKE_192S, CRYPT_SLH_DSA_SHA2_192F, CRYPT_SLH_DSA_SHAKE_192F,
    CRYPT_SLH_DSA_SHA2_256S, CRYPT_SLH_DSA_SHAKE_256S, CRYPT_SLH_DSA_SHA2_256F, CRYPT_SLH_DSA_SHAKE_256F,
};

DEFINE_OPS_SIGN(SlhDsa, CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHA256);
DEFINE_BENCH_CTX_PARA_FIXLEN(SlhDsa, g_paraIds, SIZEOF(g_paraIds));
