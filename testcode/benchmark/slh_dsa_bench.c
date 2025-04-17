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

static const char *SlhDsaHeader(BenchCtx *bench)
{
    switch (bench->ctxOps->subAlgId) {
        case CRYPT_SLH_DSA_SHA2_128S:
            return "SLH-DSA-SHA2-128S";
        case CRYPT_SLH_DSA_SHAKE_128S:
            return "SLH-DSA-SHAKE-128S";
        case CRYPT_SLH_DSA_SHA2_128F:
            return "SLH-DSA-SHA2-128F";
        case CRYPT_SLH_DSA_SHAKE_128F:
            return "SLH-DSA-SHAKE-128F";
        case CRYPT_SLH_DSA_SHA2_192S:
            return "SLH-DSA-SHA2-192S";
        case CRYPT_SLH_DSA_SHAKE_192S:
            return "SLH-DSA-SHAKE-192S";
        case CRYPT_SLH_DSA_SHA2_192F:
            return "SLH-DSA-SHA2-192F";
        case CRYPT_SLH_DSA_SHAKE_192F:
            return "SLH-DSA-SHAKE-192F";
        case CRYPT_SLH_DSA_SHA2_256S:
            return "SLH-DSA-SHA2-256S";
        case CRYPT_SLH_DSA_SHAKE_256S:
            return "SLH-DSA-SHAKE-256S";
        case CRYPT_SLH_DSA_SHA2_256F:
            return "SLH-DSA-SHA2-256F";
        case CRYPT_SLH_DSA_SHAKE_256F:
            return "SLH-DSA-SHAKE_256F";
        case CRYPT_SLH_DSA_ALG_ID_MAX:
            break;
    }
    return "";
}

static int32_t SlhDsaNewCtx(void **ctx, const CtxOps *ops)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(ops->algId);
    if (pkeyCtx == NULL) {
        printf("Failed to create pkey context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void SlhDsaFreeCtx(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t SlhDsaKeyGen(void *ctx, BenchCtx *bench)
{
    int rc = CRYPT_SUCCESS;
    CRYPT_SLH_DSA_AlgId algId = bench->ctxOps->subAlgId;
    rc = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SLH_DSA_ALG_ID, (void *)&algId, sizeof(algId));
    if (rc != CRYPT_SUCCESS) {
        return rc;
    }
    BENCH_TIMES_VA(rc = CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, bench->times, "%s keyGen", SlhDsaHeader(bench));
    return rc;
}

static int32_t SlhDsaSignInner(void *ctx)
{
    uint8_t plainText[32] = {0};
    uint8_t signature[51200];  // maximum len is 49856
    uint32_t signatureLen = sizeof(signature);
    return CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA256, plainText, sizeof(plainText), signature, &signatureLen);
}

static int32_t SlhDsaSign(void *ctx, BenchCtx *bench)
{
    int rc;
    BENCH_TIMES_VA(SlhDsaSignInner(ctx), rc, CRYPT_SUCCESS, bench->times, "%s sign", SlhDsaHeader(bench));
    return rc;
}

static int32_t SlhDsaVerify(void *ctx, BenchCtx *bench)
{
    int rc;
    uint8_t plainText[32] = {0};
    uint8_t signature[51200];  // maximum len is 49856
    uint32_t signatureLen = sizeof(signature);
    rc = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA256, plainText, sizeof(plainText), signature, &signatureLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to sign\n");
        return rc;
    }
    BENCH_TIMES_VA(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, plainText, sizeof(plainText), signature, signatureLen), rc,
                CRYPT_SUCCESS, bench->times, "%s verify", SlhDsaHeader(bench));
    return rc;
}

DEFINE_OPS_SIGN_ALG(SlhDsa, CRYPT_PKEY_SLH_DSA, CRYPT_SLH_DSA_SHA2_128S);
DEFINE_BENCH_CTX_TIMES(SlhDsa, 100);
