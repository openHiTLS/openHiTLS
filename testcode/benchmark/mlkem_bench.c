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

static const char *GetParaName(int32_t paraId)
{
    switch (paraId) {
        case CRYPT_KEM_TYPE_MLKEM_512:
            return "mlkem-512";
        case CRYPT_KEM_TYPE_MLKEM_768:
            return "mlkem-768";
        case CRYPT_KEM_TYPE_MLKEM_1024:
            return "mlkem-1024";
        default:
            return "unknown";
    }
    return "";
}

static int32_t MlkemSetUp(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t paraId)
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
        printf("Failed to gen mlkem key.\n");
        return ret;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void MlkemTearDown(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t MlkemKeyGen(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    BENCH_TIMES_VA(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts->times, "%s keyGen", GetParaName(opts->paraId));
    return rc;
}

static int32_t MlkemEncaps(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    uint8_t ciphertext[2048]; // ML-KEM can have larger ciphertexts
    uint32_t ciphertextLen = sizeof(ciphertext);
    uint8_t sharedKey[32];
    uint32_t sharedKeyLen = sizeof(sharedKey);

    BENCH_TIMES_VA(CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &ciphertextLen, sharedKey, &sharedKeyLen), rc, CRYPT_SUCCESS,
                   -1, opts->times, "%s encaps", GetParaName(opts->paraId));
    return rc;
}

static int32_t MlkemDecaps(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    uint8_t ciphertext[2048]; // ML-KEM can have larger ciphertexts
    uint32_t ciphertextLen = sizeof(ciphertext);
    uint8_t sharedKey[32];
    uint32_t sharedKeyLen = sizeof(sharedKey);

    // First encap to get a valid ciphertext
    rc = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &ciphertextLen, sharedKey, &sharedKeyLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to encap\n");
        return rc;
    }

    BENCH_TIMES_VA(CRYPT_EAL_PkeyDecaps(ctx, ciphertext, ciphertextLen, sharedKey, &sharedKeyLen), rc, CRYPT_SUCCESS,
                   -1, opts->times, "%s decaps", GetParaName(opts->paraId));
    return rc;
}

static int32_t g_paraIds[] = {
    CRYPT_KEM_TYPE_MLKEM_512,
    CRYPT_KEM_TYPE_MLKEM_768,
    CRYPT_KEM_TYPE_MLKEM_1024,
};

DEFINE_OPS_KEM(Mlkem, CRYPT_PKEY_ML_KEM);
DEFINE_BENCH_CTX_PARA_FIXLEN(Mlkem, g_paraIds, SIZEOF(g_paraIds));