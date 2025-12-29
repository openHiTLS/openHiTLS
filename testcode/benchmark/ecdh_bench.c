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

static int32_t EcdhSetUp(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t paraId)
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
        printf("Failed to gen ecdh key.\n");
        return ret;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void EcdhTearDown(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t EcdhKeyGen(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    int32_t paraId = opts->paraId;
    const char *curve = GetAlgName(paraId);

    BENCH_TIMES_VA(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts->times, "%s ecdh keyGen", curve);
    return rc;
}

static int32_t EcdhKeyDerive(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t paraId = opts->paraId;
    const char *curve = GetAlgName(paraId);

    // Create a peer context for key exchange
    CRYPT_EAL_PkeyCtx *peerCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    if (peerCtx == NULL) {
        printf("Failed to create peer context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }

    rc = CRYPT_EAL_PkeySetParaById(peerCtx, paraId);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to set peer para: %d.\n", paraId);
        CRYPT_EAL_PkeyFreeCtx(peerCtx);
        return rc;
    }

    rc = CRYPT_EAL_PkeyGen(peerCtx);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to gen peer key.\n");
        CRYPT_EAL_PkeyFreeCtx(peerCtx);
        return rc;
    }

    uint8_t sharedKey[256];
    uint32_t sharedKeyLen = sizeof(sharedKey);

    BENCH_TIMES_VA(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, sharedKey, &sharedKeyLen), rc, CRYPT_SUCCESS, -1,
                   opts->times, "%s ecdh keyDerive", curve);

    CRYPT_EAL_PkeyFreeCtx(peerCtx);
    return rc;
}

static int32_t g_paraIds[] = {
    CRYPT_ECC_NISTP192, CRYPT_ECC_NISTP224, CRYPT_ECC_NISTP256, CRYPT_ECC_NISTP384, CRYPT_ECC_NISTP521,
    CRYPT_ECC_BRAINPOOLP256R1, CRYPT_ECC_BRAINPOOLP384R1, CRYPT_ECC_BRAINPOOLP512R1,
};

DEFINE_OPS_KX(Ecdh, CRYPT_PKEY_ECDH);
DEFINE_BENCH_CTX_PARA_FIXLEN(Ecdh, g_paraIds, SIZEOF(g_paraIds));