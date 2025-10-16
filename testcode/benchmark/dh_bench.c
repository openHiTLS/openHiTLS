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

static int32_t DhSetUp(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t paraId)
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
        printf("Failed to gen dh key.\n");
        return ret;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void DhTearDown(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t DhKeyGen(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    int32_t paraId = opts->paraId;
    const char *group = GetAlgName(paraId);

    BENCH_TIMES_VA(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts->times, "%s dh keyGen", group);
    return rc;
}

static int32_t DhKeyDerive(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t paraId = opts->paraId;
    const char *group = GetAlgName(paraId);

    // Create a peer context for key exchange
    CRYPT_EAL_PkeyCtx *peerCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DH);
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

    uint8_t sharedKey[4096]; // DH can have larger key sizes
    uint32_t sharedKeyLen = sizeof(sharedKey);

    BENCH_TIMES_VA(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, sharedKey, &sharedKeyLen), rc, CRYPT_SUCCESS, -1,
                   opts->times, "%s dh keyDervie", group);

    CRYPT_EAL_PkeyFreeCtx(peerCtx);
    return rc;
}

static int32_t g_paraIds[] = {
    CRYPT_DH_RFC2409_768,  CRYPT_DH_RFC2409_1024, CRYPT_DH_RFC3526_1536, CRYPT_DH_RFC3526_2048, CRYPT_DH_RFC3526_3072,
    CRYPT_DH_RFC3526_4096, CRYPT_DH_RFC3526_6144, CRYPT_DH_RFC3526_8192, CRYPT_DH_RFC7919_2048, CRYPT_DH_RFC7919_3072,
    CRYPT_DH_RFC7919_4096, CRYPT_DH_RFC7919_6144, CRYPT_DH_RFC7919_8192,
};

DEFINE_OPS_KX(Dh, CRYPT_PKEY_DH);
DEFINE_BENCH_CTX_PARA_TIMES_FIXLEN(Dh, g_paraIds, SIZEOF(g_paraIds), 1000);