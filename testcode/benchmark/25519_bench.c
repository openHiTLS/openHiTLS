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

static int32_t X25519SetUp(void **ctx, const Operation *op, int32_t algId, int32_t paraId)
{
    (void)op;
    (void)paraId;
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(algId);
    if (pkeyCtx == NULL) {
        printf("Failed to create pkey context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_PkeyGen(pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to gen curve25519 key.\n");
        return ret;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void X25519TearDown(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t X25519KeyGen(void *ctx, const BenchExecOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    BENCH_RUN(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts, "X25519 keyGen");
    return rc;
}

static int32_t Ed25519SetUp(void **ctx, const Operation *op, int32_t algId, int32_t paraId)
{
    return X25519SetUp(ctx, op, algId, paraId);
}
static void Ed25519TearDown(void *ctx)
{
    X25519TearDown(ctx);
}

static int32_t Ed25519KeyGen(void *ctx, const BenchExecOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    BENCH_RUN(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts, "Ed25519 keyGen");
    return rc;
}

static int32_t X25519KeyDerive(void *ctx, const BenchExecOptions *opts)
{
    int rc;
    CRYPT_EAL_PkeyCtx *peerCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X25519);
    if (peerCtx == NULL) {
        printf("Failed to create peer context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }

    rc = CRYPT_EAL_PkeyGen(peerCtx);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to gen peer key.\n");
        CRYPT_EAL_PkeyFreeCtx(peerCtx);
        return rc;
    }

    uint8_t sharedKey[32];
    uint32_t sharedKeyLen = sizeof(sharedKey);

    BENCH_RUN(CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, sharedKey, &sharedKeyLen), rc, CRYPT_SUCCESS, -1,
        opts, "X25519 keyDerive");

    CRYPT_EAL_PkeyFreeCtx(peerCtx);
    return rc;
}

static int32_t GetHashId(const BenchExecOptions *opts)
{
    int32_t hashId = opts->hashId;
    if (hashId != CRYPT_MD_SHA512) {
        printf("Wrong Hash Algorithm Id for Ed25519. Must be SHA512.");
        return -1;
    }
    return hashId;
}

static int32_t Ed25519SignInner(void *ctx, int32_t hashId)
{
    uint8_t plainText[32] = {0};
    uint8_t signature[64];
    uint32_t signatureLen = sizeof(signature);
    return CRYPT_EAL_PkeySign(ctx, hashId, plainText, sizeof(plainText), signature, &signatureLen);
}

static int32_t Ed25519Sign(void *ctx, const BenchExecOptions *opts)
{
    int rc;
    int32_t hashId = GetHashId(opts);
    if (hashId == -1) {
        return -1;
    }
    BENCH_RUN(Ed25519SignInner(ctx, hashId), rc, CRYPT_SUCCESS, -1, opts, "ed25519 sign");
    return rc;
}

static int32_t Ed25519Verify(void *ctx, const BenchExecOptions *opts)
{
    int rc;
    int32_t hashId = GetHashId(opts);
    if (hashId == -1) {
        return -1;
    }
    uint8_t plainText[32] = {0};
    uint8_t signature[64];
    uint32_t signatureLen = sizeof(signature);
    rc = CRYPT_EAL_PkeySign(ctx, hashId, plainText, sizeof(plainText), signature, &signatureLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to sign\n");
        return rc;
    }
    BENCH_RUN(CRYPT_EAL_PkeyVerify(ctx, hashId, plainText, sizeof(plainText), signature, signatureLen), rc,
                CRYPT_SUCCESS, -1, opts, "ed25519 verify");
    return rc;
}

DEFINE_OPS_KX(X25519, CRYPT_PKEY_X25519);
DEFINE_BENCH_CTX_FIXLEN(X25519);

DEFINE_OPS_SIGN(Ed25519, CRYPT_PKEY_ED25519, CRYPT_MD_SHA512);
DEFINE_BENCH_CTX_FIXLEN(Ed25519);
