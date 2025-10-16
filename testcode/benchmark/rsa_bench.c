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

static int32_t RsaSetUp(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t paraId)
{
    (void)paraId;
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(ops->algId);
    if (pkeyCtx == NULL) {
        printf("Failed to create pkey context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_PkeyGen(pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to gen rsa key.\n");
        return ret;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void RsaTearDown(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t RsaKeyGen(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    BENCH_TIMES(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts->times, "rsa keyGen");
    return rc;
}

static int32_t RsaEncInner(void *ctx)
{
    uint8_t plainText[32];
    uint8_t cipherText[512]; // RSA can have larger output
    uint32_t outLen = sizeof(cipherText);
    return CRYPT_EAL_PkeyEncrypt(ctx, plainText, sizeof(plainText), cipherText, &outLen);
}

static int32_t RsaEnc(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    BENCH_TIMES(RsaEncInner(ctx), rc, CRYPT_SUCCESS, -1, opts->times, "rsa enc");
    return rc;
}

static int32_t RsaDec(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    uint8_t plainText[32];
    uint32_t plainTextLen = sizeof(plainText);
    uint8_t cipherText[512]; // RSA can have larger output
    uint32_t outLen = sizeof(cipherText);
    rc = CRYPT_EAL_PkeyEncrypt(ctx, plainText, sizeof(plainText), cipherText, &outLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to encrypt\n");
        return rc;
    }
    BENCH_TIMES(CRYPT_EAL_PkeyDecrypt(ctx, cipherText, outLen, plainText, &plainTextLen), rc, CRYPT_SUCCESS, -1,
                opts->times, "rsa dec");
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

static int32_t RsaSignInner(void *ctx, int32_t hashId)
{
    uint8_t plainText[32];
    uint8_t signature[512]; // RSA can have larger signatures
    uint32_t signatureLen = sizeof(signature);
    return CRYPT_EAL_PkeySign(ctx, hashId, plainText, sizeof(plainText), signature, &signatureLen);
}

static int32_t RsaSign(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t hashId = GetHashId(bench, opts);
    if (hashId == -1) {
        return -1;
    }
    BENCH_TIMES(RsaSignInner(ctx, hashId), rc, CRYPT_SUCCESS, -1, opts->times, "rsa sign");
    return rc;
}

static int32_t RsaVerify(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t hashId = GetHashId(bench, opts);
    if (hashId == -1) {
        return -1;
    }
    uint8_t plainText[32];
    uint8_t signature[512]; // RSA can have larger signatures
    uint32_t signatureLen = sizeof(signature);
    rc = CRYPT_EAL_PkeySign(ctx, hashId, plainText, sizeof(plainText), signature, &signatureLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to sign\n");
        return rc;
    }
    BENCH_TIMES(CRYPT_EAL_PkeyVerify(ctx, hashId, plainText, sizeof(plainText), signature, signatureLen), rc,
                CRYPT_SUCCESS, -1, opts->times, "rsa verify");
    return rc;
}

DEFINE_OPS(Rsa, CRYPT_PKEY_RSA, CRYPT_MD_SHA256);
DEFINE_BENCH_CTX_FIXLEN(Rsa);