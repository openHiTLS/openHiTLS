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

static int32_t Sm2NewCtx(void **ctx)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (pkeyCtx == NULL) {
        printf("Failed to create pkey context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void Sm2FreeCtx(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t Sm2KeyGen(void *ctx, BenchCtx *bench)
{
    int rc = CRYPT_SUCCESS;
    BENCH_TIMES(rc = CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, bench->times, "sm2 keyGen");
    return rc;
}

static int32_t Sm2KeyDeriveInner(void *ctx, void *peerCtx)
{
    int rc = CRYPT_SUCCESS;
    uint8_t localR[128] = {0};
    rc = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR));
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to generate R\n");
        return rc;
    }
    uint8_t shareKey[64] = {0};
    uint32_t shareKeyLen = sizeof(shareKey);
    rc = CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, shareKey, &shareKeyLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to compute share key\n");
        return rc;
    }
    return CRYPT_SUCCESS;
}

static int32_t Sm2KeyDerive(void *ctx, BenchCtx *bench)
{
    int rc = CRYPT_SUCCESS;
    CRYPT_EAL_PkeyCtx *peerCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (peerCtx == NULL || CRYPT_EAL_PkeyGen(peerCtx) != CRYPT_SUCCESS) {
        printf("Failed to create pkey context\n");
        CRYPT_EAL_PkeyFreeCtx(peerCtx);
        rc = CRYPT_MEM_ALLOC_FAIL;
        goto ERR_OUT;
    }

    char *peerRHex =
        "04acc27688a6f7b706098bc91ff3ad1bff7dc2802cdb14ccccdb0a90471f9bd7072fedac0494b2ffc4d6853876c79b8f301c6573ad0aa50f39fc87181e1a1b46fe";
    uint8_t peerR[128] = {0};
    uint32_t peerRLen = sizeof(peerR);
    Hex2Bin(peerRHex, peerR, &peerRLen);
    rc = CRYPT_EAL_PkeyCtrl(peerCtx, CRYPT_CTRL_SET_SM2_R, peerR, peerRLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to set R\n");
        goto ERR_OUT;
    }
    BENCH_TIMES(Sm2KeyDeriveInner(ctx, peerCtx), rc, CRYPT_SUCCESS, bench->times, "sm2 keyDerive");
ERR_OUT:
    CRYPT_EAL_PkeyFreeCtx(peerCtx);
    return rc;
}

static int32_t Sm2EncInner(void *ctx)
{
    uint8_t plainText[32];
    uint8_t cipherText[256]; // > 32 + 97 + 12
    uint32_t outLen = sizeof(cipherText);
    return CRYPT_EAL_PkeyEncrypt(ctx, plainText, sizeof(plainText), cipherText, &outLen);
}

static int32_t Sm2Enc(void *ctx, BenchCtx *bench)
{
    int rc = CRYPT_SUCCESS;
    BENCH_TIMES(Sm2EncInner(ctx), rc, CRYPT_SUCCESS, bench->times, "sm2 enc");
    return rc;
}

static int32_t Sm2Dec(void *ctx, BenchCtx *bench)
{
    int rc;
    uint8_t plainText[32];
    uint32_t plainTextLen = sizeof(plainText);
    uint8_t cipherText[256]; // > 32 + 97 + 12
    uint32_t outLen = sizeof(cipherText);
    rc = CRYPT_EAL_PkeyEncrypt(ctx, plainText, sizeof(plainText), cipherText, &outLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to encrypt\n");
        return rc;
    }
    BENCH_TIMES(CRYPT_EAL_PkeyDecrypt(ctx, cipherText, outLen, plainText, &plainTextLen), rc, CRYPT_SUCCESS, bench->times,
                "sm2 dec");
    return rc;
}

static int32_t Sm2SignInner(void *ctx)
{
    uint8_t plainText[32];
    uint8_t signature[256];
    uint32_t signatureLen = sizeof(signature);
    return CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, plainText, sizeof(plainText), signature, &signatureLen);
}

static int32_t Sm2Sign(void *ctx, BenchCtx *bench)
{
    int rc;
    BENCH_TIMES(Sm2SignInner(ctx), rc, CRYPT_SUCCESS, bench->times, "sm2 sign");
    return rc;
}

static int32_t Sm2Verify(void *ctx, BenchCtx *bench)
{
    int rc;
    uint8_t plainText[32];
    uint8_t signature[256];
    uint32_t signatureLen = sizeof(signature);
    rc = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, plainText, sizeof(plainText), signature, &signatureLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to sign\n");
        return rc;
    }
    BENCH_TIMES(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, plainText, sizeof(plainText), signature, signatureLen), rc,
                CRYPT_SUCCESS, bench->times, "sm2 verify");
    return rc;
}

DEFINE_OPS(Sm2);
DEFINE_BENCH_CTX(Sm2);
