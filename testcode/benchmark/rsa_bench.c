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
#include "crypt_params_key.h"
#include "bsl_params.h"
#include "benchmark.h"

static uint8_t g_rsaPubExp[] = {0x01, 0x00, 0x01};
static const int32_t g_defaultRsaBits = 2048;
static const int32_t g_defaultRsaHashId = CRYPT_MD_SHA256;

static int32_t RsaGetBits(const BenchExecOptions *opts)
{
    if (opts == NULL || opts->paraId == -1) {
        return g_defaultRsaBits;
    }
    return opts->paraId;
}

static int32_t RsaGetHashId(const BenchExecOptions *opts)
{
    if (opts == NULL || opts->hashId == -1) {
        return g_defaultRsaHashId;
    }
    return opts->hashId;
}

static int32_t RsaSetEncryptPadding(CRYPT_EAL_PkeyCtx *pkeyCtx, int32_t hashId)
{
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        BSL_PARAM_END
    };
    return CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0);
}

static int32_t RsaSetSignPadding(CRYPT_EAL_PkeyCtx *pkeyCtx, int32_t hashId)
{
    return CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &hashId, sizeof(hashId));
}

static int32_t RsaSetUp(void **ctx, const Operation *op, int32_t algId, int32_t paraId)
{
    (void)op;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(algId);
    if (pkeyCtx == NULL) {
        printf("Failed to create pkey context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.e = g_rsaPubExp;
    para.para.rsaPara.eLen = sizeof(g_rsaPubExp);
    para.para.rsaPara.bits = (paraId == -1) ? g_defaultRsaBits : paraId;
    int32_t ret = CRYPT_EAL_PkeySetPara(pkeyCtx, &para);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to set rsa parameters.\n");
        CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
        return ret;
    }
    ret = CRYPT_EAL_PkeyGen(pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to gen rsa key.\n");
        CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
        return ret;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void RsaTearDown(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t RsaKeyGen(void *ctx, const BenchExecOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    BENCH_RUN_VA(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts, "rsa-%d keyGen", RsaGetBits(opts));
    return rc;
}

static int32_t RsaEncInner(void *ctx)
{
    uint8_t plainText[32] = {0};
    uint8_t cipherText[512]; // RSA can have larger output
    uint32_t outLen = sizeof(cipherText);
    return CRYPT_EAL_PkeyEncrypt(ctx, plainText, sizeof(plainText), cipherText, &outLen);
}

static int32_t RsaEnc(void *ctx, const BenchExecOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    int32_t hashId = RsaGetHashId(opts);
    rc = RsaSetEncryptPadding(ctx, hashId);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to set rsa encrypt padding.\n");
        return rc;
    }
    BENCH_RUN_VA(RsaEncInner(ctx), rc, CRYPT_SUCCESS, -1, opts, "rsa-%d-%s enc", RsaGetBits(opts),
        GetAlgName(hashId));
    return rc;
}

static int32_t RsaDec(void *ctx, const BenchExecOptions *opts)
{
    int rc;
    int32_t hashId = RsaGetHashId(opts);
    uint8_t plainText[32] = {0};
    uint32_t plainTextLen = sizeof(plainText);
    uint8_t cipherText[512]; // RSA can have larger output
    uint32_t outLen = sizeof(cipherText);
    rc = RsaSetEncryptPadding(ctx, hashId);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to set rsa decrypt padding.\n");
        return rc;
    }
    rc = CRYPT_EAL_PkeyEncrypt(ctx, plainText, sizeof(plainText), cipherText, &outLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to encrypt\n");
        return rc;
    }
    BENCH_RUN_VA(CRYPT_EAL_PkeyDecrypt(ctx, cipherText, outLen, plainText, &plainTextLen), rc, CRYPT_SUCCESS, -1,
        opts, "rsa-%d-%s dec", RsaGetBits(opts), GetAlgName(hashId));
    return rc;
}

static int32_t RsaSignInner(void *ctx, int32_t hashId)
{
    uint8_t plainText[32] = {0};
    uint8_t signature[512]; // RSA can have larger signatures
    uint32_t signatureLen = sizeof(signature);
    return CRYPT_EAL_PkeySign(ctx, hashId, plainText, sizeof(plainText), signature, &signatureLen);
}

static int32_t RsaSign(void *ctx, const BenchExecOptions *opts)
{
    int rc;
    int32_t hashId = RsaGetHashId(opts);
    rc = RsaSetSignPadding(ctx, hashId);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to set rsa sign padding.\n");
        return rc;
    }
    BENCH_RUN_VA(RsaSignInner(ctx, hashId), rc, CRYPT_SUCCESS, -1, opts, "rsa-%d-%s sign",
        RsaGetBits(opts), GetAlgName(hashId));
    return rc;
}

static int32_t RsaVerify(void *ctx, const BenchExecOptions *opts)
{
    int rc;
    int32_t hashId = RsaGetHashId(opts);
    rc = RsaSetSignPadding(ctx, hashId);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to set rsa verify padding.\n");
        return rc;
    }
    uint8_t plainText[32] = {0};
    uint8_t signature[512]; // RSA can have larger signatures
    uint32_t signatureLen = sizeof(signature);
    rc = CRYPT_EAL_PkeySign(ctx, hashId, plainText, sizeof(plainText), signature, &signatureLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to sign\n");
        return rc;
    }
    BENCH_RUN_VA(CRYPT_EAL_PkeyVerify(ctx, hashId, plainText, sizeof(plainText), signature, signatureLen), rc,
        CRYPT_SUCCESS, -1, opts, "rsa-%d-%s verify", RsaGetBits(opts), GetAlgName(hashId));
    return rc;
}

DEFINE_OPS_CRYPT_SIGN(Rsa, CRYPT_PKEY_RSA, CRYPT_MD_SHA256);
DEFINE_BENCH_CTX_FIXLEN(Rsa);
