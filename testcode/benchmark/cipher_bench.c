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
#include "crypt_eal_cipher.h"
#include "benchmark.h"

static int32_t CipherSetUp(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t paraId)
{
    *ctx = CRYPT_EAL_CipherNewCtx(paraId);
    if (*ctx == NULL) {
        printf("Failed to new cipher ctx\n");
        return CRYPT_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}

static void CipherTearDown(void *ctx)
{
    if (ctx != NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
}

static int32_t DoCipherEnc(void *ctx, BenchOptions *opts)
{
    uint8_t out[16384]; // Maximum output size
    uint32_t outLen = sizeof(out);

    return CRYPT_EAL_CipherUpdate(ctx, g_plain, opts->len, out, &outLen);
}

static CRYPT_EAL_CipherCtx *InitCipherCtx(int32_t paraId, uint32_t keyLen, uint32_t ivLen, bool isEnc)
{
    int rc;

    CRYPT_EAL_CipherCtx *cipher = CRYPT_EAL_CipherNewCtx(paraId);
    if (cipher == NULL) {
        return NULL;
    }
    // the iv len of ccm is in [7, 13]
    rc = CRYPT_EAL_CipherInit(cipher, g_key, keyLen, g_iv, ivLen, isEnc);
    if (rc != CRYPT_SUCCESS) {
        printf("init ccm cipher failed\n");
        return NULL;
    }

    return cipher;
}

static int32_t DoCcmEnc(void *ctx, BenchOptions *opts, uint32_t keyLen, uint32_t ivLen)
{
    // aead do a complete init->ctrl->update->final process.
    (void)ctx;

    int rc;
    int32_t paraId = opts->paraId;
    uint32_t aad[32] = {1, 2, 3};
    uint64_t msgLen = opts->len;
    uint32_t outLen = sizeof(g_out);
    uint8_t tag[16];
    uint32_t tagLen = sizeof(tag);

    CRYPT_EAL_CipherCtx *cipher = InitCipherCtx(paraId, keyLen, ivLen, true);
    if (cipher == NULL) {
        return CRYPT_ERR_ALGID;
    }

    if ((rc = CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen))) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen))) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_SET_AAD, aad, sizeof(aad))) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherUpdate(cipher, g_plain, opts->len, g_out, &outLen)) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_GET_TAG, tag, tagLen)) != CRYPT_SUCCESS) {
        printf("do ccm enc failed\n");
        goto ERR;
    }
ERR:
    CRYPT_EAL_CipherFreeCtx(cipher);
    return rc;
}

static int32_t DoCcmDec(void *ctx, BenchOptions *opts, uint32_t keyLen, uint32_t ivLen)
{
    // aead do a complete init->ctrl->update->final process.
    (void)ctx;

    int rc;
    int32_t paraId = opts->paraId;
    uint32_t aad[32] = {1, 2, 3};
    uint64_t msgLen = opts->len;
    uint32_t outLen = sizeof(g_out);

    CRYPT_EAL_CipherCtx *cipher = InitCipherCtx(paraId, keyLen, ivLen, false);
    if (cipher == NULL) {
        return CRYPT_ERR_ALGID;
    }

    if ((rc = CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen))) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_SET_AAD, aad, sizeof(aad))) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherUpdate(cipher, g_plain, opts->len, g_out, &outLen)) != CRYPT_SUCCESS) {
        printf("do ccm dec failed\n");
        goto ERR;
    }
ERR:
    CRYPT_EAL_CipherFreeCtx(cipher);
    return rc;
}

static int32_t DoGcmEnc(void *ctx, BenchOptions *opts, uint32_t keyLen, uint32_t ivLen)
{
    // aead do a complete init->ctrl->update->final process.
    (void)ctx;

    int rc;
    int32_t paraId = opts->paraId;
    uint32_t aad[32] = {1, 2, 3};
    uint8_t tag[16];
    uint32_t tagLen = sizeof(tag);
    uint32_t outLen = sizeof(g_out);

    CRYPT_EAL_CipherCtx *cipher = InitCipherCtx(paraId, keyLen, ivLen, true);
    if (cipher == NULL) {
        return CRYPT_ERR_ALGID;
    }

    if ((rc = CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen))) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_SET_AAD, aad, sizeof(aad))) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherUpdate(cipher, g_plain, opts->len, g_out, &outLen)) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_GET_TAG, tag, sizeof(tag))) != CRYPT_SUCCESS) {
        printf("do gcm enc failed\n");
        goto ERR;
    }

ERR:
    CRYPT_EAL_CipherFreeCtx(cipher);
    return rc;
}

static int32_t DoGcmDec(void *ctx, BenchOptions *opts, uint32_t keyLen, uint32_t ivLen)
{
    // aead do a complete init->ctrl->update->final process.
    (void)ctx;

    int rc;
    int32_t paraId = opts->paraId;
    uint32_t aad[32] = {1, 2, 3};
    uint8_t tag[16];
    uint32_t tagLen = sizeof(tag);
    uint32_t outLen = sizeof(g_out);

    CRYPT_EAL_CipherCtx *cipher = InitCipherCtx(paraId, keyLen, ivLen, false);
    if (cipher == NULL) {
        return CRYPT_ERR_ALGID;
    }

    if ((rc = CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_SET_AAD, aad, sizeof(aad))) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherUpdate(cipher, g_plain, opts->len, g_out, &outLen)) != CRYPT_SUCCESS) {
        printf("do gcm enc failed\n");
        goto ERR;
    }

ERR:
    CRYPT_EAL_CipherFreeCtx(cipher);
    return rc;
}

static int32_t CipherEnc(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t paraId = opts->paraId;
    const char *cipherName = GetAlgName(paraId);
    uint32_t keyLen = 16;
    uint32_t ivLen = 16;

    if ((rc = CRYPT_EAL_CipherGetInfo(paraId, CRYPT_INFO_KEY_LEN, &keyLen)) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherGetInfo(paraId, CRYPT_INFO_IV_LEN, &ivLen)) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherInit(ctx, g_key, keyLen, g_iv, ivLen, true)) != CRYPT_SUCCESS) {
        return rc;
    }

    // aead
    if (paraId == CRYPT_CIPHER_AES128_CCM || paraId == CRYPT_CIPHER_AES192_CCM || paraId == CRYPT_CIPHER_AES256_CCM) {
        BENCH_TIMES_VA(DoCcmEnc(ctx, opts, keyLen, ivLen), rc, CRYPT_SUCCESS, opts->len, opts->times, "%s encrypt",
                       cipherName);
    } else if (paraId == CRYPT_CIPHER_AES128_GCM || paraId == CRYPT_CIPHER_AES192_GCM ||
               paraId == CRYPT_CIPHER_AES256_GCM || paraId == CRYPT_CIPHER_SM4_GCM) {
        BENCH_TIMES_VA(DoGcmEnc(ctx, opts, keyLen, ivLen), rc, CRYPT_SUCCESS, opts->len, opts->times, "%s encrypt",
                       cipherName);
    } else {
        BENCH_TIMES_VA(DoCipherEnc(ctx, opts), rc, CRYPT_SUCCESS, opts->len, opts->times, "%s encrypt", cipherName);
    }

    return rc;
}

static int32_t CipherDec(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t paraId = opts->paraId;
    const char *cipherName = GetAlgName(paraId);
    uint32_t keyLen = 16;
    uint32_t ivLen = 16;

    if ((rc = CRYPT_EAL_CipherGetInfo(paraId, CRYPT_INFO_KEY_LEN, &keyLen)) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherGetInfo(paraId, CRYPT_INFO_IV_LEN, &ivLen)) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_CipherInit(ctx, g_key, keyLen, g_iv, ivLen, false)) != CRYPT_SUCCESS) {
        return rc;
    }

    // aead
    if (paraId == CRYPT_CIPHER_AES128_CCM || paraId == CRYPT_CIPHER_AES192_CCM || paraId == CRYPT_CIPHER_AES256_CCM) {
        BENCH_TIMES_VA(DoCcmDec(ctx, opts, keyLen, ivLen), rc, CRYPT_SUCCESS, opts->len, opts->times, "%s decrypt",
                       cipherName);
    } else if (paraId == CRYPT_CIPHER_AES128_GCM || paraId == CRYPT_CIPHER_AES192_GCM ||
               paraId == CRYPT_CIPHER_AES256_GCM || paraId == CRYPT_CIPHER_SM4_GCM) {
        BENCH_TIMES_VA(DoGcmDec(ctx, opts, keyLen, ivLen), rc, CRYPT_SUCCESS, opts->len, opts->times, "%s decrypt",
                       cipherName);
    } else {
        BENCH_TIMES_VA(DoCipherEnc(ctx, opts), rc, CRYPT_SUCCESS, opts->len, opts->times, "%s decrypt", cipherName);
    }
    return rc;
}

static int32_t g_paraIds[] = {
    // AES-128 modes
    CRYPT_CIPHER_AES128_CBC,
    CRYPT_CIPHER_AES128_CTR,
    CRYPT_CIPHER_AES128_ECB,
    CRYPT_CIPHER_AES128_XTS,
    CRYPT_CIPHER_AES128_CCM,
    CRYPT_CIPHER_AES128_GCM,
    CRYPT_CIPHER_AES128_CFB,
    CRYPT_CIPHER_AES128_OFB,

    // AES-192 modes
    CRYPT_CIPHER_AES192_CBC,
    CRYPT_CIPHER_AES192_CTR,
    CRYPT_CIPHER_AES192_ECB,
    CRYPT_CIPHER_AES192_CCM,
    CRYPT_CIPHER_AES192_GCM,
    CRYPT_CIPHER_AES192_CFB,
    CRYPT_CIPHER_AES192_OFB,

    // AES-256 modes
    CRYPT_CIPHER_AES256_CBC,
    CRYPT_CIPHER_AES256_CTR,
    CRYPT_CIPHER_AES256_ECB,
    CRYPT_CIPHER_AES256_XTS,
    CRYPT_CIPHER_AES256_CCM,
    CRYPT_CIPHER_AES256_GCM,
    CRYPT_CIPHER_AES256_CFB,
    CRYPT_CIPHER_AES256_OFB,

    // SM4 modes
    CRYPT_CIPHER_SM4_XTS,
    CRYPT_CIPHER_SM4_CBC,
    CRYPT_CIPHER_SM4_ECB,
    CRYPT_CIPHER_SM4_CTR,
    CRYPT_CIPHER_SM4_GCM,
    CRYPT_CIPHER_SM4_CFB,
    CRYPT_CIPHER_SM4_OFB,

    // ChaCha20-Poly1305
    CRYPT_CIPHER_CHACHA20_POLY1305,
};

DEFINE_OPS_CIPHER(Cipher, CRYPT_PKEY_MAX);
DEFINE_BENCH_CTX_PARA(Cipher, g_paraIds, SIZEOF(g_paraIds));