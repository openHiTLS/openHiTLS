/*
 * SM9 Benchmark - Following benchmark framework pattern
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
#include <stdlib.h>
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_md.h"
#include "crypt_util_rand.h"
#include "crypt_params_key.h"
#include "bsl_params.h"
#include "benchmark.h"

#define SM9_SIGNATURE_LEN 96
#define SM9_KEY_TYPE_SIGN 1
#define SM9_KEY_TYPE_ENC 2

// SM9 context structure
typedef struct {
    CRYPT_EAL_PkeyCtx *ctx;
    uint8_t sign[SM9_SIGNATURE_LEN];
    uint32_t signLen;
    uint8_t ciphertext[256];
    uint32_t cipherLen;
} Sm9Context;

// Test data
static unsigned char g_msg[] = "Hello SM9 Benchmark!";
static unsigned char g_plaintext[] = "Secret Message for SM9 Encryption Test";

// Master keys
static unsigned char g_sig_master_key[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
};

static unsigned char g_enc_master_key[32] = {
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

static unsigned char g_user_id[] = "BenchmarkUser";

static int32_t Sm9SetEncryptCtx(CRYPT_EAL_PkeyCtx *ctx)
{
    BSL_Param params[4];
    int32_t keyType = SM9_KEY_TYPE_ENC;

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
        g_enc_master_key, sizeof(g_enc_master_key));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
        g_user_id, strlen((char *)g_user_id));
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
        &keyType, sizeof(keyType));
    params[3] = (BSL_Param)BSL_PARAM_END;
    return CRYPT_EAL_PkeySetPubEx(ctx, params);
}

static int32_t Sm9SetDecryptCtx(CRYPT_EAL_PkeyCtx *ctx)
{
    int32_t ret;
    BSL_Param params[3];
    int32_t keyType = SM9_KEY_TYPE_ENC;

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
        g_enc_master_key, sizeof(g_enc_master_key));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
        &keyType, sizeof(keyType));
    params[2] = (BSL_Param)BSL_PARAM_END;
    ret = CRYPT_EAL_PkeySetPubEx(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
        g_user_id, strlen((char *)g_user_id));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
        &keyType, sizeof(keyType));
    params[2] = (BSL_Param)BSL_PARAM_END;
    return CRYPT_EAL_PkeySetPrvEx(ctx, params);
}

static int32_t Sm9SetSignCtx(CRYPT_EAL_PkeyCtx *ctx)
{
    int32_t ret;
    BSL_Param params[3];
    int32_t keyType = SM9_KEY_TYPE_SIGN;

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
        g_sig_master_key, sizeof(g_sig_master_key));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
        &keyType, sizeof(keyType));
    params[2] = (BSL_Param)BSL_PARAM_END;
    ret = CRYPT_EAL_PkeySetPubEx(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
        g_user_id, strlen((char *)g_user_id));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
        &keyType, sizeof(keyType));
    params[2] = (BSL_Param)BSL_PARAM_END;
    return CRYPT_EAL_PkeySetPrvEx(ctx, params);
}

static int32_t Sm9BuildCiphertext(uint8_t *ciphertext, uint32_t *cipherLen)
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *encCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    if (encCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = Sm9SetEncryptCtx(encCtx);
    if (ret == CRYPT_SUCCESS) {
        ret = CRYPT_EAL_PkeyEncrypt(encCtx, g_plaintext, sizeof(g_plaintext), ciphertext, cipherLen);
    }

    CRYPT_EAL_PkeyFreeCtx(encCtx);
    return ret;
}


static int32_t Sm9SetUp(void **ctx, const Operation *op, int32_t algId, int32_t paraId)
{
    (void)paraId;
    int32_t ret;

    // Allocate context structure
    Sm9Context *sm9Ctx = (Sm9Context *)malloc(sizeof(Sm9Context));
    if (sm9Ctx == NULL) {
        printf("Failed to allocate SM9 context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memset(sm9Ctx, 0, sizeof(Sm9Context));
    // Create SM9 context
    sm9Ctx->ctx = CRYPT_EAL_PkeyNewCtx(algId);
    if (sm9Ctx->ctx == NULL) {
        printf("Failed to create SM9 pkey context\n");
        free(sm9Ctx);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    if ((op->id & ENC_ID) || (op->id & DEC_ID)) {
        if (op->id & ENC_ID) {
            ret = Sm9SetEncryptCtx(sm9Ctx->ctx);
        } else {
            ret = Sm9SetDecryptCtx(sm9Ctx->ctx);
        }
    } else {
        ret = Sm9SetSignCtx(sm9Ctx->ctx);
    }
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to set SM9 context: %d\n", ret);
        CRYPT_EAL_PkeyFreeCtx(sm9Ctx->ctx);
        free(sm9Ctx);
        return ret;
    }
    *ctx = sm9Ctx;
    return CRYPT_SUCCESS;
}

static void Sm9TearDown(void *ctx)
{
    if (ctx == NULL) {
        return;
    }

    Sm9Context *sm9Ctx = (Sm9Context *)ctx;
    if (sm9Ctx->ctx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(sm9Ctx->ctx);
    }
    free(sm9Ctx);
}

static int32_t Sm9KeyGen(void *ctx, const BenchExecOptions *opts)
{
    // SM9 doesn't use traditional key generation like RSA/ECC
    // Keys are derived from master key + user ID
    // This operation is already done in SetUp
    (void)ctx;
    (void)opts;
    return CRYPT_SUCCESS;
}

static int32_t Sm9Sign(void *ctx, const BenchExecOptions *opts)
{
    Sm9Context *sm9Ctx = (Sm9Context *)ctx;
    int rc = CRYPT_SUCCESS;

    sm9Ctx->signLen = SM9_SIGNATURE_LEN;
    BENCH_RUN(
        CRYPT_EAL_PkeySign(sm9Ctx->ctx, CRYPT_MD_SM3, g_msg, sizeof(g_msg),
                          sm9Ctx->sign, &sm9Ctx->signLen),
        rc, CRYPT_SUCCESS, (int32_t)sizeof(g_msg), opts, "sm9 sign"
    );

    return rc;
}

static int32_t Sm9Verify(void *ctx, const BenchExecOptions *opts)
{
    Sm9Context *sm9Ctx = (Sm9Context *)ctx;
    int rc = CRYPT_SUCCESS;

    // First generate a signature to verify
    sm9Ctx->signLen = SM9_SIGNATURE_LEN;
    rc = CRYPT_EAL_PkeySign(sm9Ctx->ctx, CRYPT_MD_SM3, g_msg, sizeof(g_msg),
                            sm9Ctx->sign, &sm9Ctx->signLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to generate signature for verify benchmark: %d\n", rc);
        return rc;
    }

    BENCH_RUN(
        CRYPT_EAL_PkeyVerify(sm9Ctx->ctx, CRYPT_MD_SM3, g_msg, sizeof(g_msg),
                            sm9Ctx->sign, sm9Ctx->signLen),
        rc, CRYPT_SUCCESS, (int32_t)sizeof(g_msg), opts, "sm9 verify"
    );

    return rc;
}

static int32_t Sm9Enc(void *ctx, const BenchExecOptions *opts)
{
    Sm9Context *sm9Ctx = (Sm9Context *)ctx;
    int rc = CRYPT_SUCCESS;

    sm9Ctx->cipherLen = sizeof(sm9Ctx->ciphertext);
    BENCH_RUN(
        CRYPT_EAL_PkeyEncrypt(sm9Ctx->ctx, g_plaintext, sizeof(g_plaintext),
                             sm9Ctx->ciphertext, &sm9Ctx->cipherLen),
        rc, CRYPT_SUCCESS, (int32_t)sizeof(g_plaintext), opts, "sm9 encrypt"
    );

    return rc;
}

static int32_t Sm9Dec(void *ctx, const BenchExecOptions *opts)
{
    Sm9Context *sm9Ctx = (Sm9Context *)ctx;
    int rc = CRYPT_SUCCESS;
    uint8_t decrypted[256];
    uint32_t decryptLen = sizeof(decrypted);
    sm9Ctx->cipherLen = sizeof(sm9Ctx->ciphertext);
    rc = Sm9BuildCiphertext(sm9Ctx->ciphertext, &sm9Ctx->cipherLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to generate ciphertext for decrypt benchmark: %d\n", rc);
        return rc;
    }

    BENCH_RUN(
        CRYPT_EAL_PkeyDecrypt(sm9Ctx->ctx, sm9Ctx->ciphertext, sm9Ctx->cipherLen,
                             decrypted, &decryptLen),
        rc, CRYPT_SUCCESS, (int32_t)sizeof(g_plaintext), opts, "sm9 decrypt"
    );

    return rc;
}

static int32_t Sm9KeyDerive(void *ctx, const BenchExecOptions *opts)
{
    // SM9 key exchange/derivation would require two contexts
    // For now, return success (can be implemented later if needed)
    (void)ctx;
    (void)opts;
    return CRYPT_SUCCESS;
}

DEFINE_OPS(Sm9, CRYPT_PKEY_SM9, 0);
DEFINE_BENCH_CTX_FIXLEN(Sm9);
