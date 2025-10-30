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

// Random number generator callback
static int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % 255);
    }
    return 0;
}

static int32_t Sm9SetUp(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t paraId)
{
    (void)paraId;
    int32_t ret;
    BSL_Param params[3];
    int32_t keyType;

    // Allocate context structure
    Sm9Context *sm9Ctx = (Sm9Context *)malloc(sizeof(Sm9Context));
    if (sm9Ctx == NULL) {
        printf("Failed to allocate SM9 context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memset(sm9Ctx, 0, sizeof(Sm9Context));

    // Register random number generator
    CRYPT_RandRegist(RandFunc);

    // Create SM9 context
    sm9Ctx->ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    if (sm9Ctx->ctx == NULL) {
        printf("Failed to create SM9 pkey context\n");
        free(sm9Ctx);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    // Determine key type based on operation
    // For sign/verify: use signature master key
    // For enc/dec: use encryption master key
    if (ops->opsNum > 0) {
        // Check if this is sign/verify (default to sign for now)
        keyType = SM9_KEY_TYPE_SIGN;

        // Set master key
        BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                            g_sig_master_key, sizeof(g_sig_master_key));
        BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                            &keyType, sizeof(int32_t));
        params[2] = (BSL_Param)BSL_PARAM_END;

        ret = CRYPT_EAL_PkeySetPubEx(sm9Ctx->ctx, params);
        if (ret != CRYPT_SUCCESS) {
            printf("Failed to set SM9 master key: %d\n", ret);
            CRYPT_EAL_PkeyFreeCtx(sm9Ctx->ctx);
            free(sm9Ctx);
            return ret;
        }

        // Generate user key
        BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                            g_user_id, strlen((char*)g_user_id));
        BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                            &keyType, sizeof(int32_t));
        params[2] = (BSL_Param)BSL_PARAM_END;

        ret = CRYPT_EAL_PkeySetPrvEx(sm9Ctx->ctx, params);
        if (ret != CRYPT_SUCCESS) {
            printf("Failed to set SM9 user key: %d\n", ret);
            CRYPT_EAL_PkeyFreeCtx(sm9Ctx->ctx);
            free(sm9Ctx);
            return ret;
        }
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

static int32_t Sm9KeyGen(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    // SM9 doesn't use traditional key generation like RSA/ECC
    // Keys are derived from master key + user ID
    // This operation is already done in SetUp
    (void)ctx;
    (void)bench;
    (void)opts;
    return CRYPT_SUCCESS;
}

static int32_t Sm9Sign(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    Sm9Context *sm9Ctx = (Sm9Context *)ctx;
    int rc = CRYPT_SUCCESS;

    sm9Ctx->signLen = SM9_SIGNATURE_LEN;
    BENCH_TIMES(
        CRYPT_EAL_PkeySign(sm9Ctx->ctx, CRYPT_MD_SM3, g_msg, sizeof(g_msg),
                          sm9Ctx->sign, &sm9Ctx->signLen),
        rc, CRYPT_SUCCESS, sizeof(g_msg), opts->times, "sm9 sign"
    );

    return rc;
}

static int32_t Sm9Verify(void *ctx, BenchCtx *bench, BenchOptions *opts)
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

    BENCH_TIMES(
        CRYPT_EAL_PkeyVerify(sm9Ctx->ctx, CRYPT_MD_SM3, g_msg, sizeof(g_msg),
                            sm9Ctx->sign, sm9Ctx->signLen),
        rc, CRYPT_SUCCESS, sizeof(g_msg), opts->times, "sm9 verify"
    );

    return rc;
}

static int32_t Sm9Enc(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    Sm9Context *sm9Ctx = (Sm9Context *)ctx;
    int rc = CRYPT_SUCCESS;

    // Need to reconfigure context for encryption
    BSL_Param params[3];
    int32_t keyType = SM9_KEY_TYPE_ENC;

    // Set encryption master key
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        g_enc_master_key, sizeof(g_enc_master_key));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    rc = CRYPT_EAL_PkeySetPubEx(sm9Ctx->ctx, params);
    if (rc != CRYPT_SUCCESS) {
        return rc;
    }

    // Set user key for encryption
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        g_user_id, strlen((char*)g_user_id));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    rc = CRYPT_EAL_PkeySetPrvEx(sm9Ctx->ctx, params);
    if (rc != CRYPT_SUCCESS) {
        return rc;
    }

    sm9Ctx->cipherLen = sizeof(sm9Ctx->ciphertext);
    BENCH_TIMES(
        CRYPT_EAL_PkeyEncrypt(sm9Ctx->ctx, g_plaintext, sizeof(g_plaintext),
                             sm9Ctx->ciphertext, &sm9Ctx->cipherLen),
        rc, CRYPT_SUCCESS, sizeof(g_plaintext), opts->times, "sm9 encrypt"
    );

    return rc;
}

static int32_t Sm9Dec(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    Sm9Context *sm9Ctx = (Sm9Context *)ctx;
    int rc = CRYPT_SUCCESS;
    uint8_t decrypted[256];
    uint32_t decryptLen = sizeof(decrypted);

    // Need to reconfigure context for encryption (same as Enc)
    BSL_Param params[3];
    int32_t keyType = SM9_KEY_TYPE_ENC;

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        g_enc_master_key, sizeof(g_enc_master_key));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    rc = CRYPT_EAL_PkeySetPubEx(sm9Ctx->ctx, params);
    if (rc != CRYPT_SUCCESS) {
        return rc;
    }

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        g_user_id, strlen((char*)g_user_id));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    rc = CRYPT_EAL_PkeySetPrvEx(sm9Ctx->ctx, params);
    if (rc != CRYPT_SUCCESS) {
        return rc;
    }

    // First encrypt to get ciphertext
    sm9Ctx->cipherLen = sizeof(sm9Ctx->ciphertext);
    rc = CRYPT_EAL_PkeyEncrypt(sm9Ctx->ctx, g_plaintext, sizeof(g_plaintext),
                               sm9Ctx->ciphertext, &sm9Ctx->cipherLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to generate ciphertext for decrypt benchmark: %d\n", rc);
        return rc;
    }

    BENCH_TIMES(
        CRYPT_EAL_PkeyDecrypt(sm9Ctx->ctx, sm9Ctx->ciphertext, sm9Ctx->cipherLen,
                             decrypted, &decryptLen),
        rc, CRYPT_SUCCESS, sizeof(g_plaintext), opts->times, "sm9 decrypt"
    );

    return rc;
}

static int32_t Sm9KeyDerive(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    // SM9 key exchange/derivation would require two contexts
    // For now, return success (can be implemented later if needed)
    (void)ctx;
    (void)bench;
    (void)opts;
    return CRYPT_SUCCESS;
}

DEFINE_OPS(Sm9, CRYPT_PKEY_SM9, 0);
DEFINE_BENCH_CTX_FIXLEN(Sm9);
