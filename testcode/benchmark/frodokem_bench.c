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

#include <stdlib.h>
#include <string.h>
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_types.h"
#include "benchmark.h"

static const char *GetParaName(int32_t paraId)
{
    switch (paraId) {
        case CRYPT_KEM_TYPE_FRODOKEM_640_SHAKE:
            return "frodokem-640-shake";
        case CRYPT_KEM_TYPE_FRODOKEM_976_SHAKE:
            return "frodokem-976-shake";
        case CRYPT_KEM_TYPE_FRODOKEM_1344_SHAKE:
            return "frodokem-1344-shake";
        case CRYPT_KEM_TYPE_FRODOKEM_640_AES:
            return "frodokem-640-aes";
        case CRYPT_KEM_TYPE_FRODOKEM_976_AES:
            return "frodokem-976-aes";
        case CRYPT_KEM_TYPE_FRODOKEM_1344_AES:
            return "frodokem-1344-aes";
        case CRYPT_KEM_TYPE_EFRODOKEM_640_SHAKE:
            return "efrodokem-640-shake";
        case CRYPT_KEM_TYPE_EFRODOKEM_976_SHAKE:
            return "efrodokem-976-shake";
        case CRYPT_KEM_TYPE_EFRODOKEM_1344_SHAKE:
            return "efrodokem-1344-shake";
        case CRYPT_KEM_TYPE_EFRODOKEM_640_AES:
            return "efrodokem-640-aes";
        case CRYPT_KEM_TYPE_EFRODOKEM_976_AES:
            return "efrodokem-976-aes";
        case CRYPT_KEM_TYPE_EFRODOKEM_1344_AES:
            return "efrodokem-1344-aes";
        default:
            return "unknown";
    }
}

static int32_t FrodokemSetUp(void **ctx, const Operation *op, int32_t algId, int32_t paraId)
{
    (void)op;
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(algId);
    if (pkeyCtx == NULL) {
        printf("Failed to create frodokem pkey context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_PkeySetParaById(pkeyCtx, (CRYPT_PKEY_ParaId)paraId);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to set frodokem alg info.\n");
        CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
        return ret;
    }
    ret = CRYPT_EAL_PkeyGen(pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to gen frodokem key.\n");
        CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
        return ret;
    }
    *ctx = pkeyCtx;
    return CRYPT_SUCCESS;
}

static void FrodokemTearDown(void *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static int32_t FrodokemKeyGen(void *ctx, const BenchExecOptions *opts)
{
    int rc = CRYPT_SUCCESS;
    BENCH_RUN_VA(CRYPT_EAL_PkeyGen(ctx), rc, CRYPT_SUCCESS, -1, opts, "%s keyGen", GetParaName(opts->paraId));
    return rc;
}

static int32_t FrodokemEncaps(void *ctx, const BenchExecOptions *opts)
{
    int rc;
    uint32_t ciphertextLen = 0;
    uint32_t sharedKeyLen = 0;

    rc = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ciphertextLen, sizeof(ciphertextLen));
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to get frodokem ciphertext len\n");
        return rc;
    }
    rc = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedKeyLen, sizeof(sharedKeyLen));
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to get frodokem shared key len\n");
        return rc;
    }

    uint8_t *ciphertext = malloc(ciphertextLen);
    uint8_t *sharedKey = malloc(sharedKeyLen);
    if (ciphertext == NULL || sharedKey == NULL) {
        free(ciphertext);
        free(sharedKey);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t outCiphertextLen = ciphertextLen;
    uint32_t outSharedKeyLen = sharedKeyLen;
    BENCH_RUN_VA(CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &outCiphertextLen, sharedKey, &outSharedKeyLen), rc,
        CRYPT_SUCCESS, (int32_t)ciphertextLen, opts, "%s encaps", GetParaName(opts->paraId));

    free(ciphertext);
    free(sharedKey);
    return rc;
}

static int32_t FrodokemDecaps(void *ctx, const BenchExecOptions *opts)
{
    int rc;
    uint32_t ciphertextLen = 0;
    uint32_t sharedKeyLen = 0;

    rc = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ciphertextLen, sizeof(ciphertextLen));
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to get frodokem ciphertext len\n");
        return rc;
    }
    rc = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedKeyLen, sizeof(sharedKeyLen));
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to get frodokem shared key len\n");
        return rc;
    }

    uint8_t *ciphertext = malloc(ciphertextLen);
    uint8_t *sharedKey = malloc(sharedKeyLen);
    uint8_t *decapsSharedKey = malloc(sharedKeyLen);
    if (ciphertext == NULL || sharedKey == NULL || decapsSharedKey == NULL) {
        free(ciphertext);
        free(sharedKey);
        free(decapsSharedKey);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t outCiphertextLen = ciphertextLen;
    uint32_t outSharedKeyLen = sharedKeyLen;
    rc = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &outCiphertextLen, sharedKey, &outSharedKeyLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to frodokem encap\n");
        goto EXIT;
    }

    uint32_t decapsSharedKeyLen = sharedKeyLen;
    BENCH_RUN_VA(CRYPT_EAL_PkeyDecaps(ctx, ciphertext, outCiphertextLen, decapsSharedKey, &decapsSharedKeyLen), rc,
        CRYPT_SUCCESS, (int32_t)outCiphertextLen, opts, "%s decaps", GetParaName(opts->paraId));

EXIT:
    free(ciphertext);
    free(sharedKey);
    free(decapsSharedKey);
    return rc;
}

static int32_t g_paraIds[] = {
    CRYPT_KEM_TYPE_FRODOKEM_640_SHAKE,
    CRYPT_KEM_TYPE_FRODOKEM_976_SHAKE,
    CRYPT_KEM_TYPE_FRODOKEM_1344_SHAKE,
    CRYPT_KEM_TYPE_FRODOKEM_640_AES,
    CRYPT_KEM_TYPE_FRODOKEM_976_AES,
    CRYPT_KEM_TYPE_FRODOKEM_1344_AES,
    CRYPT_KEM_TYPE_EFRODOKEM_640_SHAKE,
    CRYPT_KEM_TYPE_EFRODOKEM_976_SHAKE,
    CRYPT_KEM_TYPE_EFRODOKEM_1344_SHAKE,
    CRYPT_KEM_TYPE_EFRODOKEM_640_AES,
    CRYPT_KEM_TYPE_EFRODOKEM_976_AES,
    CRYPT_KEM_TYPE_EFRODOKEM_1344_AES,
};

DEFINE_OPS_KEM(Frodokem, CRYPT_PKEY_FRODOKEM);
DEFINE_BENCH_CTX_PARA_FIXLEN(Frodokem, g_paraIds, SIZEOF(g_paraIds));
