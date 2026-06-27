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
#include <stdlib.h>
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "benchmark.h"

typedef struct {
    CRYPT_EAL_PkeyCtx *pkeyCtx;
    uint8_t *ciphertext;
    uint8_t *sharedKey;
    uint32_t ciphertextLen;
    uint32_t sharedKeyLen;
} McelieceBenchData;

static const char *GetParaName(int32_t paraId)
{
    switch (paraId) {
        case CRYPT_KEM_TYPE_MCELIECE_6688128:
            return "mceliece-6688128";
        case CRYPT_KEM_TYPE_MCELIECE_6688128_F:
            return "mceliece-6688128f";
        case CRYPT_KEM_TYPE_MCELIECE_6688128_PC:
            return "mceliece-6688128pc";
        case CRYPT_KEM_TYPE_MCELIECE_6688128_PCF:
            return "mceliece-6688128pcf";
        case CRYPT_KEM_TYPE_MCELIECE_6960119:
            return "mceliece-6960119";
        case CRYPT_KEM_TYPE_MCELIECE_6960119_F:
            return "mceliece-6960119f";
        case CRYPT_KEM_TYPE_MCELIECE_6960119_PC:
            return "mceliece-6960119pc";
        case CRYPT_KEM_TYPE_MCELIECE_6960119_PCF:
            return "mceliece-6960119pcf";
        case CRYPT_KEM_TYPE_MCELIECE_8192128:
            return "mceliece-8192128";
        case CRYPT_KEM_TYPE_MCELIECE_8192128_F:
            return "mceliece-8192128f";
        case CRYPT_KEM_TYPE_MCELIECE_8192128_PC:
            return "mceliece-8192128pc";
        case CRYPT_KEM_TYPE_MCELIECE_8192128_PCF:
            return "mceliece-8192128pcf";
        default:
            return "unknown";
    }
}

static int32_t McelieceSetUp(void **ctx, const Operation *op, int32_t algId, int32_t paraId)
{
    (void)op;
    McelieceBenchData *benchData = (McelieceBenchData *)calloc(1, sizeof(McelieceBenchData));
    if (benchData == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    benchData->pkeyCtx = CRYPT_EAL_PkeyNewCtx(algId);
    if (benchData->pkeyCtx == NULL) {
        free(benchData);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = CRYPT_EAL_PkeyCtrl(benchData->pkeyCtx, CRYPT_CTRL_SET_PARA_BY_ID, &paraId, sizeof(paraId));
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to set mceliece para id: %d, ret = %08x\n", paraId, ret);
        goto ERR;
    }

    ret = CRYPT_EAL_PkeyCtrl(benchData->pkeyCtx, CRYPT_CTRL_GET_CIPHERTEXT_LEN,
        &benchData->ciphertextLen, sizeof(benchData->ciphertextLen));
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to get mceliece ciphertext length, ret = %08x\n", ret);
        goto ERR;
    }

    ret = CRYPT_EAL_PkeyCtrl(benchData->pkeyCtx, CRYPT_CTRL_GET_SHARED_KEY_LEN,
        &benchData->sharedKeyLen, sizeof(benchData->sharedKeyLen));
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to get mceliece shared key length, ret = %08x\n", ret);
        goto ERR;
    }

    benchData->ciphertext = (uint8_t *)malloc(benchData->ciphertextLen);
    benchData->sharedKey = (uint8_t *)malloc(benchData->sharedKeyLen);
    if (benchData->ciphertext == NULL || benchData->sharedKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }

    ret = CRYPT_EAL_PkeyGen(benchData->pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to generate mceliece key, ret = %08x\n", ret);
        goto ERR;
    }

    *ctx = benchData;
    return CRYPT_SUCCESS;
ERR:
    free(benchData->ciphertext);
    free(benchData->sharedKey);
    CRYPT_EAL_PkeyFreeCtx(benchData->pkeyCtx);
    free(benchData);
    return ret;
}

static void McelieceTearDown(void *ctx)
{
    McelieceBenchData *benchData = (McelieceBenchData *)ctx;
    if (benchData == NULL) {
        return;
    }
    free(benchData->ciphertext);
    free(benchData->sharedKey);
    CRYPT_EAL_PkeyFreeCtx(benchData->pkeyCtx);
    free(benchData);
}

static int32_t McelieceKeyGen(void *ctx, const BenchExecOptions *opts)
{
    McelieceBenchData *benchData = (McelieceBenchData *)ctx;
    int32_t rc = CRYPT_SUCCESS;
    BENCH_RUN_VA(CRYPT_EAL_PkeyGen(benchData->pkeyCtx), rc, CRYPT_SUCCESS, -1, opts,
        "%s keyGen", GetParaName(opts->paraId));
    return rc;
}

static int32_t McelieceEncaps(void *ctx, const BenchExecOptions *opts)
{
    McelieceBenchData *benchData = (McelieceBenchData *)ctx;
    int32_t rc = CRYPT_SUCCESS;
    uint32_t ciphertextLen = benchData->ciphertextLen;
    uint32_t sharedKeyLen = benchData->sharedKeyLen;

    BENCH_RUN_VA(CRYPT_EAL_PkeyEncaps(benchData->pkeyCtx, benchData->ciphertext, &ciphertextLen,
        benchData->sharedKey, &sharedKeyLen), rc, CRYPT_SUCCESS, -1, opts,
        "%s encaps", GetParaName(opts->paraId));
    return rc;
}

static int32_t McelieceDecaps(void *ctx, const BenchExecOptions *opts)
{
    McelieceBenchData *benchData = (McelieceBenchData *)ctx;
    int32_t rc = CRYPT_SUCCESS;
    uint32_t ciphertextLen = benchData->ciphertextLen;
    uint32_t sharedKeyLen = benchData->sharedKeyLen;

    rc = CRYPT_EAL_PkeyEncaps(benchData->pkeyCtx, benchData->ciphertext, &ciphertextLen,
                              benchData->sharedKey, &sharedKeyLen);
    if (rc != CRYPT_SUCCESS) {
        printf("Failed to generate ciphertext before decaps, ret = %08x\n", rc);
        return rc;
    }

    BENCH_RUN_VA(CRYPT_EAL_PkeyDecaps(benchData->pkeyCtx, benchData->ciphertext, ciphertextLen,
        benchData->sharedKey, &sharedKeyLen), rc, CRYPT_SUCCESS, -1, opts,
        "%s decaps", GetParaName(opts->paraId));
    return rc;
}

static int32_t g_paraIds[] = {
    CRYPT_KEM_TYPE_MCELIECE_6688128,
    CRYPT_KEM_TYPE_MCELIECE_6688128_F,
    CRYPT_KEM_TYPE_MCELIECE_6688128_PC,
    CRYPT_KEM_TYPE_MCELIECE_6688128_PCF,
    CRYPT_KEM_TYPE_MCELIECE_6960119,
    CRYPT_KEM_TYPE_MCELIECE_6960119_F,
    CRYPT_KEM_TYPE_MCELIECE_6960119_PC,
    CRYPT_KEM_TYPE_MCELIECE_6960119_PCF,
    CRYPT_KEM_TYPE_MCELIECE_8192128,
    CRYPT_KEM_TYPE_MCELIECE_8192128_F,
    CRYPT_KEM_TYPE_MCELIECE_8192128_PC,
    CRYPT_KEM_TYPE_MCELIECE_8192128_PCF,
};

DEFINE_OPS_KEM(Mceliece, CRYPT_PKEY_MCELIECE);
DEFINE_BENCH_CTX_PARA_FIXLEN(Mceliece, g_paraIds, SIZEOF(g_paraIds));
