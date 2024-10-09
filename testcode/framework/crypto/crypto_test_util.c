/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>

#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_eal_rand.h"

#include "helper.h"
#include "crypto_test_util.h"

#ifndef HITLS_BSL_SAL_MEM
void *TestMalloc(uint32_t len)
{
    return malloc((size_t)len);
}
#endif

void TestMemInit(void)
{
#ifdef HITLS_BSL_SAL_MEM
    return;
#else
    static BSL_SAL_MemCallback cb = {TestMalloc, free};
    BSL_SAL_RegMemCallback(&cb);
#endif
}

#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_DRBG)
typedef struct {
    CRYPT_Data *entropy;
    CRYPT_Data *nonce;
    CRYPT_Data *pers;

    CRYPT_Data *addin1;
    CRYPT_Data *entropyPR1;

    CRYPT_Data *addin2;
    CRYPT_Data *entropyPR2;

    CRYPT_Data *retBits;
} DRBG_Vec_t;

#ifdef HITLS_CRYPTO_ENTROPY
static int32_t GetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    if (lenRange == NULL) {
        Print("getEntropy Error lenRange NULL\n");
        return CRYPT_NULL_INPUT;
    }
    if (ctx == NULL || entropy == NULL) {
        Print("getEntropy Error\n");
        lenRange->max = strength;
        return CRYPT_NULL_INPUT;
    }

    DRBG_Vec_t *seedCtx = (DRBG_Vec_t *)ctx;

    entropy->data = seedCtx->entropy->data;
    entropy->len = seedCtx->entropy->len;

    return CRYPT_SUCCESS;
}

static void CleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    (void)entropy;
    return;
}
#endif

int TestRandInit(void)
{
    int drbgAlgId = GetAvailableRandAlgId();
    if (drbgAlgId == -1) {
        Print("Drbg algs are disabled.");
        return CRYPT_NOT_SUPPORT;
    }

#ifdef HITLS_CRYPTO_ENTROPY
    CRYPT_RandSeedMethod seedMeth = {GetEntropy, CleanEntropy, NULL, NULL};
    uint8_t entropy[64] = {0};
    CRYPT_Data tempEntropy = {entropy, sizeof(entropy)};
    DRBG_Vec_t seedCtx = {0};
    seedCtx.entropy = &tempEntropy;
    return CRYPT_EAL_RandInit(drbgAlgId, &seedMeth, (void *)&seedCtx, NULL, 0);
#else
    return CRYPT_EAL_RandInit(drbgAlgId, NULL, NULL, NULL, 0);
#endif
}
#endif
