/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_ENTROPY)

#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "entropy.h"
#include "eal_entropy.h"

#define DEV_RAND_MIN_ENTROPY 7.0

static uint32_t GetEntropyInputLen(uint32_t strength, CRYPT_Range *lenRange)
{
    // Calculate the required length based on the strength and the average entropy.
    double cSize = (double)strength / DEV_RAND_MIN_ENTROPY;
    uint32_t len = (uint32_t)cSize;
    if (cSize > (double)len) {  // Ensure that the decimal carries 1.
        len++;
    }
    // '<' indicates that the data with a length of len can provide sufficient bit entropy.
    if (len < lenRange->min) {
        len = lenRange->min;
    }
    return len;
}

static int32_t GetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    bool needFullEntropy = (lenRange->max == lenRange->min) ? true : false;
    uint32_t len = (needFullEntropy) ? lenRange->min : GetEntropyInputLen(strength, lenRange);
    // '>' indicates that data with a length of lenRange->max cannot provide sufficient bit entropy.
    // Only data with a length of len can provide sufficient bit entropy.
    if (len > lenRange->max) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_RANGE_ERROR);
        return CRYPT_ENTROPY_RANGE_ERROR;
    }
    uint8_t *data = (uint8_t *)BSL_SAL_Malloc(len);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    if (needFullEntropy) {
        ret = ENTROPY_GetFullEntropyInput(ctx, data, len);
    } else {
        ret = ENTROPY_GetRandom(data, len);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(data);
        return ret;
    }
    entropy->data = data;
    entropy->len = len;
    return CRYPT_SUCCESS;
}

static void CleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    BSL_SAL_CleanseData(entropy->data, entropy->len);
    BSL_SAL_FREE(entropy->data);
}

static int32_t GetNonce(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    return GetEntropy(ctx, nonce, strength, lenRange);
}

static void CleanNonce(void *ctx, CRYPT_Data *nonce)
{
    CleanEntropy(ctx, nonce);
}

int32_t EAL_SetDefaultEntropyMeth(CRYPT_RandSeedMethod *meth, void **seedCtx)
{
    if (meth == NULL || seedCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    *seedCtx = ENTROPY_GetCtx(EAL_EntropyGetECF(CRYPT_MAC_HMAC_SHA256), CRYPT_MAC_HMAC_SHA224);
    if (*seedCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    meth->getEntropy = GetEntropy;
    meth->cleanEntropy = CleanEntropy;
    meth->cleanNonce = CleanNonce;
    meth->getNonce = GetNonce;
    return CRYPT_SUCCESS;
}

#endif
