/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ENTROPY

#include <stdint.h>

#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "securec.h"
#include "entropy.h"

static EntropyCtx g_entropyCtx = { 0 };

static uint32_t ECFAlgidValidCheck(uint32_t algId)
{
    uint32_t algTable[] = {
        CRYPT_MD_SHA224, CRYPT_MD_SHA256, CRYPT_MD_SHA384, CRYPT_MD_SHA512,
        CRYPT_MD_SHA3_224, CRYPT_MD_SHA3_256, CRYPT_MD_SHA3_384, CRYPT_MD_SHA3_512,
        CRYPT_MAC_HMAC_SHA224, CRYPT_MAC_HMAC_SHA256, CRYPT_MAC_HMAC_SHA384, CRYPT_MAC_HMAC_SHA512,
        CRYPT_MAC_HMAC_SHA3_224, CRYPT_MAC_HMAC_SHA3_256, CRYPT_MAC_HMAC_SHA3_384, CRYPT_MAC_HMAC_SHA3_512
    };
    for (uint32_t iter = 0; iter < sizeof(algTable) / sizeof(algTable[0]); iter++) {
        if (algId == algTable[iter]) {
            return CRYPT_SUCCESS;
        }
    }
    BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ECF_ALG_ERROR);
    return CRYPT_ENTROPY_ECF_ALG_ERROR;
}

EntropyCtx *ENTROPY_GetCtx(ExternalConditioningFunction conFunc, uint32_t algId)
{
    if (ECFAlgidValidCheck(algId) != CRYPT_SUCCESS || conFunc == NULL) {
        return NULL;
    }
    g_entropyCtx.algId = algId;
    g_entropyCtx.conFunc = conFunc;
    return &g_entropyCtx;
}

#define ECF_MAX_OUTPUT_LEN 64
#define ECF_ADDITION_LEN 8 // reference nist-800 90c-3pd section 3.3.2

int32_t ENTROPY_GetFullEntropyInput(void *ctx, uint8_t *data, uint32_t len)
{
    EntropyCtx *enCtx = (EntropyCtx *)ctx;
    uint8_t *ptr = data;
    uint32_t remainLen = len;
    int32_t ret = CRYPT_SUCCESS;
    if (enCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t oneLen = len + ECF_ADDITION_LEN;
    uint8_t *tmp = BSL_SAL_Malloc(oneLen);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    do {
        ret = ENTROPY_GetRandom(tmp, oneLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        uint8_t conData[ECF_MAX_OUTPUT_LEN] = {0};
        uint32_t conLen = ECF_MAX_OUTPUT_LEN;
        ret = enCtx->conFunc(enCtx->algId, tmp, oneLen, conData, &conLen);
        (void)memset_s(tmp, oneLen, 0, oneLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        uint32_t cpLen = (conLen > remainLen) ? remainLen : conLen;
        (void)memcpy_s(ptr, remainLen, conData, cpLen);
        remainLen -= cpLen;
        ptr += cpLen;
        (void)memset_s(conData, conLen, 0, conLen);
    } while (remainLen > 0);
    BSL_SAL_FREE(tmp);
    return ret;
}
#endif /* HITLS_CRYPTO_ENTROPY */
