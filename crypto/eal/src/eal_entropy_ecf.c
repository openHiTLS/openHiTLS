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

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_ENTROPY)

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "eal_entropy.h"
#include "crypt_eal_mac.h"

#ifdef HITLS_CRYPTO_MAC

#define ECF_ALG_KEY_LEN_128 16

static int32_t ECFMac(uint32_t algId, uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_ENTROPY_CONDITION_FAILURE;
    }
    uint32_t keyLen = ECF_ALG_KEY_LEN_128;
    uint8_t *ecfKey = (uint8_t *)BSL_SAL_Malloc(keyLen);
    if (ecfKey == NULL) {
        CRYPT_EAL_MacFreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    /* reference nist-800 90c-3pd section 3.3.1.1
     * Unlike other cryptographic applications, keys used in these external conditioning functions do not require
     * secrecy to accomplish their purpose so may be hard-coded, fixed, or all zeros.
     */
    (void)memset_s(ecfKey, keyLen, 0, keyLen);
    int32_t ret = CRYPT_EAL_MacInit(ctx, ecfKey, keyLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(ctx);
        BSL_SAL_FREE(ecfKey);
        return ret;
    }
    ret = CRYPT_EAL_MacUpdate(ctx, in, inLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(ctx);
        BSL_SAL_FREE(ecfKey);
        return ret;
    }
    ret = CRYPT_EAL_MacFinal(ctx, out, outLen);
    CRYPT_EAL_MacFreeCtx(ctx);
    BSL_SAL_FREE(ecfKey);
    return ret;
}
#endif

ExternalConditioningFunction EAL_EntropyGetECF(uint32_t algId)
{
    (void)algId;
#ifdef HITLS_CRYPTO_MAC
    return ECFMac;
#else
    return NULL;
#endif
}
#endif
