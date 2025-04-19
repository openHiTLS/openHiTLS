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
#if defined(HITLS_CRYPTO_RSA_EMSA_PSS) || defined(HITLS_CRYPTO_RSAES_OAEP) || defined(HITLS_CRYPTO_SLH_DSA)

#include <stdlib.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_eal_md.h"
#include "crypt_utils.h"

#define UINT32_SIZE     4
#define HASH_MAX_MDSIZE (64)

// outlen should be hash len
int32_t CalcHash(const EAL_MdMethod *hashMethod, const CRYPT_ConstData *hashData, uint32_t size, uint8_t *out,
                 uint32_t *outlen)
{
    void *mdCtx = hashMethod->newCtx();
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = hashMethod->init(mdCtx, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    for (uint32_t i = 0; i < size; i++) {
        ret = hashMethod->update(mdCtx, hashData[i].data, hashData[i].len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
    }
    ret = hashMethod->final(mdCtx, out, outlen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

int32_t CRYPT_Mgf1(const EAL_MdMethod *hashMethod, const uint8_t *seed, const uint32_t seedLen, uint8_t *mask,
                   uint32_t maskLen)
{
    uint32_t hashLen = hashMethod->mdSize;
    if (hashLen > HASH_MAX_MDSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    uint8_t md[HASH_MAX_MDSIZE];
    uint8_t counter[UINT32_SIZE];

    const CRYPT_ConstData hashData[] = {
        {seed, seedLen}, // mgfSeed
        {counter, sizeof(counter)} // counter
    };
    int32_t ret = CRYPT_RSA_ERR_INPUT_VALUE;
    uint32_t i, outLen, partLen;
    for (i = 0, outLen = 0; outLen < maskLen; i++, outLen += partLen) {
        PUT_UINT32_BE(i, counter, 0);
        ret = CalcHash(hashMethod, hashData, sizeof(hashData) / sizeof(hashData[0]), md, &hashLen);
        if (ret != CRYPT_SUCCESS) {
            goto EXIT;
        }
        // Output the leading maskLen octets of T as the octet string mask
        partLen = (outLen + hashLen <= maskLen) ? hashLen : (maskLen - outLen);
        if (memcpy_s(mask + outLen, maskLen - outLen, md, partLen) != EOK) {
            ret = CRYPT_SECUREC_FAIL;
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
    }
EXIT:
    BSL_SAL_CleanseData(md, sizeof(md));
    return ret;
}

#endif
