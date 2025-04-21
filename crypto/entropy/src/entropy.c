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
#ifdef HITLS_CRYPTO_ENTROPY

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_entropy.h"

#define ECF_MAX_OUTPUT_LEN 64
#define ECF_ADDITION_ENTROPY 64 // reference nist-800 90c-3pd section 3.3.2
#define ECF_BYTE_TO_BIT 8

static int32_t EntropyEcf(void *ctx, uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen)
{
    ENTROPY_ECFCtx *enCtx = (ENTROPY_ECFCtx *)ctx;
    if (enCtx == NULL || enCtx->conFunc == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ECF_IS_ERROR);
        return CRYPT_ENTROPY_ECF_IS_ERROR;
    }
    uint8_t conData[ECF_MAX_OUTPUT_LEN] = {0};
    uint32_t conLen = ECF_MAX_OUTPUT_LEN;
    int32_t ret = enCtx->conFunc(enCtx->algId, data, dataLen, conData, &conLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t cpLen = (conLen > *outLen) ? *outLen : conLen;
    (void)memcpy_s(out, cpLen, conData, cpLen);
    (void)memset_s(conData, conLen, 0, conLen);
    *outLen = cpLen;
    return CRYPT_SUCCESS;
}

static uint32_t GetNeedEntropyLen(uint32_t currEnt, uint32_t needEnt)
{
    if (currEnt > needEnt) {
        return ((currEnt - needEnt) >= ECF_ADDITION_ENTROPY) ? 0 :
            (ECF_ADDITION_ENTROPY - (currEnt - needEnt));
    }
    return needEnt + ECF_ADDITION_ENTROPY - currEnt;
}

static int32_t CpEntropyToOut(ENTROPY_SeedPool *pool, uint8_t *in, uint32_t inLen, uint8_t *data, uint32_t len)
{
    uint32_t cpLen = (inLen < len) ? inLen : len;
    (void)memcpy_s(data, len, in, cpLen);
    (void)memset_s(in, inLen, 0, inLen);
    if (cpLen < len) {
        uint32_t tmpLen = len - cpLen;
        uint32_t entropy = ENTROPY_SeedPoolCollect(pool, true, 0, data + cpLen, &tmpLen);
        if (entropy == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT);
            return CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT;
        }
    }
    return CRYPT_SUCCESS;
}

int32_t ENTROPY_GetFullEntropyInput(void *ctx, ENTROPY_SeedPool *pool, bool isNpesUsed, uint32_t needEntropy,
    uint8_t *data, uint32_t len)
{
    int32_t ret;
    uint8_t *ptr = data;
    uint32_t remainLen = len;
    if (ENTROPY_SeedPoolGetMinEntropy(pool) == 0) {
        return CRYPT_INVALID_ARG;
    }
    uint32_t needLen = (needEntropy + ECF_ADDITION_ENTROPY) / ENTROPY_SeedPoolGetMinEntropy(pool) + 1;
    uint8_t *tmp = BSL_SAL_Malloc(needLen);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    /*
     * If the length of the entropy data is less than the lower limit of the required length,
     * the entropy data that meets the length requirement is read without considering the entropy.
     */
    uint32_t tmpLen = needLen;
    uint32_t entropy = ENTROPY_SeedPoolCollect(pool, isNpesUsed, needEntropy, tmp, &tmpLen);
    if (entropy < needEntropy) {
        GOTO_ERR_IF(CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT, ret);
    }
    /* If the data of the length specified by tmpLen can be provided, the value is the full entropy (tmpLen * 8). */
    if (tmpLen * ECF_BYTE_TO_BIT == entropy) {
        ret = CpEntropyToOut(pool, tmp, tmpLen, data, len);
        BSL_SAL_FREE(tmp);
        return ret;
    }
    do {
        uint32_t leftEnt = GetNeedEntropyLen(entropy, needEntropy);
        if (leftEnt != 0) {
            uint32_t readLen = needLen - tmpLen;
            uint32_t exEntropy = ENTROPY_SeedPoolCollect(pool, isNpesUsed, leftEnt, tmp + tmpLen, &readLen);
            if (exEntropy < leftEnt) {
                GOTO_ERR_IF(CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT, ret);
            }
            tmpLen += readLen;
        }
        uint32_t cpLen = remainLen;
        GOTO_ERR_IF(EntropyEcf(ctx, tmp, tmpLen, ptr, &cpLen), ret);
        remainLen -= cpLen;
        ptr += cpLen;
        entropy = 0;
        tmpLen = 0;
    } while (remainLen > 0);
ERR:
    (void)memset_s(tmp, needLen, 0, needLen);
    BSL_SAL_FREE(tmp);
    return ret;
}

#endif /* HITLS_CRYPTO_ENTROPY */
