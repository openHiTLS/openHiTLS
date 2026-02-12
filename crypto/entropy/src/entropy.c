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
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_entropy.h"

#define ECF_MAX_OUTPUT_LEN 64
#define ECF_ADDITION_ENTROPY 64 // reference nist-800 90c-3pd section 3.3.2
#define ECF_BYTE_TO_BIT 8

static int32_t EntropyEcf(ENTROPY_ECFCtx *enCtx, uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen)
{
    uint8_t conData[ECF_MAX_OUTPUT_LEN] = {0};
    uint32_t conLen = ECF_MAX_OUTPUT_LEN;
    int32_t ret = enCtx->conFunc(enCtx->algId, data, dataLen, conData, &conLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t cpLen = (conLen > *outLen) ? *outLen : conLen;
    memcpy(out, conData, cpLen);
    memset(conData, 0, conLen);
    *outLen = cpLen;
    return CRYPT_SUCCESS;
}

int32_t ENTROPY_GetFullEntropyInput(void *ctx, ENTROPY_SeedPool *pool, bool isNpesUsed, uint32_t needEntropy,
    uint8_t *data, uint32_t len)
{
    int32_t ret = CRYPT_SUCCESS;
    uint8_t *ptr = data;
    if (ENTROPY_SeedPoolGetMinEntropy(pool) == 0) {
        return CRYPT_INVALID_ARG;
    }
    ENTROPY_ECFCtx *enCtx = (ENTROPY_ECFCtx *)ctx;
    if (enCtx == NULL || enCtx->conFunc == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ECF_IS_ERROR);
        return CRYPT_ENTROPY_ECF_IS_ERROR;
    }
    uint32_t conEnt = enCtx->outLen * ECF_BYTE_TO_BIT;
    uint32_t tmpEntropy = conEnt + ECF_ADDITION_ENTROPY;
    uint32_t tmpDataLen = (tmpEntropy + ECF_BYTE_TO_BIT - 1) / ENTROPY_SeedPoolGetMinEntropy(pool);
    uint8_t *tmpData = BSL_SAL_Malloc(tmpDataLen);
    if (tmpData == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t remEnt = needEntropy;
    uint32_t remLen = len;
    while (remEnt > 0) {
        uint32_t tmpLen = tmpDataLen;
        uint32_t oneEnt = (remEnt < conEnt) ? remEnt : conEnt;
        uint32_t entropy = ENTROPY_SeedPoolCollect(pool, isNpesUsed, oneEnt, tmpData, &tmpLen);
        if (entropy < oneEnt) {
            GOTO_ERR_IF(CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT, ret);
        }
        uint32_t cpLen;
        /* If the data of the length specified by tmpLen can be provided, the value is the full entropy (tmpLen * 8). */
        if (tmpLen * ECF_BYTE_TO_BIT == entropy) {
            cpLen = tmpLen < remLen ? tmpLen : remLen;
            memcpy(ptr, tmpData, cpLen);
            remEnt -= ((entropy > remEnt) ? remEnt : entropy);
        } else {
            uint32_t leftLen = tmpDataLen - tmpLen;
            uint32_t leftEnt = ENTROPY_SeedPoolCollect(pool, isNpesUsed, tmpEntropy - entropy, tmpData + tmpLen,
                &leftLen);
            if (leftEnt < tmpEntropy - entropy) {
                GOTO_ERR_IF(CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT, ret);
            }
            cpLen = remLen;
            GOTO_ERR_IF(EntropyEcf(ctx, tmpData, tmpLen + leftLen, ptr, &cpLen), ret);
            remEnt -= (remEnt < conEnt ? remEnt : conEnt);
        }
        ptr += cpLen;
        remLen -= cpLen;
    }
    if (remLen > 0) {
        uint32_t leftLen = remLen;
        uint32_t entropy = ENTROPY_SeedPoolCollect(pool, true, 0, ptr, &leftLen);
        if (entropy == 0 || leftLen < remLen) {
            GOTO_ERR_IF(CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT, ret);
        }
    }
ERR:
    memset(tmpData, 0, tmpDataLen);
    BSL_SAL_FREE(tmpData);
    return ret;
}

#endif /* HITLS_CRYPTO_ENTROPY */
