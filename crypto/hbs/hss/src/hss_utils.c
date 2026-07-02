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
#ifdef HITLS_CRYPTO_HSS_LMS

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "hss_local.h"

int32_t HssParaInit(HSS_Para *para, uint32_t levels, const uint32_t *lmsTypes, const uint32_t *otsTypes)
{
    if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_LEVEL);
        return CRYPT_HSS_INVALID_LEVEL;
    }

    // IMPORTANT: Save copies of lmsTypes and otsTypes arrays before memset
    // because they might point to para->lmsType/para->otsType which will be zeroed!
    uint32_t lmsTypesCopy[HSS_LEVELS_ARRAY_SIZE];
    uint32_t otsTypesCopy[HSS_LEVELS_ARRAY_SIZE];

    for (uint32_t i = 0; i < levels; i++) {
        lmsTypesCopy[i] = lmsTypes[i];
        otsTypesCopy[i] = otsTypes[i];
    }

    // Clear parameter structure (this may zero the input arrays if they point to para!)
    memset(para, 0, sizeof(HSS_Para));

    para->levels = levels;

    // Initialize LMS parameters for each level
    for (uint32_t i = 0; i < levels; i++) {
        para->lmsType[i] = lmsTypesCopy[i];
        para->otsType[i] = otsTypesCopy[i];

        // Directly use LMS's initialization function
        int32_t ret = LmsParaInit(&para->levelPara[i], lmsTypesCopy[i], otsTypesCopy[i]);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret; // Return the actual LMS error code
        }
    }

    // Set HSS-level parameters
    // HSS public key = levels(4) + pub[0] where pub[0] = lms_type(4) + ots_type(4) + I(16) + root(n) = 24 + n
    // Total = 4 + 24 + n = 28 + n
    para->pubKeyLen = HSS_PUBKEY_ROOT_OFFSET + para->levelPara[0].n;
    para->prvKeyLen = HSS_PRVKEY_LEN;
    para->sigLen = HssGetSignatureLen(para);
    para->maxSignatures = HssGetMaxSignatures(para);

    if (para->sigLen == 0 || para->maxSignatures == 0) {
        memset(para, 0, sizeof(HSS_Para));
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }

    return CRYPT_SUCCESS;
}

uint32_t HssGetSignatureLen(const HSS_Para *para)
{
    if (para->levels == 0) {
        return 0;
    }

    // HSS signature = Nspk(4) + bottom_sig + signed_pub_keys[1..L-1]
    uint32_t totalLen = HSS_SIG_NSPK_LEN;

    // Bottom-level LMS signature (for message)
    totalLen += para->levelPara[para->levels - 1].sigLen;

    // Signed public keys for levels 1 to L-1
    // Each signed_pub_key = LMS_sig(child's pub key) + child's pub key (24 + n)
    for (uint32_t i = 0; i < para->levels - 1; i++) {
        totalLen += para->levelPara[i].sigLen + para->levelPara[i + 1].pubKeyLen;
    }

    return totalLen;
}

uint64_t HssGetMaxSignatures(const HSS_Para *para)
{
    if (para->levels == 0) {
        return 0;
    }

    // Total signatures = product of (2^height) for all levels
    uint64_t total = 1;
    for (uint32_t i = 0; i < para->levels; i++) {
        uint32_t height = para->levelPara[i].height;

        // Check for overflow: height must be <= 60 to safely compute (1ULL << height) without overflow
        // and total must have enough headroom for multiplication
        if (height > LMS_MAX_SAFE_HEIGHT_FOR_UINT64 || total > (UINT64_MAX >> height)) {
            return 0; // Return 0 to indicate overflow/unsupported configuration
        }

        total *= (1ULL << height);
    }

    return total;
}

#endif /* HITLS_CRYPTO_HSS_LMS */
