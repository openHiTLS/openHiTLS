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
#ifdef HITLS_CRYPTO_HSS

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
    para->pubKeyLen = 28 + para->levelPara[0].n;
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

/**
 * @ingroup hss
 * @brief Compress LMS type to compact representation
 * @param lmsType [IN]  LMS type identifier
 * @param lmsComp [OUT] Compressed LMS type (height value)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssCompressLmsType(uint32_t lmsType, uint8_t *lmsComp)
{
    switch (lmsType) {
        case LMS_SHA256_M32_H5:
            *lmsComp = 5;
            break;
        case LMS_SHA256_M32_H10:
            *lmsComp = 10;
            break;
        case LMS_SHA256_M32_H15:
            *lmsComp = 15;
            break;
        case LMS_SHA256_M32_H20:
            *lmsComp = 20;
            break;
        case LMS_SHA256_M32_H25:
            *lmsComp = 25;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Compress OTS type to compact representation
 * @param otsType [IN]  OTS type identifier
 * @param otsComp [OUT] Compressed OTS type (w value)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssCompressOtsType(uint32_t otsType, uint8_t *otsComp)
{
    switch (otsType) {
        case LMOTS_SHA256_N32_W1:
            *otsComp = 1;
            break;
        case LMOTS_SHA256_N32_W2:
            *otsComp = 2;
            break;
        case LMOTS_SHA256_N32_W4:
            *otsComp = 4;
            break;
        case LMOTS_SHA256_N32_W8:
            *otsComp = 8;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
    }
    return CRYPT_SUCCESS;
}

int32_t HssCompressParamSet(uint8_t compressed[8], const HSS_Para *para)
{
    if (para->levels < HSS_MIN_LEVELS || para->levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_LEVEL);
        return CRYPT_HSS_INVALID_LEVEL;
    }

    memset(compressed, 0, HSS_COMPRESSED_PARAMS_LEN);
    compressed[0] = (uint8_t)para->levels;

    for (uint32_t i = 0; i < para->levels && i < HSS_MAX_LEVELS; i++) {
        uint8_t lmsComp;
        uint8_t otsComp;
        int32_t ret = HssCompressLmsType(para->lmsType[i], &lmsComp);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        ret = HssCompressOtsType(para->otsType[i], &otsComp);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        compressed[HSS_COMPRESSED_LEVEL_FIELD_SIZE + i * HSS_COMPRESSED_PARAM_PAIR_SIZE] = lmsComp;
        compressed[HSS_COMPRESSED_LEVEL_FIELD_SIZE + i * HSS_COMPRESSED_PARAM_PAIR_SIZE + 1] = otsComp;
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Decompress LMS type from compact representation
 * @param lmsComp [IN]  Compressed LMS type (height value)
 * @param lmsType [OUT] LMS type identifier
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssDecompressLmsType(uint8_t lmsComp, uint32_t *lmsType)
{
    switch (lmsComp) {
        case 5:
            *lmsType = LMS_SHA256_M32_H5;
            break;
        case 10:
            *lmsType = LMS_SHA256_M32_H10;
            break;
        case 15:
            *lmsType = LMS_SHA256_M32_H15;
            break;
        case 20:
            *lmsType = LMS_SHA256_M32_H20;
            break;
        case 25:
            *lmsType = LMS_SHA256_M32_H25;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Decompress OTS type from compact representation
 * @param otsComp [IN]  Compressed OTS type (w value)
 * @param otsType [OUT] OTS type identifier
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssDecompressOtsType(uint8_t otsComp, uint32_t *otsType)
{
    switch (otsComp) {
        case 1:
            *otsType = LMOTS_SHA256_N32_W1;
            break;
        case 2:
            *otsType = LMOTS_SHA256_N32_W2;
            break;
        case 4:
            *otsType = LMOTS_SHA256_N32_W4;
            break;
        case 8:
            *otsType = LMOTS_SHA256_N32_W8;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
    }
    return CRYPT_SUCCESS;
}

int32_t HssDecompressParamSet(HSS_Para *para, const uint8_t compressed[8])
{
    uint32_t levels = compressed[0];
    if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_LEVEL);
        return CRYPT_HSS_INVALID_LEVEL;
    }

    uint32_t lmsTypes[HSS_LEVELS_ARRAY_SIZE];
    uint32_t otsTypes[HSS_LEVELS_ARRAY_SIZE];

    for (uint32_t i = 0; i < levels; i++) {
        uint8_t lmsComp = compressed[HSS_COMPRESSED_LEVEL_FIELD_SIZE + i * HSS_COMPRESSED_PARAM_PAIR_SIZE];
        uint8_t otsComp = compressed[HSS_COMPRESSED_LEVEL_FIELD_SIZE + i * HSS_COMPRESSED_PARAM_PAIR_SIZE + 1];

        int32_t ret = HssDecompressLmsType(lmsComp, &lmsTypes[i]);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        ret = HssDecompressOtsType(otsComp, &otsTypes[i]);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    int32_t initRet = HssParaInit(para, levels, lmsTypes, otsTypes);
    if (initRet != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(initRet);
    }
    return initRet;
}

uint32_t HssGetSignatureLen(const HSS_Para *para)
{
    if (para->levels == 0) {
        return 0;
    }

    // HSS signature = Nspk(4) + bottom_sig + signed_pub_keys[1..L-1]
    size_t totalLen = HSS_SIG_NSPK_LEN;

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

int32_t HssGenerateRootSeed(uint8_t rootI[16], uint8_t rootSeed[32], const uint8_t masterSeed[32])
{
    // Derive root I: SHA256(masterSeed || 0x00 || 0x00)
    uint8_t buffer[HSS_ROOT_SEED_DERIVE_BUF_LEN];
    memcpy(buffer, masterSeed, LMS_SEED_LEN);
    buffer[LMS_SEED_LEN] = HSS_SEED_ROOT_I;
    buffer[LMS_SEED_LEN + 1] = 0x00; // Padding byte

    uint8_t hash[LMS_SHA256_N];
    int32_t ret = LmsHash(hash, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SEED_DERIVE_FAIL);
        return CRYPT_HSS_SEED_DERIVE_FAIL;
    }
    memcpy(rootI, hash, LMS_I_LEN); // Take first 16 bytes

    // Derive root seed: SHA256(masterSeed || 0x01 || 0x00)
    buffer[LMS_SEED_LEN] = HSS_SEED_ROOT_SEED;
    buffer[LMS_SEED_LEN + 1] = 0x00; // Padding byte

    ret = LmsHash(rootSeed, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SEED_DERIVE_FAIL);
        return CRYPT_HSS_SEED_DERIVE_FAIL;
    }

    BSL_SAL_CleanseData(buffer, sizeof(buffer));
    return CRYPT_SUCCESS;
}

int32_t HssGenerateChildSeed(uint8_t childI[16], uint8_t childSeed[32], const uint8_t parentI[16],
                             const uint8_t parentSeed[32], const HssChildPosition *position)
{
    // Buffer: parentSeed(32) || parentI(16) || treeIndex(8) || level(4)
    uint8_t buffer[HSS_CHILD_SEED_DERIVE_BUF_LEN];
    memcpy(buffer, parentSeed, LMS_SEED_LEN);
    memcpy(buffer + LMS_SEED_LEN, parentI, LMS_I_LEN);
    BSL_Uint64ToByte(position->treeIndex, buffer + LMS_SEED_LEN + LMS_I_LEN);
    BSL_Uint32ToByte(position->level, buffer + LMS_SEED_LEN + LMS_I_LEN + LMS_TREE_INDEX_BYTES);

    // Derive child I: SHA256(buffer)
    uint8_t hash[LMS_SHA256_N];
    int32_t ret = LmsHash(hash, buffer, HSS_CHILD_SEED_DERIVE_BUF_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(buffer, sizeof(buffer));
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SEED_DERIVE_FAIL);
        return CRYPT_HSS_SEED_DERIVE_FAIL;
    }
    memcpy(childI, hash, LMS_I_LEN); // Take first 16 bytes

    // Derive child seed: SHA256(buffer || 0x01)
    uint8_t bufferWithSuffix[HSS_CHILD_SEED_SUFFIX_BUF_LEN];
    memcpy(bufferWithSuffix, buffer, HSS_CHILD_SEED_DERIVE_BUF_LEN);
    bufferWithSuffix[HSS_CHILD_SEED_DERIVE_BUF_LEN] = HSS_SEED_CHILD_SUFFIX;

    ret = LmsHash(childSeed, bufferWithSuffix, HSS_CHILD_SEED_SUFFIX_BUF_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(buffer, sizeof(buffer));
        BSL_SAL_CleanseData(bufferWithSuffix, sizeof(bufferWithSuffix));
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SEED_DERIVE_FAIL);
        return CRYPT_HSS_SEED_DERIVE_FAIL;
    }

    BSL_SAL_CleanseData(buffer, sizeof(buffer));
    BSL_SAL_CleanseData(bufferWithSuffix, sizeof(bufferWithSuffix));
    return CRYPT_SUCCESS;
}

int32_t HssCalculateTreeIndices(const HSS_Para *para, uint64_t globalIndex, uint64_t treeIndex[HSS_LEVELS_ARRAY_SIZE],
                                uint32_t leafIndex[HSS_LEVELS_ARRAY_SIZE])
{
    if (para->levels == 0 || para->levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_LEVEL);
        return CRYPT_HSS_INVALID_LEVEL;
    }

    // Calculate signatures per tree at each level
    // sigsPerTree[i] = total number of signatures producible by the sub-hierarchy
    //                  rooted at a single tree at level i (i.e. 2^h[i] * 2^h[i+1] * ... * 2^h[L-1])
    uint64_t sigsPerTree[HSS_LEVELS_ARRAY_SIZE];
    sigsPerTree[para->levels - 1] = 1ULL << para->levelPara[para->levels - 1].height;

    for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
        uint32_t currentHeight = para->levelPara[i].height;
        sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << currentHeight);
    }

    // Calculate tree and leaf indices for each level
    for (uint32_t i = 0; i < para->levels; i++) {
        // Tree index at level i = globalIndex / sigsPerTree[i]
        treeIndex[i] = globalIndex / sigsPerTree[i];

        // Leaf index at level i = (globalIndex / sigsPerTree[i+1]) % (2^height[i])
        uint32_t height = para->levelPara[i].height;
        uint64_t maxLeaves = 1ULL << height;

        if (i == para->levels - 1) {
            // Bottom level: leaf = globalIndex mod (2^height)
            leafIndex[i] = (uint32_t)(globalIndex % maxLeaves);
        } else {
            // Higher levels: leaf = (globalIndex / sigsPerTree[i+1]) mod (2^height)
            leafIndex[i] = (uint32_t)((globalIndex / sigsPerTree[i + 1]) % maxLeaves);
        }
    }

    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_HSS */
