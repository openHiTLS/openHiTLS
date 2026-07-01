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
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_local_types.h"
#include "crypt_params_key.h"
#include "hss_local.h"

CRYPT_HSS_Ctx *CRYPT_HSS_NewCtx(void)
{
    return (CRYPT_HSS_Ctx *)BSL_SAL_Calloc(1, sizeof(CRYPT_HSS_Ctx));
}

CRYPT_HSS_Ctx *CRYPT_HSS_NewCtxEx(void *libCtx)
{
    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

void CRYPT_HSS_FreeCtx(CRYPT_HSS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    BSL_SAL_ClearFree(ctx->privateKey, HSS_PRVKEY_LEN);
    BSL_SAL_ClearFree(ctx->publicKey, ctx->publicLen);
    for (uint32_t i = 0; i < HSS_LEVELS_ARRAY_SIZE; i++) {
        BSL_SAL_ClearFree(ctx->cachedTrees[i], ctx->cachedTreeSizes[i]);
    }
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_HSS_Ctx));
}

CRYPT_HSS_Ctx *CRYPT_HSS_DupCtx(CRYPT_HSS_Ctx *srcCtx)
{
    if (srcCtx == NULL) {
        return NULL;
    }

    CRYPT_HSS_Ctx *newCtx = (CRYPT_HSS_Ctx *)CRYPT_HSS_NewCtx();
    if (newCtx == NULL) {
        return NULL;
    }

    newCtx->para = srcCtx->para;

    if (srcCtx->publicKey != NULL && srcCtx->publicLen > 0) {
        newCtx->publicLen = srcCtx->publicLen;
        newCtx->publicKey = (uint8_t *)BSL_SAL_Calloc(1, newCtx->publicLen);
        if (newCtx->publicKey == NULL) {
            CRYPT_HSS_FreeCtx(newCtx);
            return NULL;
        }
        memcpy(newCtx->publicKey, srcCtx->publicKey, newCtx->publicLen);
    }

    newCtx->signatureIndex = 0;
    return newCtx;
}

int32_t CRYPT_HSS_Cmp(CRYPT_HSS_Ctx *ctx1, CRYPT_HSS_Ctx *ctx2)
{
    if (ctx1 == NULL || ctx2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
        return CRYPT_HSS_CMP_FALSE;
    }

    // Compare parameters
    if (ctx1->para.levels != ctx2->para.levels) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
        return CRYPT_HSS_CMP_FALSE;
    }
    for (uint32_t i = 0; i < ctx1->para.levels; i++) {
        if (ctx1->para.lmsType[i] != ctx2->para.lmsType[i] || ctx1->para.otsType[i] != ctx2->para.otsType[i]) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
            return CRYPT_HSS_CMP_FALSE;
        }
    }

    // Compare public keys
    if ((ctx1->publicKey == NULL) != (ctx2->publicKey == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
        return CRYPT_HSS_CMP_FALSE;
    }
    if (ctx1->publicKey != NULL) {
        if (ctx1->publicLen != ctx2->publicLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
            return CRYPT_HSS_CMP_FALSE;
        }
        if (ConstTimeMemcmp(ctx1->publicKey, ctx2->publicKey, ctx1->publicLen) == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
            return CRYPT_HSS_CMP_FALSE;
        }
    }

    // Compare private keys -- constant-time to prevent timing side-channel leakage
    if ((ctx1->privateKey == NULL) != (ctx2->privateKey == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
        return CRYPT_HSS_CMP_FALSE;
    }
    if (ctx1->privateKey != NULL) {
        if (ConstTimeMemcmp(ctx1->privateKey, ctx2->privateKey, HSS_PRVKEY_LEN) == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
            return CRYPT_HSS_CMP_FALSE;
        }
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Set all HSS parameters via BSL_Param array
 * @param ctx    [IN/OUT] HSS context
 * @param val    [IN]     BSL_Param array terminated by BSL_PARAM_END
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssCtrlSetParam(CRYPT_HSS_Ctx *ctx, void *val)
{
    BSL_Param *params = (BSL_Param *)val;
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    const BSL_Param *levelParam = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_HSS_LEVEL);
    if (levelParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    uint32_t levels = 0;
    uint32_t valLen = sizeof(levels);
    if (BSL_PARAM_GetValue(levelParam, CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, &valLen) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_LEVEL);
        return CRYPT_HSS_INVALID_LEVEL;
    }

    uint32_t lmsTypes[HSS_LEVELS_ARRAY_SIZE] = {0};
    uint32_t otsTypes[HSS_LEVELS_ARRAY_SIZE] = {0};

    static const int32_t g_lmsTypeKeys[] = {
        CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE,
        CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE,
        CRYPT_PARAM_HSS_LEVEL3_LMS_TYPE
    };
    static const int32_t g_otsTypeKeys[] = {
        CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE,
        CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE,
        CRYPT_PARAM_HSS_LEVEL3_OTS_TYPE
    };

    for (uint32_t i = 0; i < levels; i++) {
        const BSL_Param *lmsParam = BSL_PARAM_FindConstParam(params, g_lmsTypeKeys[i]);
        if (lmsParam == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
        }
        valLen = sizeof(lmsTypes[i]);
        if (BSL_PARAM_GetValue(lmsParam, g_lmsTypeKeys[i], BSL_PARAM_TYPE_UINT32, &lmsTypes[i], &valLen) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
        }
        const BSL_Param *otsParam = BSL_PARAM_FindConstParam(params, g_otsTypeKeys[i]);
        if (otsParam == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
        }
        valLen = sizeof(otsTypes[i]);
        if (BSL_PARAM_GetValue(otsParam, g_otsTypeKeys[i], BSL_PARAM_TYPE_UINT32, &otsTypes[i], &valLen) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
        }
    }
    return HssParaInit(&ctx->para, levels, lmsTypes, otsTypes);
}

/**
 * @ingroup hss
 * @brief Get public key length
 * @param val    [OUT] Public key length (always 60)
 * @param valLen [IN]  Value buffer length (must be sizeof(uint32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssCtrlGetPubKeyLen(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (ctx->para.pubKeyLen == 0) {
        int32_t ret = HssParaInit(&ctx->para, ctx->para.levels, ctx->para.lmsType, ctx->para.otsType);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    *(uint32_t *)val = ctx->para.pubKeyLen;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Get private key length
 * @param val    [OUT] Private key length (always 48)
 * @param valLen [IN]  Value buffer length (must be sizeof(uint32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssCtrlGetPrvKeyLen(void *val, uint32_t valLen)
{
    if (valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    *(uint32_t *)val = HSS_PRVKEY_LEN;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Get signature length
 * @param ctx    [IN]  HSS context
 * @param val    [OUT] Signature length
 * @param valLen [IN]  Value buffer length (must be sizeof(uint32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssCtrlGetSigLen(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }

    if (ctx->para.pubKeyLen == 0) {
        int32_t ret = HssParaInit(&ctx->para, ctx->para.levels, ctx->para.lmsType, ctx->para.otsType);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    uint32_t sigLen = HssGetSignatureLen(&ctx->para);
    if (sigLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }

    *(uint32_t *)val = sigLen;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Get remaining signature capacity
 * @param ctx    [IN]  HSS context
 * @param val    [OUT] Remaining signatures
 * @param valLen [IN]  Value buffer length (must be sizeof(uint64_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssCtrlGetRemaining(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(uint64_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (ctx->para.levels == 0 || ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    if (ctx->para.pubKeyLen == 0) {
        int32_t ret = HssParaInit(&ctx->para, ctx->para.levels, ctx->para.lmsType, ctx->para.otsType);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    uint64_t maxSigs = HssGetMaxSignatures(&ctx->para);
    uint64_t counter = BSL_ByteToUint64(ctx->privateKey + HSS_PRVKEY_COUNTER_OFFSET);
    uint64_t remaining = (maxSigs > 0 && counter < maxSigs) ? (maxSigs - counter) : 0;
    *(uint64_t *)val = remaining;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Get number of hierarchy levels
 * @param ctx    [IN]  HSS context
 * @param val    [OUT] Number of levels
 * @param valLen [IN]  Value buffer length (must be sizeof(uint32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssCtrlGetLevels(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    *(uint32_t *)val = ctx->para.levels;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Set HSS parameters by algorithm ID
 * @param ctx    [IN/OUT] HSS context
 * @param val    [IN]     Algorithm ID value
 * @param valLen [IN]     Value length (must be sizeof(int32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
/* Lookup table entry for HSS algorithm presets.
 * To add a new preset append an entry; the table is scanned linearly. */
typedef struct {
    int32_t algId;
    uint32_t levels;
    uint32_t lmsTypes[HSS_LEVELS_ARRAY_SIZE];
    uint32_t otsTypes[HSS_LEVELS_ARRAY_SIZE];
} HssAlgMapping;

static const HssAlgMapping g_hssAlgMap[] = {
    /* Multi-level HSS presets (all use W=4) */
    {CRYPT_HSS_SHA256_L2_H10_H10,    2, {LMS_SHA256_M32_H10, LMS_SHA256_M32_H10},
                                          {LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L2_H15_H15,    2, {LMS_SHA256_M32_H15, LMS_SHA256_M32_H15},
                                          {LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L2_H20_H20,    2, {LMS_SHA256_M32_H20, LMS_SHA256_M32_H20},
                                          {LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L3_H10_H10_H10, 3, {LMS_SHA256_M32_H10, LMS_SHA256_M32_H10, LMS_SHA256_M32_H10},
                                           {LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4}},
    /* Old LMS single-tree presets mapped to HSS L=1 */
    {CRYPT_HSS_SHA256_L1_H5_W4,  1, {LMS_SHA256_M32_H5},  {LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L1_H10_W4, 1, {LMS_SHA256_M32_H10}, {LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L1_H15_W4, 1, {LMS_SHA256_M32_H15}, {LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L1_H20_W4, 1, {LMS_SHA256_M32_H20}, {LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L1_H25_W4, 1, {LMS_SHA256_M32_H25}, {LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L1_H10_W2, 1, {LMS_SHA256_M32_H10}, {LMOTS_SHA256_N32_W2}},
    {CRYPT_HSS_SHA256_L1_H15_W2, 1, {LMS_SHA256_M32_H15}, {LMOTS_SHA256_N32_W2}},
    {CRYPT_HSS_SHA256_L1_H20_W2, 1, {LMS_SHA256_M32_H20}, {LMOTS_SHA256_N32_W2}},
    {CRYPT_HSS_SHA256_L1_H10_W8, 1, {LMS_SHA256_M32_H10}, {LMOTS_SHA256_N32_W8}},
    {CRYPT_HSS_SHA256_L1_H15_W8, 1, {LMS_SHA256_M32_H15}, {LMOTS_SHA256_N32_W8}},
    {CRYPT_HSS_SHA256_L1_H20_W8, 1, {LMS_SHA256_M32_H20}, {LMOTS_SHA256_N32_W8}},
};

static int32_t HssCtrlSetParaById(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (ctx->para.levels != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_CTRL_INIT_REPEATED);
        return CRYPT_HSS_CTRL_INIT_REPEATED;
    }
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t algId = *(int32_t *)val;

    for (size_t i = 0; i < sizeof(g_hssAlgMap) / sizeof(g_hssAlgMap[0]); i++) {
        if (g_hssAlgMap[i].algId == algId) {
            return HssParaInit(&ctx->para, g_hssAlgMap[i].levels,
                               g_hssAlgMap[i].lmsTypes, g_hssAlgMap[i].otsTypes);
        }
    }

    BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
    return CRYPT_HSS_INVALID_PARAM;
}

int32_t CRYPT_HSS_Ctrl(CRYPT_HSS_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    switch (cmd) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return HssCtrlSetParaById(ctx, val, valLen);
        case CRYPT_CTRL_HSS_SET_PARAM:
            return HssCtrlSetParam(ctx, val);
        case CRYPT_CTRL_HSS_GET_PUBKEY_LEN:
            return HssCtrlGetPubKeyLen(ctx, val, valLen);
        case CRYPT_CTRL_HSS_GET_PRVKEY_LEN:
            return HssCtrlGetPrvKeyLen(val, valLen);
        case CRYPT_CTRL_HSS_GET_SIG_LEN:
            return HssCtrlGetSigLen(ctx, val, valLen);
        case CRYPT_CTRL_HSS_GET_REMAINING:
            return HssCtrlGetRemaining(ctx, val, valLen);
        case CRYPT_CTRL_HSS_GET_LEVELS:
            return HssCtrlGetLevels(ctx, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_CMD);
            return CRYPT_HSS_INVALID_CMD;
    }
}

/* Invalidate and free all cached Merkle trees in the HSS context. */
static void HssInvalidateAllTreeCaches(CRYPT_HSS_Ctx *ctx)
{
    for (uint32_t i = 0; i < HSS_LEVELS_ARRAY_SIZE; i++) {
        BSL_SAL_ClearFree(ctx->cachedTrees[i], ctx->cachedTreeSizes[i]);
        ctx->cachedTrees[i] = NULL;
        ctx->cachedTreeSizes[i] = 0;
        ctx->treeCacheValid[i] = false;
        ctx->cachedTreeIndex[i] = 0;
    }
}

int32_t CRYPT_HSS_SetPrvKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *prvKeyParam = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_HSS_PRVKEY);
    if (prvKeyParam == NULL || prvKeyParam->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }
    if (prvKeyParam->valueLen != HSS_PRVKEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_KEY_LEN);
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    uint8_t compressed[HSS_COMPRESSED_PARAMS_LEN];
    memcpy(compressed, (const uint8_t *)prvKeyParam->value + HSS_PRVKEY_PARAMS_OFFSET, HSS_PRVKEY_PARAMS_LEN);
    HSS_Para newPara;
    memset(&newPara, 0, sizeof(newPara));
    int32_t ret = HssDecompressParamSet(&newPara, compressed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (ctx->privateKey == NULL) {
        ctx->privateKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PRVKEY_LEN);
        if (ctx->privateKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    memcpy(ctx->privateKey, prvKeyParam->value, HSS_PRVKEY_LEN);

    memcpy(&ctx->para, &newPara, sizeof(HSS_Para));

    HssInvalidateAllTreeCaches(ctx);
    ctx->signatureIndex = BSL_ByteToUint64(ctx->privateKey + HSS_PRVKEY_COUNTER_OFFSET);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_SetPubKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    /* Require parameters to have been initialized by SET_PARAM or SET_PARA_BY_ID first */
    if (ctx->para.pubKeyLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }

    const BSL_Param *pubKeyParam = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_HSS_PUBKEY);
    if (pubKeyParam == NULL || pubKeyParam->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }
    if (pubKeyParam->valueLen < HSS_PUBKEY_ROOT_OFFSET || pubKeyParam->valueLen != ctx->para.pubKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_KEY_LEN);
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    const uint8_t *keyData = (const uint8_t *)pubKeyParam->value;
    uint32_t levels = BSL_ByteToUint32(keyData + HSS_PUBKEY_LEVELS_OFFSET);
    uint32_t lmsType = BSL_ByteToUint32(keyData + HSS_PUBKEY_LMS_TYPE_OFFSET);
    uint32_t otsType = BSL_ByteToUint32(keyData + HSS_PUBKEY_OTS_TYPE_OFFSET);

    /* Strictly validate public key parameters against the preset configuration */
    if (ctx->para.levels != levels || ctx->para.lmsType[0] != lmsType || ctx->para.otsType[0] != otsType) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }

    void *tmpPubKey = BSL_SAL_Dump(pubKeyParam->value, pubKeyParam->valueLen);
    if (tmpPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (ctx->publicKey != NULL) {
        BSL_SAL_Free(ctx->publicKey);
    }
    ctx->publicKey = tmpPubKey;
    ctx->publicLen = pubKeyParam->valueLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_GetPrvKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    BSL_Param *prv = BSL_PARAM_FindParam(param, CRYPT_PARAM_HSS_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (prv->valueLen < HSS_PRVKEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_KEY_LEN);
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    memcpy(prv->value, ctx->privateKey, HSS_PRVKEY_LEN);
    prv->useLen = HSS_PRVKEY_LEN;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_GetPubKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    BSL_Param *pub = BSL_PARAM_FindParam(param, CRYPT_PARAM_HSS_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->publicLen == 0 || pub->valueLen < ctx->publicLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_KEY_LEN);
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    memcpy(pub->value, ctx->publicKey, ctx->publicLen);
    pub->useLen = ctx->publicLen;
    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_HSS_CHECK) && defined(HITLS_CRYPTO_HSS_KEYGEN)
/**
 * @ingroup hss
 * @brief Verify basic HSS parameters match between public and private keys
 * @param pubKey [IN] Public key context
 * @param prvKey [IN] Private key context
 * @return CRYPT_SUCCESS if parameters match, error code otherwise
 */
static int32_t HSSCheckBasicParams(const CRYPT_HSS_Ctx *pubKey, const CRYPT_HSS_Ctx *prvKey)
{
    uint32_t pubLevels = BSL_ByteToUint32(pubKey->publicKey + HSS_PUBKEY_LEVELS_OFFSET);
    if (pubLevels != prvKey->para.levels) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_HSS_PAIRWISE_CHECK_FAIL;
    }

    uint32_t pubLmsType = BSL_ByteToUint32(pubKey->publicKey + HSS_PUBKEY_LMS_TYPE_OFFSET);
    uint32_t pubOtsType = BSL_ByteToUint32(pubKey->publicKey + HSS_PUBKEY_OTS_TYPE_OFFSET);
    if (pubLmsType != prvKey->para.lmsType[0] || pubOtsType != prvKey->para.otsType[0]) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_HSS_PAIRWISE_CHECK_FAIL;
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Verify root hash matches between public and private keys
 * @param pubKey  [IN] Public key context
 * @param prvKey  [IN] Private key context
 * @param rootI   [IN] Root tree identifier (16 bytes)
 * @param rootSeed [IN] Root tree seed (32 bytes)
 * @return CRYPT_SUCCESS if root hash matches, error code otherwise
 */
static int32_t HSSVerifyRootHash(const CRYPT_HSS_Ctx *pubKey, const CRYPT_HSS_Ctx *prvKey, const uint8_t *rootI,
                                 const uint8_t *rootSeed)
{
    if (ConstTimeMemcmp(rootI, pubKey->publicKey + HSS_PUBKEY_I_OFFSET, LMS_I_LEN) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_HSS_PAIRWISE_CHECK_FAIL;
    }

    LMS_Para lmsPara;
    int32_t ret = LmsParaInit(&lmsPara, prvKey->para.lmsType[0], prvKey->para.otsType[0]);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t computedRoot[LMS_SHA256_N];
    ret = LmsComputeRoot(computedRoot, &lmsPara, rootI, rootSeed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    int32_t cmpRet = ConstTimeMemcmp(computedRoot, pubKey->publicKey + HSS_PUBKEY_ROOT_OFFSET, LMS_SHA256_N);
    BSL_SAL_CleanseData(computedRoot, sizeof(computedRoot));
    if (cmpRet == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_HSS_PAIRWISE_CHECK_FAIL;
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Verify HSS key pair consistency
 * @param pubKey [IN] Public key context
 * @param prvKey [IN] Private key context
 * @return CRYPT_SUCCESS if keys match, error code otherwise
 */
static int32_t HSSKeyPairCheck(const CRYPT_HSS_Ctx *pubKey, const CRYPT_HSS_Ctx *prvKey)
{
    if (pubKey == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->para.levels == 0 || prvKey->para.levels == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->publicKey == NULL || prvKey->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    int32_t ret = HSSCheckBasicParams(pubKey, prvKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t masterSeed[LMS_SEED_LEN];
    memcpy(masterSeed, prvKey->privateKey + HSS_PRVKEY_SEED_OFFSET, HSS_PRVKEY_SEED_LEN);

    uint8_t rootI[LMS_I_LEN];
    uint8_t rootSeed[LMS_SEED_LEN];
    ret = HssGenerateRootSeed(rootI, rootSeed, masterSeed);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HSSVerifyRootHash(pubKey, prvKey, rootI, rootSeed);
    /* masterSeed is a copy of the HSS master secret; rootSeed is the derived
     * root-tree WOTS+ seed. Both must be scrubbed on every exit path of this
     * helper. rootI is public-by-spec but cleansed for consistency with
     * LmsKeyGen/CRYPT_HSS_Gen. */
    BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));
    BSL_SAL_CleanseData(rootSeed, sizeof(rootSeed));
    BSL_SAL_CleanseData(rootI, sizeof(rootI));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/**
 * @ingroup hss
 * @brief Verify private key validity
 * @param prvKey [IN] Private key context
 * @return CRYPT_SUCCESS if valid, error code otherwise
 */
static int32_t HSSPrvKeyCheck(const CRYPT_HSS_Ctx *prvKey)
{
    if (prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->para.levels == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_Check(uint32_t checkType, const CRYPT_HSS_Ctx *pkey1, const CRYPT_HSS_Ctx *pkey2)
{
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            return HSSKeyPairCheck(pkey1, pkey2);
        case CRYPT_PKEY_CHECK_PRVKEY:
            return HSSPrvKeyCheck(pkey1);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}
#endif

#endif /* HITLS_CRYPTO_HSS_LMS */
