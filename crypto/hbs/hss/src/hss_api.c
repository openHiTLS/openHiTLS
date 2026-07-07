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
#include "crypt_utils.h"
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
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_HSS_Ctx *newCtx = (CRYPT_HSS_Ctx *)CRYPT_HSS_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    memcpy(&newCtx->para, &srcCtx->para, sizeof(HSS_Para));
    if (srcCtx->publicKey != NULL && srcCtx->publicLen > 0) {
        newCtx->publicKey = (uint8_t *)BSL_SAL_Calloc(1, srcCtx->publicLen);
        if (newCtx->publicKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            CRYPT_HSS_FreeCtx(newCtx);
            return NULL;
        }
        newCtx->publicLen = srcCtx->publicLen;
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
    RETURN_RET_IF((ctx->para.levels != 0), CRYPT_HSS_CTRL_INIT_REPEATED);
    BSL_Param *params = (BSL_Param *)val;
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
    RETURN_RET_IF((levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS), CRYPT_HSS_INVALID_LEVEL);

    uint32_t lmsTypes[HSS_LEVELS_ARRAY_SIZE] = {0};
    uint32_t otsTypes[HSS_LEVELS_ARRAY_SIZE] = {0};

    static const int32_t g_lmsTypeKeys[] = {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE,
        CRYPT_PARAM_HSS_LEVEL3_LMS_TYPE
    };
    static const int32_t g_otsTypeKeys[] = {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE,
        CRYPT_PARAM_HSS_LEVEL3_OTS_TYPE
    };

    for (uint32_t i = 0; i < levels; i++) {
        const BSL_Param *lmsParam = BSL_PARAM_FindConstParam(params, g_lmsTypeKeys[i]);
        RETURN_RET_IF((lmsParam == NULL), CRYPT_HSS_INVALID_PARAM);
        valLen = sizeof(lmsTypes[i]);
        if (BSL_PARAM_GetValue(lmsParam, g_lmsTypeKeys[i], BSL_PARAM_TYPE_UINT32,
            &lmsTypes[i], &valLen) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
        }
        const BSL_Param *otsParam = BSL_PARAM_FindConstParam(params, g_otsTypeKeys[i]);
        RETURN_RET_IF((otsParam == NULL), CRYPT_HSS_INVALID_PARAM);
        valLen = sizeof(otsTypes[i]);
        if (BSL_PARAM_GetValue(otsParam, g_otsTypeKeys[i], BSL_PARAM_TYPE_UINT32,
            &otsTypes[i], &valLen) != CRYPT_SUCCESS) {
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
    {CRYPT_HSS_SHA256_L2_H10_H10_W4,    2, {LMS_SHA256_M32_H10, LMS_SHA256_M32_H10},
        {LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L2_H15_H15_W4,    2, {LMS_SHA256_M32_H15, LMS_SHA256_M32_H15},
        {LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L2_H20_H20_W4,    2, {LMS_SHA256_M32_H20, LMS_SHA256_M32_H20},
        {LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4}},
    {CRYPT_HSS_SHA256_L3_H10_H10_H10_W4, 3, {LMS_SHA256_M32_H10, LMS_SHA256_M32_H10, LMS_SHA256_M32_H10},
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

    for (uint32_t i = 0; i < sizeof(g_hssAlgMap) / sizeof(g_hssAlgMap[0]); i++) {
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
        case CRYPT_CTRL_HSS_GET_LEVELS:
            return HssCtrlGetLevels(ctx, val, valLen);
        case CRYPT_CTRL_HSS_GET_SIG_LEN:
            return HssCtrlGetSigLen(ctx, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_CMD);
            return CRYPT_HSS_INVALID_CMD;
    }
}

#endif /* HITLS_CRYPTO_HSS_LMS */
