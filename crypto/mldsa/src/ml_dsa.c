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
#ifdef HITLS_CRYPTO_MLDSA
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "crypt_utils.h"
#include "crypt_algid.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "ml_dsa_local.h"
#include "eal_md_local.h"

// These data from NIST.FIPS.204 Table 1 and Table 2.
static const CRYPT_ML_DSA_Info MLDSA_PARAMETERTER_44 = {CRYPT_MLDSA_TYPE_MLDSA_44, 4,  4,   2,    39,   78,  (1 << 17),
                                                        ((MLDSA_Q - 1) / 88),      80, 128, 1312, 2560, 2420};

static const CRYPT_ML_DSA_Info MLDSA_PARAMETERTER_65 = {CRYPT_MLDSA_TYPE_MLDSA_65, 6,  5,   4,    49,   196, (1 << 19),
                                                        ((MLDSA_Q - 1) / 32),      55, 192, 1952, 4032, 3309};

static const CRYPT_ML_DSA_Info MLDSA_PARAMETERTER_87 = {CRYPT_MLDSA_TYPE_MLDSA_87, 8,  7,   2,    60,   120, (1 << 19),
                                                        ((MLDSA_Q - 1) / 32),      75, 256, 2592, 4896, 4627};

static const CRYPT_ML_DSA_Info *g_mldsaInfo[] = {&MLDSA_PARAMETERTER_44, &MLDSA_PARAMETERTER_65,
    &MLDSA_PARAMETERTER_87};

const CRYPT_ML_DSA_Info *CRYPT_ML_DSA_GetInfo(int32_t k)
{
    if (k == CRYPT_MLDSA_TYPE_MLDSA_44) {
        return g_mldsaInfo[0];
    } else if (k == CRYPT_MLDSA_TYPE_MLDSA_65) {
        return g_mldsaInfo[1];
    } else if (k == CRYPT_MLDSA_TYPE_MLDSA_87) {
        return g_mldsaInfo[2];
    }
    return NULL;
}

CRYPT_ML_DSA_Ctx *CRYPT_ML_DSA_NewCtx(void)
{
    CRYPT_ML_DSA_Ctx *keyCtx = BSL_SAL_Calloc(1, sizeof(CRYPT_ML_DSA_Ctx));
    if (keyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    keyCtx->needEncodeCtx = true;
    keyCtx->isMuMsg = false;
    keyCtx->deterministicSignFlag = false;
    keyCtx->needPreHash = false;
    keyCtx->hasSeed = false;
    keyCtx->prvKeyFormat = CRYPT_ALGO_MLDSA_PRIV_FORMAT_NOT_SET;
    BSL_SAL_ReferencesInit(&(keyCtx->references));
    return keyCtx;
}

CRYPT_ML_DSA_Ctx *CRYPT_ML_DSA_NewCtxEx(void *libCtx)
{
    CRYPT_ML_DSA_Ctx *ctx = CRYPT_ML_DSA_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

void CRYPT_ML_DSA_FreeCtx(CRYPT_ML_DSA_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int ret = 0;
    BSL_SAL_AtomicDownReferences(&(ctx->references), &ret);
    if (ret > 0) {
        return;
    }
    BSL_SAL_CleanseData(ctx->seed, MLDSA_SEED_BYTES_LEN);
    BSL_SAL_ClearFree(ctx->prvKey, ctx->prvLen);
    BSL_SAL_FREE(ctx->pubKey);
    BSL_SAL_FREE(ctx->ctxInfo);
    BSL_SAL_ReferencesFree(&(ctx->references));
    BSL_SAL_Free(ctx);
}

CRYPT_ML_DSA_Ctx *CRYPT_ML_DSA_DupCtx(CRYPT_ML_DSA_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_ML_DSA_Ctx *newCtx = CRYPT_ML_DSA_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    newCtx->info = ctx->info;
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->pubKey, ctx->pubKey, BSL_SAL_Dump(ctx->pubKey, ctx->pubLen),
        CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->prvKey, ctx->prvKey, BSL_SAL_Dump(ctx->prvKey, ctx->prvLen),
        CRYPT_MEM_ALLOC_FAIL);
    newCtx->pubLen = ctx->pubLen;
    newCtx->prvLen = ctx->prvLen;
    newCtx->needEncodeCtx = ctx->needEncodeCtx;
    newCtx->isMuMsg = ctx->isMuMsg;
    newCtx->deterministicSignFlag = ctx->deterministicSignFlag;
    newCtx->needPreHash = ctx->needPreHash;
    newCtx->libCtx = ctx->libCtx;
    return newCtx;
ERR:
    CRYPT_ML_DSA_FreeCtx(newCtx);
    return NULL;
}

static int32_t MlDSASetAlgInfo(CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->info != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_CTRL_INIT_REPEATED);
        return CRYPT_MLDSA_CTRL_INIT_REPEATED;
    }
    ctx->info = CRYPT_ML_DSA_GetInfo(*(int32_t *)val);
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}

static int32_t MlDSAGetParaId(CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_CTRL_INIT_REPEATED);
        return CRYPT_MLDSA_CTRL_INIT_REPEATED;
    }
    *(int32_t *)val = ctx->info->paramId;
    return CRYPT_SUCCESS;
}

static int32_t MLDSAGetSignLen(const CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYINFO_NOT_SET);
        return CRYPT_MLDSA_KEYINFO_NOT_SET;
    }
    *(int32_t *)val = ctx->info->signatureLen;
    return CRYPT_SUCCESS;
}

static int32_t MLDSAGetSecBits(const CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYINFO_NOT_SET);
        return CRYPT_MLDSA_KEYINFO_NOT_SET;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(int32_t *)val = ctx->info->secBits;
    return CRYPT_SUCCESS;
}

static int32_t MLDSAGetSeed(const CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!ctx->hasSeed) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_SEED_NOT_SET);
        return CRYPT_MLDSA_SEED_NOT_SET;
    }
    if (len != MLDSA_SEED_BYTES_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    (void)memcpy_s(val, len, ctx->seed, MLDSA_SEED_BYTES_LEN);
    return CRYPT_SUCCESS;
}

static int32_t MLDSASetPrvKeyFormat(CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(uint32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->prvKeyFormat = *(uint32_t *)val;
    return CRYPT_SUCCESS;
}

static int32_t MLDSAGetPrvKeyFormat(const CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(uint32_t *) val = ctx->prvKeyFormat;
    return CRYPT_SUCCESS;
}

static int32_t MlDSASetEncodeFlag(CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->needEncodeCtx = (*(int32_t *)val != 0);
    return CRYPT_SUCCESS;
}

static int32_t MlDSASetMsgFlag(CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->isMuMsg = (*(int32_t *)val != 0);
    return CRYPT_SUCCESS;
}

static int32_t MlDSASetDeterministicSignFlag(CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->deterministicSignFlag = (*(int32_t *)val != 0);
    return CRYPT_SUCCESS;
}

static int32_t MlDSASetPreHashFlag(CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->needPreHash = (*(int32_t *)val != 0);
    return CRYPT_SUCCESS;
}

int32_t MLDSASetctxInfo(CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    if (len > MLDSA_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYLEN_ERROR);
        return CRYPT_MLDSA_KEYLEN_ERROR;
    }
    if (ctx->ctxInfo != NULL) {
        BSL_SAL_FREE(ctx->ctxInfo);
        ctx->ctxLen = 0;
    }
    if (val == NULL && len == 0) {
        ctx->needEncodeCtx = true;
        return CRYPT_SUCCESS;
    }

    ctx->ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);
    if (ctx->ctxInfo == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->ctxLen = len;
    ctx->needEncodeCtx = true;
    return CRYPT_SUCCESS;
}

static int32_t MLDSAGetPubKeyLen(const CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF((ctx->info == NULL), CRYPT_MLDSA_KEYINFO_NOT_SET);
    RETURN_RET_IF((len != sizeof(uint32_t)), CRYPT_INVALID_ARG);
    *(uint32_t *)val = ctx->info->publicKeyLen;
    return CRYPT_SUCCESS;
}

static int32_t MLDSAGetPrvKeyLen(const CRYPT_ML_DSA_Ctx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF((ctx->info == NULL), CRYPT_MLDSA_KEYINFO_NOT_SET);
    RETURN_RET_IF((len != sizeof(uint32_t)), CRYPT_INVALID_ARG);
    *(uint32_t *)val = ctx->info->privateKeyLen;
    return CRYPT_SUCCESS;
}

static int32_t MLDSACleanPubKey(CRYPT_ML_DSA_Ctx *ctx)
{
    if (ctx->pubKey != NULL) {
        BSL_SAL_CleanseData(ctx->pubKey, ctx->pubLen);
        BSL_SAL_FREE(ctx->pubKey);
        ctx->pubLen = 0;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ML_DSA_Ctrl(CRYPT_ML_DSA_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch ((uint32_t)opt) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return MlDSASetAlgInfo(ctx, val, len);
        case CRYPT_CTRL_GET_PARAID:
            return MlDSAGetParaId(ctx, val, len);
        case CRYPT_CTRL_GET_SIGNLEN:
            return MLDSAGetSignLen(ctx, val, len);
        case CRYPT_CTRL_GET_SECBITS:
            return MLDSAGetSecBits(ctx, val, len);
        case CRYPT_CTRL_SET_CTX_INFO:
            return MLDSASetctxInfo(ctx, val, len);
        case CRYPT_CTRL_SET_MLDSA_ENCODE_FLAG:
            return MlDSASetEncodeFlag(ctx, val, len);
        case CRYPT_CTRL_SET_MLDSA_MUMSG_FLAG:
            return MlDSASetMsgFlag(ctx, val, len);
        case CRYPT_CTRL_SET_DETERMINISTIC_FLAG:
            return MlDSASetDeterministicSignFlag(ctx, val, len);
        case CRYPT_CTRL_SET_PREHASH_FLAG:
            return MlDSASetPreHashFlag(ctx, val, len);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return MLDSAGetPubKeyLen(ctx, val, len);
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            return MLDSAGetPrvKeyLen(ctx, val, len);
        case CRYPT_CTRL_GET_MLDSA_SEED:
            return MLDSAGetSeed(ctx, val, len);
        case CRYPT_CTRL_SET_MLDSA_PRVKEY_FORMAT:
            return MLDSASetPrvKeyFormat(ctx, val, len);
        case CRYPT_CTRL_GET_MLDSA_PRVKEY_FORMAT:
            return MLDSAGetPrvKeyFormat(ctx, val, len);
        case CRYPT_CTRL_CLEAN_PUB_KEY:
            return MLDSACleanPubKey(ctx);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_CTRL_NOT_SUPPORT);
            return CRYPT_MLDSA_CTRL_NOT_SUPPORT;
    }
}

static int32_t MLDSACreateKeyBuf(CRYPT_ML_DSA_Ctx *ctx)
{
    if (ctx->pubKey == NULL) {
        ctx->pubKey = BSL_SAL_Malloc(ctx->info->publicKeyLen);
        if (ctx->pubKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ctx->pubLen = ctx->info->publicKeyLen;
    }
    if (ctx->prvKey == NULL) {
        ctx->prvKey = BSL_SAL_Malloc(ctx->info->privateKeyLen);
        if (ctx->prvKey == NULL) {
            BSL_SAL_FREE(ctx->pubKey);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ctx->prvLen = ctx->info->privateKeyLen;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ML_DSA_GenKey(CRYPT_ML_DSA_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYINFO_NOT_SET);
        return CRYPT_MLDSA_KEYINFO_NOT_SET;
    }
    if (MLDSACreateKeyBuf(ctx) != CRYPT_SUCCESS) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint8_t seed[MLDSA_SEED_BYTES_LEN];
    int32_t ret = CRYPT_RandEx(ctx->libCtx, seed, MLDSA_SEED_BYTES_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = MLDSA_KeyGenInternal(ctx, seed);
    BSL_SAL_CleanseData(seed, MLDSA_SEED_BYTES_LEN);
    return ret;
}

static int32_t MLDSA_SignArgCheck(CRYPT_ML_DSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    if (ctx == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYINFO_NOT_SET);
        return CRYPT_MLDSA_KEYINFO_NOT_SET;
    }
    if (ctx->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEY_NOT_SET);
        return CRYPT_MLDSA_KEY_NOT_SET;
    }
    if (*signLen < ctx->info->signatureLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_LEN_NOT_ENOUGH);
        return CRYPT_MLDSA_LEN_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

static int32_t MLDSA_VerifyArgCheck(CRYPT_ML_DSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t signLen)
{
    if (ctx == NULL || data == NULL || dataLen == 0 || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYINFO_NOT_SET);
        return CRYPT_MLDSA_KEYINFO_NOT_SET;
    }

    if (ctx->pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEY_NOT_SET);
        return CRYPT_MLDSA_KEY_NOT_SET;
    }
    if (signLen != ctx->info->signatureLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_LEN_NOT_ENOUGH);
        return CRYPT_MLDSA_LEN_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ML_DSA_SetPrvKey(CRYPT_ML_DSA_Ctx *ctx, CRYPT_MlDsaPrv *prv)
{
    if (ctx == NULL || prv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYINFO_NOT_SET);
        return CRYPT_MLDSA_KEYINFO_NOT_SET;
    }
    if (ctx->prvKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_SET_KEY_FAILED);
        return CRYPT_MLDSA_SET_KEY_FAILED;
    }
    if (prv->len != ctx->info->privateKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYLEN_ERROR);
        return CRYPT_MLDSA_KEYLEN_ERROR;
    }
    ctx->prvKey = BSL_SAL_Malloc(ctx->info->privateKeyLen);
    if (ctx->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->prvLen = ctx->info->privateKeyLen;
    (void)memcpy_s(ctx->prvKey, ctx->prvLen, prv->data, prv->len);
    return CRYPT_SUCCESS;
}

#ifdef HITLS_BSL_PARAMS
static int32_t MLDSA_SetPrvSeed(CRYPT_ML_DSA_Ctx *ctx, uint8_t* buff, uint32_t len)
{
    if (ctx == NULL || buff == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYINFO_NOT_SET);
        return CRYPT_MLDSA_KEYINFO_NOT_SET;
    }
    if (ctx->prvKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_SET_KEY_FAILED);
        return CRYPT_MLDSA_SET_KEY_FAILED;
    }
    if (len != MLDSA_SEED_BYTES_LEN) {
            BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_SET_KEY_FAILED);
            return CRYPT_MLDSA_SET_KEY_FAILED;
    }
    if (MLDSACreateKeyBuf(ctx) != CRYPT_SUCCESS) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return MLDSA_KeyGenInternal(ctx, buff);
}

int32_t CRYPT_ML_DSA_SetPrvKeyEx(CRYPT_ML_DSA_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_MlDsaPrv prvKey = {0};
    CRYPT_MlDsaPrv prvKeySeed = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_ML_DSA_PRVKEY, &prvKey.data, &prvKey.len);
    (void)GetConstParamValue(para, CRYPT_PARAM_ML_DSA_PRVKEY_SEED, &prvKeySeed.data, &prvKeySeed.len);
    if (prvKeySeed.data!= NULL && prvKeySeed.len != 0) {
        int32_t ret = MLDSA_SetPrvSeed(ctx, prvKeySeed.data, prvKeySeed.len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        // Consistence Check
        if (prvKey.data != NULL && prvKey.len != 0) {
            return memcmp(ctx->prvKey, prvKey.data, ctx->prvLen) == 0 ? CRYPT_SUCCESS :
                                                                        CRYPT_MLDSA_PRVKEY_SEED_INCONSISTENT;
        }
        return CRYPT_SUCCESS;
    }
    return CRYPT_ML_DSA_SetPrvKey(ctx, &prvKey);
}

int32_t CRYPT_ML_DSA_SetPubKeyEx(CRYPT_ML_DSA_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_MlDsaPub pub = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_ML_DSA_PUBKEY, &pub.data, &pub.len);
    return CRYPT_ML_DSA_SetPubKey(ctx, &pub);
}

int32_t CRYPT_ML_DSA_GetPrvKeyEx(const CRYPT_ML_DSA_Ctx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_MlDsaPrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_ML_DSA_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = CRYPT_ML_DSA_GetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPrv->useLen = prv.len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ML_DSA_GetPubKeyEx(const CRYPT_ML_DSA_Ctx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_MlDsaPub pub = {0};
    BSL_Param *paramPub = GetParamValue(para, CRYPT_PARAM_ML_DSA_PUBKEY, &pub.data, &(pub.len));
    int32_t ret = CRYPT_ML_DSA_GetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPub->useLen = pub.len;
    return CRYPT_SUCCESS;
}
#endif

int32_t CRYPT_ML_DSA_SetPubKey(CRYPT_ML_DSA_Ctx *ctx, CRYPT_MlDsaPub *pub)
{
    if (ctx == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYINFO_NOT_SET);
        return CRYPT_MLDSA_KEYINFO_NOT_SET;
    }

    if (pub->len != ctx->info->publicKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYLEN_ERROR);
        return CRYPT_MLDSA_KEYLEN_ERROR;
    }
    if (ctx->pubKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_SET_KEY_FAILED);
        return CRYPT_MLDSA_SET_KEY_FAILED;
    }

    ctx->pubKey = BSL_SAL_Malloc(ctx->info->publicKeyLen);
    if (ctx->pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->pubLen = ctx->info->publicKeyLen;
    (void)memcpy_s(ctx->pubKey, ctx->pubLen, pub->data, pub->len);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ML_DSA_GetPrvKey(const CRYPT_ML_DSA_Ctx *ctx, CRYPT_MlDsaPrv *prv)
{
    if (ctx == NULL || prv == NULL || prv->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEY_NOT_SET);
        return CRYPT_MLDSA_KEY_NOT_SET;
    }

    if (memcpy_s(prv->data, prv->len, ctx->prvKey, ctx->prvLen) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_LEN_NOT_ENOUGH);
        return CRYPT_MLDSA_LEN_NOT_ENOUGH;
    }
    prv->len = ctx->prvLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ML_DSA_GetPubKey(const CRYPT_ML_DSA_Ctx *ctx, CRYPT_MlDsaPub *pub)
{
    if (ctx == NULL || pub == NULL || pub->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEY_NOT_SET);
        return CRYPT_MLDSA_KEY_NOT_SET;
    }
    if (memcpy_s(pub->data, pub->len, ctx->pubKey, ctx->pubLen) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_LEN_NOT_ENOUGH);
        return CRYPT_MLDSA_LEN_NOT_ENOUGH;
    }
    pub->len = ctx->pubLen;
    return CRYPT_SUCCESS;
}

static int32_t MLDSACmpKey(uint8_t *a, uint32_t aLen, uint8_t *b, uint32_t bLen)
{
    if (aLen != bLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEY_NOT_EQUAL);
        return CRYPT_MLDSA_KEY_NOT_EQUAL;
    }
    if (a != NULL && b != NULL) {
        if (memcmp(a, b, aLen) != 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEY_NOT_EQUAL);
            return CRYPT_MLDSA_KEY_NOT_EQUAL;
        }
    }
    if (a == NULL && b == NULL) {
        return CRYPT_SUCCESS;
    }
    if (a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEY_NOT_EQUAL);
        return CRYPT_MLDSA_KEY_NOT_EQUAL;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ML_DSA_Cmp(const CRYPT_ML_DSA_Ctx *a, const CRYPT_ML_DSA_Ctx *b)
{
    if (a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (a->info != b->info) {  // The value of info must be one of the g_mldsaInfo arrays.
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEY_NOT_EQUAL);
        return CRYPT_MLDSA_KEY_NOT_EQUAL;
    }
 
    if (MLDSACmpKey(a->prvKey, a->prvLen, b->prvKey, b->prvLen) != CRYPT_SUCCESS) {
        return CRYPT_MLDSA_KEY_NOT_EQUAL;
    }
    if (MLDSACmpKey(a->pubKey, a->pubLen, b->pubKey, b->pubLen) != CRYPT_SUCCESS) {
        return CRYPT_MLDSA_KEY_NOT_EQUAL;
    }
    return CRYPT_SUCCESS;
}

static uint32_t MLDSAGetMdSize(const EAL_MdMethod *hashMethod, int32_t hashId)
{
    if (hashId == CRYPT_MD_SHAKE128) {
        return 32;  // To use SHAKE128, generate a 32-byte digest.
    } else if (hashId == CRYPT_MD_SHAKE256) {
        return 64;  // To use SHAKE256, generate a 64-byte digest.
    }
    return hashMethod->mdSize;
}

static int32_t MLDSAPreHashEncode(CRYPT_ML_DSA_Ctx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
    CRYPT_Data *msg)
{
    int32_t ret = CRYPT_SUCCESS;
    // The maximum value of ctx->ctxLen is 255.
    if (dataLen > (UINT32_MAX - MLDSA_SIGN_PREFIX_BYTES - ctx->ctxLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    BslOidString *oidInfo = BSL_OBJ_GetOID(hashId);
    RETURN_RET_IF(oidInfo == NULL, CRYPT_ERR_ALGID);

    const EAL_MdMethod *hashMethod = EAL_MdFindDefaultMethod(hashId);
    RETURN_RET_IF(hashMethod == NULL, CRYPT_EAL_ALG_NOT_SUPPORT);
    uint32_t mdSize = MLDSAGetMdSize(hashMethod, hashId);
    msg->len = MLDSA_SIGN_PREFIX_BYTES + ctx->ctxLen + MLDSA_SIGN_PREFIX_BYTES + oidInfo->octetLen + mdSize;
    msg->data = BSL_SAL_Malloc(msg->len);
    RETURN_RET_IF(msg->data == NULL, CRYPT_MEM_ALLOC_FAIL);

    uint8_t *ptr = msg->data;
    uint32_t tmpLen = msg->len;
    ptr[0] = 1;
    ptr[1] = (uint8_t)ctx->ctxLen;
    ptr += MLDSA_SIGN_PREFIX_BYTES;
    tmpLen -= MLDSA_SIGN_PREFIX_BYTES;

    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        (void)memcpy_s(ptr, msg->len - MLDSA_SIGN_PREFIX_BYTES, ctx->ctxInfo, ctx->ctxLen);
        ptr += ctx->ctxLen;
        tmpLen -= ctx->ctxLen;
    }
    ptr[0] = 0x06;  // tag of objectId
    ptr[1] = (uint8_t)oidInfo->octetLen;
    ptr += MLDSA_SIGN_PREFIX_BYTES;
    tmpLen -= MLDSA_SIGN_PREFIX_BYTES;
    (void)memcpy_s(ptr, tmpLen, oidInfo->octs, oidInfo->octetLen);
    ptr += oidInfo->octetLen;
    tmpLen -= oidInfo->octetLen;
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL) {
        BSL_SAL_Free(msg->data);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, data, dataLen), ret);
    GOTO_ERR_IF(hashMethod->final(mdCtx, ptr, &tmpLen), ret);
ERR:
    hashMethod->freeCtx(mdCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(msg->data);
    }
    return ret;
}

static int32_t MLDSAEncodeInputData(CRYPT_ML_DSA_Ctx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
    CRYPT_Data *msg)
{
    int32_t ret;
    if (ctx->isMuMsg || ctx->needEncodeCtx == false) {
        msg->data = BSL_SAL_Dump(data, dataLen);
        RETURN_RET_IF(msg->data == NULL, CRYPT_MEM_ALLOC_FAIL);
        msg->len = dataLen;
        return CRYPT_SUCCESS;
    }

    // The maximum value of ctx->ctxLen is 255.
    if (dataLen > (UINT32_MAX - MLDSA_SIGN_PREFIX_BYTES - ctx->ctxLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->needPreHash) {
        RETURN_RET_IF_ERR(MLDSAPreHashEncode(ctx, hashId, data, dataLen, msg), ret);
        return CRYPT_SUCCESS;
    }

    msg->len = dataLen + ctx->ctxLen + MLDSA_SIGN_PREFIX_BYTES;
    msg->data = BSL_SAL_Malloc(msg->len);
    if (msg->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    msg->data[0] = 0;
    msg->data[1] = (uint8_t)ctx->ctxLen;
    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        (void)memcpy_s(msg->data + MLDSA_SIGN_PREFIX_BYTES, msg->len - MLDSA_SIGN_PREFIX_BYTES,
            ctx->ctxInfo, ctx->ctxLen);
    }
    (void)memcpy_s(msg->data + MLDSA_SIGN_PREFIX_BYTES + ctx->ctxLen,
        msg->len - MLDSA_SIGN_PREFIX_BYTES - ctx->ctxLen, data, dataLen);
    return CRYPT_SUCCESS;
}

// Algorithm 4 HashML-DSA.Sign(sk, M, ctx, PH)
int32_t CRYPT_ML_DSA_Sign(CRYPT_ML_DSA_Ctx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    int32_t ret = MLDSA_SignArgCheck(ctx, data, dataLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t signSeed[MLDSA_SEED_BYTES_LEN] = { 0 };
    if (ctx->deterministicSignFlag == false) {
        ret = CRYPT_RandEx(ctx->libCtx, signSeed, MLDSA_SEED_BYTES_LEN);
        RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    }
    CRYPT_Data msg = { 0 };
    RETURN_RET_IF_ERR(MLDSAEncodeInputData(ctx, hashId, data, dataLen, &msg), ret);
    ret = MLDSA_SignInternal(ctx, &msg, sign, signLen, signSeed);
    BSL_SAL_Free(msg.data);
    BSL_SAL_CleanseData(signSeed, sizeof(signSeed));
    return ret;
}

// Algorithm 5 HashML-DSA.Verify(pk, M, 𝜎, ctx, PH)
int32_t CRYPT_ML_DSA_Verify(CRYPT_ML_DSA_Ctx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t signLen)
{
    int32_t ret = MLDSA_VerifyArgCheck(ctx, data, dataLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_Data msg = { 0 };
    RETURN_RET_IF_ERR(MLDSAEncodeInputData(ctx, hashId, data, dataLen, &msg), ret);
    ret = MLDSA_VerifyInternal(ctx, &msg, sign, signLen);
    BSL_SAL_Free(msg.data);
    return ret;
}

#ifdef HITLS_CRYPTO_MLDSA_CHECK

static int32_t MLDSAKeyPairCheck(const CRYPT_ML_DSA_Ctx *pubKey, const CRYPT_ML_DSA_Ctx *prvKey)
{
    if (pubKey == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->info == NULL || prvKey->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYINFO_NOT_SET);
        return CRYPT_MLDSA_KEYINFO_NOT_SET;
    }
    if (pubKey->info->secBits != prvKey->info->secBits) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_PAIRWISE_CHECK_FAIL);
        return CRYPT_MLDSA_PAIRWISE_CHECK_FAIL;
    }
    if (pubKey->pubKey == NULL || pubKey->pubLen != pubKey->info->publicKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_INVALID_PUBKEY);
        return CRYPT_MLDSA_INVALID_PUBKEY;
    }
    if (prvKey->prvKey == NULL || prvKey->prvLen != prvKey->info->privateKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_INVALID_PRVKEY);
        return CRYPT_MLDSA_INVALID_PRVKEY;
    }
    uint8_t *pub = BSL_SAL_Malloc(pubKey->info->publicKeyLen);
    if (pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = MLDSA_CalPub(prvKey, pub, pubKey->info->publicKeyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(pub);
        return ret;
    }
    if (memcmp(pub, pubKey->pubKey, pubKey->info->publicKeyLen) != 0) {
        BSL_SAL_Free(pub);
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_PAIRWISE_CHECK_FAIL);
        return CRYPT_MLDSA_PAIRWISE_CHECK_FAIL;
    }
    BSL_SAL_Free(pub);
    return CRYPT_SUCCESS;
}

static int32_t MLDSAPrvKeyCheck(const CRYPT_ML_DSA_Ctx *prvKey)
{
    if (prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_KEYINFO_NOT_SET);
        return CRYPT_MLDSA_KEYINFO_NOT_SET;
    }
    if (prvKey->prvKey == NULL || prvKey->prvLen != prvKey->info->privateKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_INVALID_PRVKEY);
        return CRYPT_MLDSA_INVALID_PRVKEY;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ML_DSA_Check(uint32_t checkType, const CRYPT_ML_DSA_Ctx *pkey1, const CRYPT_ML_DSA_Ctx *pkey2)
{
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            return MLDSAKeyPairCheck(pkey1, pkey2);
        case CRYPT_PKEY_CHECK_PRVKEY:
            return MLDSAPrvKeyCheck(pkey1);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}

#endif // HITLS_CRYPTO_MLDSA_CHECK

#endif