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
#ifdef HITLS_CRYPTO_PAILLIER

#include "crypt_types.h"
#include "crypt_paillier.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "paillier_local.h"
#include "crypt_errno.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_params_key.h"

typedef struct {
    BSL_Param *n;      /**< Paillier private key parameter marked as n */
    BSL_Param *lambda; /**< Paillier private key parameter marked as lambda */
    BSL_Param *mu;     /**< Paillier private key parameter marked as mu */
    BSL_Param *n2;     /**< Paillier private key parameter marked as n2 */
} CRYPT_PaillierPrvParam;

typedef struct {
    BSL_Param *n;  /**< Paillier public key parameter marked as n */
    BSL_Param *g;  /**< Paillier public key parameter marked as g */
    BSL_Param *n2; /**< Paillier public key parameter marked as n2 */
} CRYPT_PaillierPubParam;

#define PARAMISNULL(a) (a == NULL || a->value == NULL)

static int32_t CheckSquare(const BN_BigNum *n2, const BN_BigNum *n, uint32_t bits)
{
    BN_BigNum *tmp = BN_Create(bits);
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    int32_t ret;
    if (optimizer == NULL || tmp == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_Sqr(tmp, n, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    if (BN_Cmp(tmp, n2) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_PAILLIER_ERR_INPUT_VALUE);
        ret = CRYPT_PAILLIER_ERR_INPUT_VALUE;
    }

EXIT:
    BN_Destroy(tmp);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

static int32_t SetPrvPara(const CRYPT_PAILLIER_PrvKey *prvKey, const CRYPT_PaillierPrvParam *prv)
{
    int32_t ret = BN_Bin2Bn(prvKey->n, prv->n->value, prv->n->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t bnBits = BN_Bits(prvKey->n);
    if (bnBits > PAILLIER_MAX_MODULUS_BITS || bnBits <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_PAILLIER_ERR_KEY_BITS);
        return CRYPT_PAILLIER_ERR_KEY_BITS;
    }

    ret = BN_Bin2Bn(prvKey->lambda, prv->lambda->value, prv->lambda->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Bin2Bn(prvKey->mu, prv->mu->value, prv->mu->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Bin2Bn(prvKey->n2, prv->n2->value, prv->n2->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CheckSquare(prvKey->n2, prvKey->n, prv->n2->valueLen * 8);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (BN_IsZero(prvKey->mu) || BN_IsOne(prvKey->mu)) {
        BSL_ERR_PUSH_ERROR(CRYPT_PAILLIER_ERR_INPUT_VALUE);
        return CRYPT_PAILLIER_ERR_INPUT_VALUE;
    }
    return ret;
}

static int32_t SetPrvBasicCheck(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *para, CRYPT_PaillierPrvParam *prv)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    prv->n = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_N);
    prv->lambda = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_LAMBDA);
    prv->mu = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_MU);
    prv->n2 = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_N2);
    if (PARAMISNULL(prv->n) || PARAMISNULL(prv->lambda) || PARAMISNULL(prv->mu) || PARAMISNULL(prv->n2) ||
        prv->lambda->valueLen == 0 || prv->mu->valueLen == 0 || prv->n->valueLen == 0 || prv->n2->valueLen == 0) {    
        BSL_ERR_PUSH_ERROR(CRYPT_PAILLIER_ERR_INPUT_VALUE);
        return CRYPT_PAILLIER_ERR_INPUT_VALUE;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PAILLIER_SetPrvKey(CRYPT_PAILLIER_Ctx *ctx, const BSL_Param *para)
{
    CRYPT_PaillierPrvParam prv = {0};
    int32_t ret = SetPrvBasicCheck(ctx, (BSL_Param *)(uintptr_t)para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_PAILLIER_Ctx *newCtx = CRYPT_PAILLIER_NewCtx();
    if (newCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // Bit length is obtained by multiplying byte length by 8.
    newCtx->prvKey = Paillier_NewPrvKey(prv.lambda->valueLen * 8);
    if (newCtx->prvKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = SetPrvPara(newCtx->prvKey, &prv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    PAILLIER_FREE_PRV_KEY(ctx->prvKey);
    ctx->prvKey = newCtx->prvKey;

    BSL_SAL_ReferencesFree(&(newCtx->references));
    BSL_SAL_FREE(newCtx);
    return ret;
ERR:
    CRYPT_PAILLIER_FreeCtx(newCtx);
    return ret;
}

static int32_t SetPubBasicCheck(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *para, CRYPT_PaillierPubParam *pub)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    pub->n = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_N);
    pub->g = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_G);
    pub->n2 = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_N2);
    if (PARAMISNULL(pub->n) || PARAMISNULL(pub->g) || PARAMISNULL(pub->n2)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PAILLIER_SetPubKey(CRYPT_PAILLIER_Ctx *ctx, const BSL_Param *para)
{
    CRYPT_PaillierPubParam pub = {0};
    int32_t ret = SetPubBasicCheck(ctx, (BSL_Param *)(uintptr_t)para, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_PAILLIER_PubKey *newPub = NULL;

    /* Bit length is obtained by multiplying byte length by 8. */
    newPub = Paillier_NewPubKey(pub.n->valueLen * 8);
    if (newPub == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->n, pub.n->value, pub.n->valueLen), ret);
    uint32_t bnBits = BN_Bits(newPub->n);
    if (bnBits > PAILLIER_MAX_MODULUS_BITS || bnBits <= 0) {
        ret = CRYPT_PAILLIER_ERR_KEY_BITS;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->g, pub.g->value, pub.g->valueLen), ret);
    GOTO_ERR_IF(BN_Bin2Bn(newPub->n2, pub.n2->value, pub.n2->valueLen), ret);

    GOTO_ERR_IF(CheckSquare(newPub->n2, newPub->n, pub.n->valueLen * 8), ret);

    PAILLIER_FREE_PUB_KEY(ctx->pubKey);
    ctx->pubKey = newPub;
    return ret;
ERR:
    PAILLIER_FREE_PUB_KEY(newPub);
    return ret;
}

static int32_t GetPrvBasicCheck(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *para, CRYPT_PaillierPrvParam *prv)
{
    if (ctx == NULL || ctx->prvKey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    prv->n = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_N);
    prv->lambda = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_LAMBDA);
    prv->mu = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_MU);
    prv->n2 = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_N2);
    if (PARAMISNULL(prv->lambda) || PARAMISNULL(prv->mu)) {
        BSL_ERR_PUSH_ERROR(CRYPT_PAILLIER_ERR_INPUT_VALUE);
        return CRYPT_PAILLIER_ERR_INPUT_VALUE;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PAILLIER_GetPrvKey(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *para)
{
    CRYPT_PaillierPrvParam prv = {0};
    int32_t ret = GetPrvBasicCheck(ctx, para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    prv.lambda->useLen = prv.lambda->valueLen;
    GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->lambda, prv.lambda->value, &(prv.lambda->useLen)), ret);
    prv.mu->useLen = prv.mu->valueLen;
    GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->mu, prv.mu->value, &(prv.mu->useLen)), ret);
    if (!PARAMISNULL(prv.n)) {
        prv.n->useLen = prv.n->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->n, prv.n->value, &(prv.n->useLen)), ret);
    }
    if (!PARAMISNULL(prv.n2)) {
        prv.n2->useLen = prv.n2->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->n2, prv.n2->value, &(prv.n2->useLen)), ret);
    }
    return CRYPT_SUCCESS;
ERR:
    if (!PARAMISNULL(prv.lambda) && prv.lambda->useLen != 0) {
        BSL_SAL_CleanseData(prv.lambda->value, prv.lambda->useLen);
        prv.lambda->useLen = 0;
    }
    if (!PARAMISNULL(prv.mu) && prv.mu->useLen != 0) {
        BSL_SAL_CleanseData(prv.mu->value, prv.mu->useLen);
        prv.mu->useLen = 0;
    }
    if (!PARAMISNULL(prv.n) && prv.n->useLen != 0) {
        BSL_SAL_CleanseData(prv.n->value, prv.n->useLen);
        prv.n->useLen = 0;
    }
    if (!PARAMISNULL(prv.n2) && prv.n2->useLen != 0) {
        BSL_SAL_CleanseData(prv.n2->value, prv.n2->useLen);
        prv.n2->useLen = 0;
    }
    return ret;
}

static int32_t GetPubBasicCheck(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *para, CRYPT_PaillierPubParam *pub)
{
    if (ctx == NULL || ctx->pubKey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    pub->n = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_N);
    pub->g = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_G);
    pub->n2 = BSL_PARAM_FindParam(para, CRYPT_PARAM_PAILLIER_N2);
    if (PARAMISNULL(pub->n) || PARAMISNULL(pub->g) || PARAMISNULL(pub->n2)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PAILLIER_GetPubKey(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *para)
{
    CRYPT_PaillierPubParam pub = {0};
    int32_t ret = GetPubBasicCheck(ctx, para, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    pub.g->useLen = pub.g->valueLen;
    ret = BN_Bn2Bin(ctx->pubKey->g, pub.g->value, &(pub.g->useLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pub.n->useLen = pub.n->valueLen;
    ret = BN_Bn2Bin(ctx->pubKey->n, pub.n->value, &(pub.n->useLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (pub.n2 != NULL) {
        pub.n2->useLen = pub.n2->valueLen;
        ret = BN_Bn2Bin(ctx->pubKey->n2, pub.n2->value, &pub.n2->useLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
    }
    return ret;
}

int32_t CRYPT_PAILLIER_GetSecBits(const CRYPT_PAILLIER_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    int32_t bits = (int32_t)CRYPT_PAILLIER_GetBits(ctx);
    return BN_SecBits(bits, -1);
}

#endif /* HITLS_CRYPTO_PAILLIER */