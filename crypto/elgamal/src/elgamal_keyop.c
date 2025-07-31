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
#ifdef HITLS_CRYPTO_ELGAMAL

#include "crypt_types.h"
#include "crypt_elgamal.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "elgamal_local.h"
#include "crypt_errno.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_params_key.h"

#define PARAMISNULL(a) (a == NULL || a->value == NULL)

static int32_t SetPrvPara(const CRYPT_ELGAMAL_PrvKey *prvKey, const CRYPT_ElGamalPrv *prv)
{
    int32_t ret = BN_Bin2Bn(prvKey->p, prv->p, prv->pLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t bnBits = BN_Bits(prvKey->p);
    if (bnBits > ELGAMAL_MAX_MODULUS_BITS || bnBits <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_KEY_BITS);
        return CRYPT_ELGAMAL_ERR_KEY_BITS;
    }

    ret = BN_Bin2Bn(prvKey->g, prv->g, prv->gLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BN_Bin2Bn(prvKey->x, prv->x, prv->xLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ret;
}

int32_t CRYPT_ELGAMAL_SetPrvKey(CRYPT_ELGAMAL_Ctx *ctx, const CRYPT_ElGamalPrv *prv)
{
    if (ctx == NULL || prv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (prv->p == NULL || prv->g == NULL || prv->x == NULL ||
        prv->pLen == 0 || prv->gLen == 0 || prv->xLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_INPUT_VALUE);
        return CRYPT_ELGAMAL_ERR_INPUT_VALUE;
    }
    int32_t ret = CRYPT_SUCCESS;
    CRYPT_ELGAMAL_Ctx *newCtx = CRYPT_ELGAMAL_NewCtx();
    if (newCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    newCtx->prvKey = ElGamal_NewPrvKey(prv->pLen * 8); // Bit length is obtained by multiplying byte length by 8.
    if (newCtx->prvKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = SetPrvPara(newCtx->prvKey, prv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ELGAMAL_FREE_PRV_KEY(ctx->prvKey);
    ctx->prvKey = newCtx->prvKey;

    BSL_SAL_ReferencesFree(&(newCtx->references));
    BSL_SAL_FREE(newCtx);

    return ret;
ERR:
    CRYPT_ELGAMAL_FreeCtx(newCtx);
    return ret;
}


int32_t CRYPT_ELGAMAL_SetPubKey(CRYPT_ELGAMAL_Ctx *ctx, const CRYPT_ElGamalPub *pub)
{
    if (ctx == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pub->p == NULL || pub->g == NULL || pub->y == NULL || pub->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_SUCCESS;
    CRYPT_ELGAMAL_PubKey *newPub = NULL;
    /* Bit length is obtained by multiplying byte length by 8. */
    newPub = ElGamal_NewPubKey(pub->pLen * 8);
    if (newPub == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->p, pub->p, pub->pLen), ret);
    uint32_t bnBits = BN_Bits(newPub->p);
    if (bnBits > ELGAMAL_MAX_MODULUS_BITS || bnBits <= 0) {
        ret = CRYPT_ELGAMAL_ERR_KEY_BITS;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->g, pub->g, pub->gLen), ret);
    GOTO_ERR_IF(BN_Bin2Bn(newPub->y, pub->y, pub->yLen), ret);
    GOTO_ERR_IF(BN_Bin2Bn(newPub->q, pub->q, pub->qLen), ret);

    ELGAMAL_FREE_PUB_KEY(ctx->pubKey);
    ctx->pubKey = newPub;
    return ret;
ERR:
    ELGAMAL_FREE_PUB_KEY(newPub);
    return ret;
}


int32_t CRYPT_ELGAMAL_GetPrvKey(const CRYPT_ELGAMAL_Ctx *ctx, CRYPT_ElGamalPrv *prv)
{
    if (ctx == NULL || ctx->prvKey == NULL || prv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->x == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_INPUT_VALUE);
        return CRYPT_ELGAMAL_ERR_INPUT_VALUE;
    }

    int32_t ret = CRYPT_SUCCESS;
    if (prv->p != NULL) {
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->p, prv->p, &(prv->pLen)), ret);
    }
    if (prv->g != NULL) {
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->g, prv->g, &(prv->gLen)), ret);
    }
    GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->x, prv->x, &(prv->xLen)), ret);

    return CRYPT_SUCCESS;
ERR:
    BSL_SAL_CleanseData(prv->p, prv->pLen);
    BSL_SAL_CleanseData(prv->g, prv->gLen);
    BSL_SAL_CleanseData(prv->x, prv->xLen);
    prv->pLen = 0;
    prv->gLen = 0;
    prv->xLen = 0;
    return ret;
}

int32_t CRYPT_ELGAMAL_GetPubKey(const CRYPT_ELGAMAL_Ctx *ctx, CRYPT_ElGamalPub *pub)
{
    if (ctx == NULL || ctx->pubKey == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->p == NULL || pub->g == NULL || pub->y == NULL || pub->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret;
    GOTO_ERR_IF(BN_Bn2Bin(ctx->pubKey->g, pub->g, &(pub->gLen)), ret);
    GOTO_ERR_IF(BN_Bn2Bin(ctx->pubKey->p, pub->p, &(pub->pLen)), ret);
    GOTO_ERR_IF(BN_Bn2Bin(ctx->pubKey->q, pub->q, &(pub->qLen)), ret);
    GOTO_ERR_IF(BN_Bn2Bin(ctx->pubKey->y, pub->y, &(pub->yLen)), ret);

    return CRYPT_SUCCESS;
ERR:
    BSL_SAL_CleanseData(pub->g, pub->gLen);
    BSL_SAL_CleanseData(pub->p, pub->pLen);
    BSL_SAL_CleanseData(pub->q, pub->qLen);
    BSL_SAL_CleanseData(pub->y, pub->yLen);
    pub->gLen = 0;
    pub->pLen = 0;
    pub->qLen = 0;
    pub->yLen = 0;
    return ret;
}

#ifdef HITLS_BSL_PARAMS
int32_t CRYPT_ELGAMAL_SetPrvKeyEx(CRYPT_ELGAMAL_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_ElGamalPrv elGamalPara = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_ELGAMAL_P, &(elGamalPara.p), &(elGamalPara.pLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_ELGAMAL_G, &(elGamalPara.g), &(elGamalPara.gLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_ELGAMAL_X, &(elGamalPara.x), &(elGamalPara.xLen));
    return CRYPT_ELGAMAL_SetPrvKey(ctx, &elGamalPara);
}

int32_t CRYPT_ELGAMAL_SetPubKeyEx(CRYPT_ELGAMAL_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_ElGamalPub elGamalPara = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_ELGAMAL_P, &(elGamalPara.p), &(elGamalPara.pLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_ELGAMAL_G, &(elGamalPara.g), &(elGamalPara.gLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_ELGAMAL_Y, &(elGamalPara.y), &(elGamalPara.yLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_ELGAMAL_Q, &(elGamalPara.q), &(elGamalPara.qLen));
    return CRYPT_ELGAMAL_SetPubKey(ctx, &elGamalPara);
}

int32_t CRYPT_ELGAMAL_GetPrvKeyEx(const CRYPT_ELGAMAL_Ctx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_ElGamalPrv prv = {0};
    BSL_Param *paramP = GetParamValue(para, CRYPT_PARAM_ELGAMAL_P, &prv.p, &prv.pLen);
    BSL_Param *paramG = GetParamValue(para, CRYPT_PARAM_ELGAMAL_G, &prv.g, &prv.gLen);
    BSL_Param *paramX = GetParamValue(para, CRYPT_PARAM_ELGAMAL_X, &prv.x, &prv.xLen);
    int32_t ret = CRYPT_ELGAMAL_GetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (paramP != NULL) {
        paramP->useLen = prv.pLen;
    }
    if (paramG != NULL) {
        paramG->useLen = prv.gLen;
    }
    paramX->useLen = prv.xLen;
    return CRYPT_SUCCESS;
}


int32_t CRYPT_ELGAMAL_GetPubKeyEx(const CRYPT_ELGAMAL_Ctx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_ElGamalPub pub = {0};
    BSL_Param *paramP = GetParamValue(para, CRYPT_PARAM_ELGAMAL_P, &pub.p, &pub.pLen);
    BSL_Param *paramG = GetParamValue(para, CRYPT_PARAM_ELGAMAL_G, &pub.g, &pub.gLen);
    BSL_Param *paramY = GetParamValue(para, CRYPT_PARAM_ELGAMAL_Y, &pub.y, &pub.yLen);
    BSL_Param *paramQ = GetParamValue(para, CRYPT_PARAM_ELGAMAL_Q, &pub.q, &pub.qLen);
    int32_t ret = CRYPT_ELGAMAL_GetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramP->useLen = pub.pLen;
    paramG->useLen = pub.gLen;
    paramY->useLen = pub.yLen;
    paramQ->useLen = pub.qLen;
    return ret;
}
#endif

int32_t CRYPT_ELGAMAL_GetSecBits(const CRYPT_ELGAMAL_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    int32_t bits = (int32_t)CRYPT_ELGAMAL_GetBits(ctx);
    return BN_SecBits(bits, -1);
}

#endif /* HITLS_CRYPTO_ELGAMAL */