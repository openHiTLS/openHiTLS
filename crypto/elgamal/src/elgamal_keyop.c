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

typedef struct {
    BSL_Param *p; /**< ElGamal private key parameter marked as p */
    BSL_Param *g; /**< ElGamal private key parameter marked as g */
    BSL_Param *x; /**< ElGamal private key parameter marked as x */
} CRYPT_ElGamalPrvParam;

typedef struct {
    BSL_Param *p; /**< ElGamal public key parameter marked as p */
    BSL_Param *g; /**< ElGamal public key parameter marked as g */
    BSL_Param *y; /**< ElGamal public key parameter marked as y */
    BSL_Param *q; /**< ElGamal public key parameter marked as y */
} CRYPT_ElGamalPubParam;

#define PARAMISNULL(a) (a == NULL || a->value == NULL)

static int32_t SetPrvPara(const CRYPT_ELGAMAL_PrvKey *prvKey, const CRYPT_ElGamalPrvParam *prv)
{
    int32_t ret = BN_Bin2Bn(prvKey->p, prv->p->value, prv->p->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t bnBits = BN_Bits(prvKey->p);
    if (bnBits > ELGAMAL_MAX_MODULUS_BITS || bnBits <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_KEY_BITS);
        return CRYPT_ELGAMAL_ERR_KEY_BITS;
    }

    ret = BN_Bin2Bn(prvKey->g, prv->g->value, prv->g->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BN_Bin2Bn(prvKey->x, prv->x->value, prv->x->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ret;
}

static int32_t SetPrvBasicCheck(const CRYPT_ELGAMAL_Ctx *ctx, BSL_Param *para, CRYPT_ElGamalPrvParam *prv)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    prv->p = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_P);
    prv->g = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_G);
    prv->x = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_X);
    if (PARAMISNULL(prv->p) || PARAMISNULL(prv->g) || PARAMISNULL(prv->x) ||
        prv->p->valueLen == 0 || prv->g->valueLen == 0 || prv->x->valueLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_INPUT_VALUE);
        return CRYPT_ELGAMAL_ERR_INPUT_VALUE;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_ELGAMAL_SetPrvKey(CRYPT_ELGAMAL_Ctx *ctx, const BSL_Param *para)
{
    CRYPT_ElGamalPrvParam prv = {0};
    int32_t ret = SetPrvBasicCheck(ctx, (BSL_Param *)(uintptr_t)para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_ELGAMAL_Ctx *newCtx = CRYPT_ELGAMAL_NewCtx();
    if (newCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    newCtx->prvKey = ElGamal_NewPrvKey(prv.p->valueLen * 8); // Bit length is obtained by multiplying byte length by 8.
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

    ELGAMAL_FREE_PRV_KEY(ctx->prvKey);
    ctx->prvKey = newCtx->prvKey;

    BSL_SAL_ReferencesFree(&(newCtx->references));
    BSL_SAL_FREE(newCtx);

    return ret;
ERR:
    CRYPT_ELGAMAL_FreeCtx(newCtx);
    return ret;
}

static int32_t SetPubBasicCheck(const CRYPT_ELGAMAL_Ctx *ctx, BSL_Param *para, CRYPT_ElGamalPubParam *pub)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    pub->p = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_P);
    pub->g = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_G);
    pub->y = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_Y);
    pub->q = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_Q);
    if (PARAMISNULL(pub->p) || PARAMISNULL(pub->g) || PARAMISNULL(pub->y) || PARAMISNULL(pub->q)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ELGAMAL_SetPubKey(CRYPT_ELGAMAL_Ctx *ctx, const BSL_Param *para)
{
    CRYPT_ElGamalPubParam pub = {0};
    int32_t ret = SetPubBasicCheck(ctx, (BSL_Param *)(uintptr_t)para, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    CRYPT_ELGAMAL_PubKey *newPub = NULL;
    /* Bit length is obtained by multiplying byte length by 8. */
    newPub = ElGamal_NewPubKey(pub.p->valueLen * 8);
    if (newPub == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->p, pub.p->value, pub.p->valueLen), ret);
    uint32_t bnBits = BN_Bits(newPub->p);
    if (bnBits > ELGAMAL_MAX_MODULUS_BITS || bnBits <= 0) {
        ret = CRYPT_ELGAMAL_ERR_KEY_BITS;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->g, pub.g->value, pub.g->valueLen), ret);
    GOTO_ERR_IF(BN_Bin2Bn(newPub->y, pub.y->value, pub.y->valueLen), ret);
    GOTO_ERR_IF(BN_Bin2Bn(newPub->q, pub.q->value, pub.q->valueLen), ret);

    ELGAMAL_FREE_PUB_KEY(ctx->pubKey);
    ctx->pubKey = newPub;
    return ret;
ERR:
    ELGAMAL_FREE_PUB_KEY(newPub);
    return ret;
}

static int32_t GetPrvBasicCheck(const CRYPT_ELGAMAL_Ctx *ctx, BSL_Param *para, CRYPT_ElGamalPrvParam *prv)
{
    if (ctx == NULL || ctx->prvKey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    prv->p = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_P);
    prv->g = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_G);
    prv->x = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_X);

    if (PARAMISNULL(prv->x)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_INPUT_VALUE);
        return CRYPT_ELGAMAL_ERR_INPUT_VALUE;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ELGAMAL_GetPrvKey(const CRYPT_ELGAMAL_Ctx *ctx, BSL_Param *para)
{
    CRYPT_ElGamalPrvParam prv = {0};
    int32_t ret = GetPrvBasicCheck(ctx, para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (!PARAMISNULL(prv.p)) {
        prv.p->useLen = prv.p->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->p, prv.p->value, &(prv.p->useLen)), ret);
    }
    if (!PARAMISNULL(prv.g)) {
        prv.g->useLen = prv.g->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->g, prv.g->value, &(prv.g->useLen)), ret);
    }
    if (!PARAMISNULL(prv.x)) {
        prv.x->useLen = prv.x->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->x, prv.x->value, &(prv.x->useLen)), ret);
    }
    
    return CRYPT_SUCCESS;
ERR:
    if (!PARAMISNULL(prv.p) && prv.p->useLen != 0) {
        BSL_SAL_CleanseData(prv.p->value, prv.p->useLen);
        prv.p->useLen = 0;
    }
    if (!PARAMISNULL(prv.g) && prv.g->useLen != 0) {
        BSL_SAL_CleanseData(prv.g->value, prv.g->useLen);
        prv.g->useLen = 0;
    }
    if (!PARAMISNULL(prv.x) && prv.x->useLen != 0) {
        BSL_SAL_CleanseData(prv.x->value, prv.x->useLen);
        prv.x->useLen = 0;
    }
    
    return ret;
}

static int32_t GetPubBasicCheck(const CRYPT_ELGAMAL_Ctx *ctx, BSL_Param *para, CRYPT_ElGamalPubParam *pub)
{
    if (ctx == NULL || ctx->pubKey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    pub->p = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_P);
    pub->g = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_G);
    pub->y = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_Y);
    pub->q = BSL_PARAM_FindParam(para, CRYPT_PARAM_ELGAMAL_Q);
    if (PARAMISNULL(pub->p) || PARAMISNULL(pub->g) || PARAMISNULL(pub->y) || PARAMISNULL(pub->q)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ELGAMAL_GetPubKey(const CRYPT_ELGAMAL_Ctx *ctx, BSL_Param *para)
{
    CRYPT_ElGamalPubParam pub = {0};
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

    pub.p->useLen = pub.p->valueLen;
    ret = BN_Bn2Bin(ctx->pubKey->p, pub.p->value, &(pub.p->useLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    pub.q->useLen = pub.q->valueLen;
    ret = BN_Bn2Bin(ctx->pubKey->q, pub.q->value, &(pub.q->useLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (pub.y != NULL) {
        pub.y->useLen = pub.y->valueLen;
        ret = BN_Bn2Bin(ctx->pubKey->y, pub.y->value, &pub.y->useLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
    }

    return ret;
}

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