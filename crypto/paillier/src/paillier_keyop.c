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

static int32_t SetPrvPara(const CRYPT_PAILLIER_PrvKey *prvKey, const CRYPT_PaillierPrv *prv)
{
    int32_t ret = BN_Bin2Bn(prvKey->n, prv->n, prv->nLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t bnBits = BN_Bits(prvKey->n);
    if (bnBits > PAILLIER_MAX_MODULUS_BITS || bnBits <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_PAILLIER_ERR_KEY_BITS);
        return CRYPT_PAILLIER_ERR_KEY_BITS;
    }

    ret = BN_Bin2Bn(prvKey->lambda, prv->lambda, prv->lambdaLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Bin2Bn(prvKey->mu, prv->mu, prv->muLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Bin2Bn(prvKey->n2, prv->n2, prv->n2Len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CheckSquare(prvKey->n2, prvKey->n, prv->n2Len * 8);
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

static int32_t SetPrvBasicCheck(const CRYPT_PAILLIER_Ctx *ctx, const CRYPT_PaillierPrv *prv)
{
    if (ctx == NULL || prv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->n == NULL || prv->lambda == NULL || prv->mu == NULL || prv->n2 == NULL || prv->lambdaLen == 0 || prv->muLen == 0 || prv->nLen == 0 || prv->n2Len == 0) {    
        BSL_ERR_PUSH_ERROR(CRYPT_PAILLIER_ERR_INPUT_VALUE);
        return CRYPT_PAILLIER_ERR_INPUT_VALUE;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PAILLIER_SetPrvKey(CRYPT_PAILLIER_Ctx *ctx, const CRYPT_PaillierPrv *prv)
{
    int32_t ret = SetPrvBasicCheck(ctx, prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_PAILLIER_Ctx *newCtx = CRYPT_PAILLIER_NewCtx();
    if (newCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    newCtx->prvKey = Paillier_NewPrvKey(prv->lambdaLen * 8); // Bit length is obtained by multiplying byte length by 8.
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

    PAILLIER_FREE_PRV_KEY(ctx->prvKey);
    ctx->prvKey = newCtx->prvKey;

    BSL_SAL_ReferencesFree(&(newCtx->references));
    BSL_SAL_FREE(newCtx);
    return ret;
ERR:
    CRYPT_PAILLIER_FreeCtx(newCtx);
    return ret;
}

static int32_t SetPubBasicCheck(const CRYPT_PAILLIER_Ctx *ctx, const CRYPT_PaillierPub *pub)
{
    if (ctx == NULL || pub == NULL || pub->n == NULL || pub->g == NULL || pub->n2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PAILLIER_SetPubKey(CRYPT_PAILLIER_Ctx *ctx, const CRYPT_PaillierPub *pub)
{
    int32_t ret = SetPubBasicCheck(ctx, pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_PAILLIER_PubKey *newPub = NULL;

    /* Bit length is obtained by multiplying byte length by 8. */
    newPub = Paillier_NewPubKey(pub->nLen * 8);
    if (newPub == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->n, pub->n, pub->nLen), ret);
    uint32_t bnBits = BN_Bits(newPub->n);
    if (bnBits > PAILLIER_MAX_MODULUS_BITS || bnBits <= 0) {
        ret = CRYPT_PAILLIER_ERR_KEY_BITS;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->g, pub->g, pub->gLen), ret);
    GOTO_ERR_IF(BN_Bin2Bn(newPub->n2, pub->n2, pub->n2Len), ret);

    GOTO_ERR_IF(CheckSquare(newPub->n2, newPub->n, pub->nLen * 8), ret);

    PAILLIER_FREE_PUB_KEY(ctx->pubKey);
    ctx->pubKey = newPub;
    return ret;
ERR:
    PAILLIER_FREE_PUB_KEY(newPub);
    return ret;
}

int32_t CRYPT_PAILLIER_GetPrvKey(const CRYPT_PAILLIER_Ctx *ctx, CRYPT_PaillierPrv *prv)
{
    if (ctx == NULL || ctx->prvKey == NULL || prv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->lambda == NULL || prv->mu == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PAILLIER_ERR_INPUT_VALUE);
        return CRYPT_PAILLIER_ERR_INPUT_VALUE;
    }
    int32_t ret = BN_Bn2Bin(ctx->prvKey->lambda, prv->lambda, &prv->lambdaLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Bn2Bin(ctx->prvKey->mu, prv->mu, &prv->muLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    if (prv->n != NULL)
    {
        ret = BN_Bn2Bin(ctx->prvKey->n, prv->n, &prv->nLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
    }
    if (prv->n2 != NULL)
    {
        ret = BN_Bn2Bin(ctx->prvKey->n2, prv->n2, &prv->n2Len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
    }
    return ret;
}

int32_t CRYPT_PAILLIER_GetPubKey(const CRYPT_PAILLIER_Ctx *ctx, CRYPT_PaillierPub *pub)
{
    if (ctx == NULL || ctx->pubKey == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = BN_Bn2Bin(ctx->pubKey->g, pub->g, &pub->gLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Bn2Bin(ctx->pubKey->n, pub->n, &pub->nLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (pub->n2 != NULL) {
        ret = BN_Bn2Bin(ctx->pubKey->n2, pub->n2, &pub->n2Len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
    }
    return ret;
}

#ifdef HITLS_BSL_PARAMS
int32_t CRYPT_PAILLIER_SetPrvKeyEx(CRYPT_PAILLIER_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_PaillierPrv prv = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_PAILLIER_N, &prv.n, &prv.nLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_PAILLIER_LAMBDA, &prv.lambda, &prv.lambdaLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_PAILLIER_MU, &prv.mu, &prv.muLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_PAILLIER_N2, &prv.n2, &prv.n2Len);
    return CRYPT_PAILLIER_SetPrvKey(ctx, &prv);
}

int32_t CRYPT_PAILLIER_SetPubKeyEx(CRYPT_PAILLIER_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_PaillierPub pub = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_PAILLIER_N, &pub.n, &pub.nLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_PAILLIER_G, &pub.g, &pub.gLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_PAILLIER_N2, &pub.n2, &pub.n2Len);
    return CRYPT_PAILLIER_SetPubKey(ctx, &pub);
}

int32_t CRYPT_PAILLIER_GetPrvKeyEx(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_PaillierPrv prv = {0};
    BSL_Param *paramN = GetParamValue(para, CRYPT_PARAM_PAILLIER_N, &prv.n, &(prv.nLen));
    BSL_Param *paramLambda = GetParamValue(para, CRYPT_PARAM_PAILLIER_LAMBDA, &prv.lambda, &(prv.lambdaLen));
    BSL_Param *paramMu = GetParamValue(para, CRYPT_PARAM_PAILLIER_MU, &prv.mu, &(prv.muLen));
    BSL_Param *paramN2 = GetParamValue(para, CRYPT_PARAM_PAILLIER_N2, &prv.n2, &(prv.n2Len));
    int32_t ret = CRYPT_PAILLIER_GetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramN->useLen = prv.nLen;
    paramLambda->useLen = prv.lambdaLen;
    paramMu->useLen = prv.muLen;
    paramN2->useLen = prv.n2Len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PAILLIER_GetPubKeyEx(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_PaillierPub pub = {0};
    BSL_Param *paramN = GetParamValue(para, CRYPT_PARAM_PAILLIER_N, &pub.n, &(pub.nLen));
    BSL_Param *paramG = GetParamValue(para, CRYPT_PARAM_PAILLIER_G, &pub.g, &(pub.gLen));
    BSL_Param *paramN2 = GetParamValue(para, CRYPT_PARAM_PAILLIER_N2, &pub.n2, &(pub.n2Len));
    int32_t ret = CRYPT_PAILLIER_GetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramN->useLen = pub.nLen;
    paramG->useLen = pub.gLen;
    paramN2->useLen = pub.n2Len;
    return CRYPT_SUCCESS;
}
#endif

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