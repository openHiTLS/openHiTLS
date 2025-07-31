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

#include "crypt_paillier.h"
#include "paillier_local.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_params_key.h"

CRYPT_PAILLIER_Ctx *CRYPT_PAILLIER_NewCtx(void)
{
    CRYPT_PAILLIER_Ctx *ctx = NULL;

    ctx = (CRYPT_PAILLIER_Ctx *)BSL_SAL_Malloc(sizeof(CRYPT_PAILLIER_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(ctx, sizeof(CRYPT_PAILLIER_Ctx), 0, sizeof(CRYPT_PAILLIER_Ctx));
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

CRYPT_PAILLIER_Ctx *CRYPT_PAILLIER_NewCtxEx(void *libCtx)
{
    CRYPT_PAILLIER_Ctx *ctx = CRYPT_PAILLIER_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

static CRYPT_PAILLIER_PubKey *PaillierPubKeyDupCtx(CRYPT_PAILLIER_PubKey *pubKey)
{
    CRYPT_PAILLIER_PubKey *newPubKey = (CRYPT_PAILLIER_PubKey *)BSL_SAL_Malloc(sizeof(CRYPT_PAILLIER_PubKey));
    if (newPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newPubKey, sizeof(CRYPT_PAILLIER_PubKey), 0, sizeof(CRYPT_PAILLIER_PubKey));
    
    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->n, pubKey->n, BN_Dup(pubKey->n), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->g, pubKey->g, BN_Dup(pubKey->g), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->n2, pubKey->n2, BN_Dup(pubKey->n2), CRYPT_MEM_ALLOC_FAIL);

    return newPubKey;

ERR:
    PAILLIER_FREE_PUB_KEY(newPubKey);
    return NULL;
}

static CRYPT_PAILLIER_PrvKey *PaillierPrvKeyDupCtx(CRYPT_PAILLIER_PrvKey *prvKey)
{
    CRYPT_PAILLIER_PrvKey *newPrvKey = (CRYPT_PAILLIER_PrvKey *)BSL_SAL_Malloc(sizeof(CRYPT_PAILLIER_PrvKey));
    if (newPrvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newPrvKey, sizeof(CRYPT_PAILLIER_PrvKey), 0, sizeof(CRYPT_PAILLIER_PrvKey));
    
    GOTO_ERR_IF_SRC_NOT_NULL(newPrvKey->n, prvKey->n, BN_Dup(prvKey->n), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPrvKey->lambda, prvKey->lambda, BN_Dup(prvKey->lambda), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPrvKey->mu, prvKey->mu, BN_Dup(prvKey->mu), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPrvKey->n2, prvKey->n2, BN_Dup(prvKey->n2), CRYPT_MEM_ALLOC_FAIL);

    return newPrvKey;
ERR:
    PAILLIER_FREE_PRV_KEY(newPrvKey);
    return NULL;
}

static CRYPT_PAILLIER_Para *PaillierParaDupCtx(CRYPT_PAILLIER_Para *para)
{
    CRYPT_PAILLIER_Para *newPara = (CRYPT_PAILLIER_Para *)BSL_SAL_Malloc(sizeof(CRYPT_PAILLIER_Para));
    if (newPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newPara, sizeof(CRYPT_PAILLIER_Para), 0, sizeof(CRYPT_PAILLIER_Para));
    
    newPara->bits = para->bits;
    GOTO_ERR_IF_SRC_NOT_NULL(newPara->p, para->p, BN_Dup(para->p), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPara->q, para->q, BN_Dup(para->q), CRYPT_MEM_ALLOC_FAIL);

    return newPara;

ERR:
    PAILLIER_FREE_PARA(newPara);
    return NULL;
}

CRYPT_PAILLIER_Ctx *CRYPT_PAILLIER_DupCtx(CRYPT_PAILLIER_Ctx *keyCtx)
{
    if (keyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_PAILLIER_Ctx *newKeyCtx = NULL;
    newKeyCtx = BSL_SAL_Malloc(sizeof(CRYPT_PAILLIER_Ctx));
    if (newKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newKeyCtx, sizeof(CRYPT_PAILLIER_Ctx), 0, sizeof(CRYPT_PAILLIER_Ctx));

    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->prvKey, keyCtx->prvKey, PaillierPrvKeyDupCtx(keyCtx->prvKey), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->pubKey, keyCtx->pubKey, PaillierPubKeyDupCtx(keyCtx->pubKey), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->para, keyCtx->para, PaillierParaDupCtx(keyCtx->para), CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_ReferencesInit(&(newKeyCtx->references));
    return newKeyCtx;

ERR:
    CRYPT_PAILLIER_FreeCtx(newKeyCtx);
    return NULL;
}

static int32_t PaillierNewParaBasicCheck(const CRYPT_PaillierPara *para)
{
    if (para == NULL || para->p == NULL || para->pLen == 0 || para->q == NULL ||
        para->qLen == 0 || para->bits <= 0 || para->bits > PAILLIER_MAX_MODULUS_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    /* the length of p and q should be equal to bits */
    if (para->pLen != BN_BITS_TO_BYTES(para->bits) || para->qLen != BN_BITS_TO_BYTES(para->bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_PAILLIER_ERR_KEY_BITS);
        return CRYPT_PAILLIER_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}

CRYPT_PAILLIER_Para *CRYPT_PAILLIER_NewPara(const CRYPT_PaillierPara *para)
{
    int32_t ret = PaillierNewParaBasicCheck(para);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    CRYPT_PAILLIER_Para *retPara = BSL_SAL_Malloc(sizeof(CRYPT_PAILLIER_Para));
    if (retPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    retPara->bits = para->bits;
    retPara->p = BN_Create(para->bits);
    retPara->q = BN_Create(para->bits);
    if (retPara->p == NULL || retPara->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    return retPara;
ERR:
    CRYPT_PAILLIER_FreePara(retPara);
    return NULL;
}

void CRYPT_PAILLIER_FreeCtx(CRYPT_PAILLIER_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int i = 0;
    BSL_SAL_AtomicDownReferences(&(ctx->references), &i);
    if (i > 0) {
        return;
    }

    BSL_SAL_ReferencesFree(&(ctx->references));
    PAILLIER_FREE_PRV_KEY(ctx->prvKey);
    PAILLIER_FREE_PUB_KEY(ctx->pubKey);
    PAILLIER_FREE_PARA(ctx->para);
    BSL_SAL_Free(ctx);
}

void CRYPT_PAILLIER_FreePara(CRYPT_PAILLIER_Para *para)
{
    if (para == NULL) {
        return;
    }
    BN_Destroy(para->p);
    BN_Destroy(para->q);
    BSL_SAL_Free(para);
}

void PAILLIER_FreePrvKey(CRYPT_PAILLIER_PrvKey *prvKey)
{
    if (prvKey == NULL) {
        return;
    }
    BN_Destroy(prvKey->n);
    BN_Destroy(prvKey->lambda);
    BN_Destroy(prvKey->mu);
    BN_Destroy(prvKey->n2);
    BSL_SAL_Free(prvKey);
}

void PAILLIER_FreePubKey(CRYPT_PAILLIER_PubKey *pubKey)
{
    if (pubKey == NULL) {
        return;
    }
    BN_Destroy(pubKey->n);
    BN_Destroy(pubKey->g);
    BN_Destroy(pubKey->n2);
    BSL_SAL_Free(pubKey);
}

static int32_t IsPAILLIERSetParaVaild(const CRYPT_PAILLIER_Ctx *ctx, const CRYPT_PAILLIER_Para *para)
{
    if (ctx == NULL || para == NULL || para->p == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->bits > PAILLIER_MAX_MODULUS_BITS || para->bits <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_PAILLIER_ERR_KEY_BITS);
        return CRYPT_PAILLIER_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}

CRYPT_PAILLIER_Para *CRYPT_Paillier_DupPara(const CRYPT_PAILLIER_Para *para)
{
    CRYPT_PAILLIER_Para *paraCopy = BSL_SAL_Malloc(sizeof(CRYPT_PAILLIER_Para));
    if (paraCopy == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    paraCopy->bits = para->bits;
    paraCopy->p = BN_Dup(para->p);
    paraCopy->q = BN_Dup(para->q);
    if (paraCopy->p == NULL || paraCopy->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        PAILLIER_FREE_PARA(paraCopy);
        return NULL;
    }

    return paraCopy;
}

int32_t CRYPT_PAILLIER_SetPara(CRYPT_PAILLIER_Ctx *ctx, const CRYPT_PaillierPara *para)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_PAILLIER_Para *paillierPara = CRYPT_PAILLIER_NewPara(para);
    if (paillierPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = IsPAILLIERSetParaVaild(ctx, paillierPara);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_PAILLIER_FreePara(paillierPara);
        return ret;
    }

    PAILLIER_FREE_PARA(ctx->para);
    PAILLIER_FREE_PUB_KEY(ctx->pubKey);
    PAILLIER_FREE_PRV_KEY(ctx->prvKey);
    ctx->para = paillierPara;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_BSL_PARAMS
int32_t CRYPT_PAILLIER_SetParaEx(CRYPT_PAILLIER_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_PaillierPara paillierPara = {0};
    uint32_t bitsLen = sizeof(uint32_t);
    int32_t ret = 0;
    (void)GetConstParamValue(para, CRYPT_PARAM_PAILLIER_P, &(paillierPara.p), &(paillierPara.pLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_PAILLIER_Q, &(paillierPara.q), &(paillierPara.qLen));
    const BSL_Param *temp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_PAILLIER_BITS);
    if (temp != NULL) {
        RETURN_RET_IF_ERR(BSL_PARAM_GetValue(temp, CRYPT_PARAM_PAILLIER_BITS,
            BSL_PARAM_TYPE_UINT32, &paillierPara.bits, &bitsLen), ret);
    }
    return CRYPT_PAILLIER_SetPara(ctx, &paillierPara);
}
#endif

uint32_t CRYPT_PAILLIER_GetBits(const CRYPT_PAILLIER_Ctx *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    if (ctx->para != NULL) {
        return ctx->para->bits;
    }
    if (ctx->prvKey != NULL) {
        return BN_Bits(ctx->prvKey->lambda);
    }
    if (ctx->pubKey != NULL) {
        return BN_Bits(ctx->pubKey->n);
    }
    return 0;
}

CRYPT_PAILLIER_PrvKey *Paillier_NewPrvKey(uint32_t bits)
{
    CRYPT_PAILLIER_PrvKey *prvKey = (CRYPT_PAILLIER_PrvKey *)BSL_SAL_Malloc(sizeof(CRYPT_PAILLIER_PrvKey));
    if (prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    prvKey->n = BN_Create(bits);
    prvKey->lambda = BN_Create(bits);
    prvKey->mu = BN_Create(bits);
    prvKey->n2 = BN_Create(bits);
    if (prvKey->n == NULL || prvKey->lambda == NULL || prvKey->mu == NULL || prvKey->n2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        PAILLIER_FREE_PRV_KEY(prvKey);
    }
    return prvKey;
}

CRYPT_PAILLIER_PubKey *Paillier_NewPubKey(uint32_t bits)
{
    CRYPT_PAILLIER_PubKey *pubKey = (CRYPT_PAILLIER_PubKey *)BSL_SAL_Malloc(sizeof(CRYPT_PAILLIER_PubKey));
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pubKey->n = BN_Create(bits);
    pubKey->g = BN_Create(bits);
    pubKey->n2 = BN_Create(bits);
    if (pubKey->n == NULL || pubKey->g == NULL || pubKey->n2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        PAILLIER_FREE_PUB_KEY(pubKey);
    }
    return pubKey;
}

static int32_t Paillier_GenPQ(CRYPT_PAILLIER_Para *para, BN_Optimizer *optimizer)
{
    uint32_t bits = para->bits;
    int32_t ret = BN_GenPrime(para->p, NULL, bits, true, optimizer, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_GenPrime(para->q, NULL, bits, true, optimizer, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t Paillier_CalcPubKey(CRYPT_PAILLIER_PubKey *pubKey, CRYPT_PAILLIER_Para *para, BN_Optimizer *optimizer)
{
    int32_t ret = BN_Mul(pubKey->n, para->p, para->q, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_AddLimb(pubKey->g, pubKey->n, 1);  // g = n + 1
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Sqr(pubKey->n2, pubKey->n, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t Paillier_CalcLambda(BN_BigNum *lambda, CRYPT_PAILLIER_Para *para, BN_Optimizer *optimizer)
{
    uint32_t bits = para->bits;
    BN_BigNum *pMinus1 = BN_Create(bits);
    BN_BigNum *qMinus1 = BN_Create(bits);
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    if (pMinus1 == NULL || qMinus1 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto EXIT;
    }
    ret = BN_SubLimb(pMinus1, para->p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_SubLimb(qMinus1, para->q, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Lcm(lambda, pMinus1, qMinus1, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BN_Destroy(pMinus1);
    BN_Destroy(qMinus1);
    return ret;
}

static int32_t Paillier_CalcMu(BN_BigNum *mu, const BN_BigNum *lambda, CRYPT_PAILLIER_PubKey *pubKey, uint32_t bits, BN_Optimizer *optimizer)
{
    BN_BigNum *x = BN_Create(bits);
    BN_BigNum *xMinus1 = BN_Create(bits);
    BN_BigNum *Lx = BN_Create(bits);

    int32_t ret;
    if (x == NULL || xMinus1 == NULL || Lx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

    ret = BN_ModExp(x, pubKey->g, lambda, pubKey->n2, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_SubLimb(xMinus1, x, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_Div(Lx, NULL, xMinus1, pubKey->n, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_ModInv(mu, Lx, pubKey->n, optimizer);
     if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BN_Destroy(x);
    BN_Destroy(xMinus1);
    BN_Destroy(Lx);

    return ret;
}

int32_t Paillier_CalcPrvKey(CRYPT_PAILLIER_Ctx *ctx, BN_Optimizer *optimizer)
{
    int32_t ret = Paillier_CalcLambda(ctx->prvKey->lambda, ctx->para, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = Paillier_CalcMu(ctx->prvKey->mu, ctx->prvKey->lambda, ctx->pubKey, ctx->para->bits, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_PAILLIER_Gen(CRYPT_PAILLIER_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    BN_Optimizer *optimizer = NULL;
    CRYPT_PAILLIER_Ctx *newCtx = CRYPT_PAILLIER_NewCtx();

    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    newCtx->para = CRYPT_Paillier_DupPara(ctx->para);
    if (newCtx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }

    newCtx->prvKey = Paillier_NewPrvKey(newCtx->para->bits);
    newCtx->pubKey = Paillier_NewPubKey(newCtx->para->bits);
    optimizer = BN_OptimizerCreate();
    if (optimizer == NULL || newCtx->prvKey == NULL || newCtx->pubKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    BN_OptimizerSetLibCtx(ctx->libCtx, optimizer);
    ret = Paillier_GenPQ(newCtx->para, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = Paillier_CalcPubKey(newCtx->pubKey, newCtx->para, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = Paillier_CalcPrvKey(newCtx, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    GOTO_ERR_IF(BN_Copy(newCtx->prvKey->n, newCtx->pubKey->n), ret);
    GOTO_ERR_IF(BN_Copy(newCtx->prvKey->n2, newCtx->pubKey->n2), ret);

    PAILLIER_FREE_PARA(ctx->para);
    PAILLIER_FREE_PRV_KEY(ctx->prvKey);
    PAILLIER_FREE_PUB_KEY(ctx->pubKey);
    BSL_SAL_ReferencesFree(&(newCtx->references));

    ctx->prvKey = newCtx->prvKey;
    ctx->pubKey = newCtx->pubKey;
    ctx->para = newCtx->para;
    BSL_SAL_FREE(newCtx);
    BN_OptimizerDestroy(optimizer);

    return ret;

ERR:
    CRYPT_PAILLIER_FreeCtx(newCtx);
    BN_OptimizerDestroy(optimizer);
    return ret;
}


#endif // HITLS_CRYPTO_PAILLIER