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

#include "crypt_elgamal.h"
#include "elgamal_local.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_params_key.h"

CRYPT_ELGAMAL_Ctx *CRYPT_ELGAMAL_NewCtx(void)
{
    CRYPT_ELGAMAL_Ctx *ctx = NULL;
    ctx = (CRYPT_ELGAMAL_Ctx *)BSL_SAL_Malloc(sizeof(CRYPT_ELGAMAL_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(ctx, sizeof(CRYPT_ELGAMAL_Ctx), 0, sizeof(CRYPT_ELGAMAL_Ctx));
    BSL_SAL_ReferencesInit(&(ctx->references));

    return ctx;
}

CRYPT_ELGAMAL_Ctx *CRYPT_ELGAMAL_NewCtxEx(void *libCtx)
{
    CRYPT_ELGAMAL_Ctx *ctx = CRYPT_ELGAMAL_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

static CRYPT_ELGAMAL_PubKey *ElGamalPubKeyDupCtx(CRYPT_ELGAMAL_PubKey *pubKey)
{
    CRYPT_ELGAMAL_PubKey *newPubKey = (CRYPT_ELGAMAL_PubKey *)BSL_SAL_Malloc(sizeof(CRYPT_ELGAMAL_PubKey));
    if (newPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newPubKey, sizeof(CRYPT_ELGAMAL_PubKey), 0, sizeof(CRYPT_ELGAMAL_PubKey));

    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->p, pubKey->p, BN_Dup(pubKey->p), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->g, pubKey->g, BN_Dup(pubKey->g), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->y, pubKey->y, BN_Dup(pubKey->y), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->q, pubKey->q, BN_Dup(pubKey->q), CRYPT_MEM_ALLOC_FAIL);

    return newPubKey;
ERR:
    ELGAMAL_FREE_PUB_KEY(newPubKey);
    return NULL;
}

static CRYPT_ELGAMAL_PrvKey *ElGamalPrvKeyDupCtx(CRYPT_ELGAMAL_PrvKey *prvKey)
{
    CRYPT_ELGAMAL_PrvKey *newPrvKey = (CRYPT_ELGAMAL_PrvKey *)BSL_SAL_Malloc(sizeof(CRYPT_ELGAMAL_PrvKey));
    if (newPrvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newPrvKey, sizeof(CRYPT_ELGAMAL_PrvKey), 0, sizeof(CRYPT_ELGAMAL_PrvKey));

    GOTO_ERR_IF_SRC_NOT_NULL(newPrvKey->p, prvKey->p, BN_Dup(prvKey->p), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPrvKey->g, prvKey->g, BN_Dup(prvKey->g), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPrvKey->x, prvKey->x, BN_Dup(prvKey->x), CRYPT_MEM_ALLOC_FAIL);

    return newPrvKey;
ERR:
    ELGAMAL_FREE_PRV_KEY(newPrvKey);
    return NULL;
}

static CRYPT_ELGAMAL_Para *ElGamalParaDupCtx(CRYPT_ELGAMAL_Para *para)
{
    CRYPT_ELGAMAL_Para *newPara = (CRYPT_ELGAMAL_Para *)BSL_SAL_Malloc(sizeof(CRYPT_ELGAMAL_Para));
    if (newPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newPara, sizeof(CRYPT_ELGAMAL_Para), 0, sizeof(CRYPT_ELGAMAL_Para));

    newPara->bits = para->bits;
    GOTO_ERR_IF_SRC_NOT_NULL(newPara->q, para->q, BN_Dup(para->q), CRYPT_MEM_ALLOC_FAIL);

    return newPara;
ERR:
    ELGAMAL_FREE_PARA(newPara);
    return NULL;
}

CRYPT_ELGAMAL_Ctx *CRYPT_ELGAMAL_DupCtx(CRYPT_ELGAMAL_Ctx *keyCtx)
{
    if (keyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_ELGAMAL_Ctx *newKeyCtx = BSL_SAL_Malloc(sizeof(CRYPT_ELGAMAL_Ctx));;
    if (newKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newKeyCtx, sizeof(CRYPT_ELGAMAL_Ctx), 0, sizeof(CRYPT_ELGAMAL_Ctx));

    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->prvKey, keyCtx->prvKey, ElGamalPrvKeyDupCtx(keyCtx->prvKey),
                             CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->pubKey, keyCtx->pubKey, ElGamalPubKeyDupCtx(keyCtx->pubKey),
                             CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->para, keyCtx->para, ElGamalParaDupCtx(keyCtx->para), CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_ReferencesInit(&(newKeyCtx->references));

    return newKeyCtx;
ERR:
    CRYPT_ELGAMAL_FreeCtx(newKeyCtx);
    return NULL;
}

static int32_t NewParaCheck(const CRYPT_ElGamalPara *para)
{
    if (para == NULL || para->q == NULL || para->qLen == 0 ||
        para->bits == 0 || para->k_bits == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->bits > ELGAMAL_MAX_MODULUS_BITS || para->k_bits > ELGAMAL_MAX_MODULUS_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (para->qLen != BN_BITS_TO_BYTES(para->k_bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_KEY_KBITS);
        return CRYPT_ELGAMAL_ERR_KEY_KBITS;
    }

    return CRYPT_SUCCESS;
}

CRYPT_ELGAMAL_Para *CRYPT_ELGAMAL_NewPara(const CRYPT_ElGamalPara *para)
{
    if (NewParaCheck(para) != CRYPT_SUCCESS) {
        return NULL;
    }

    CRYPT_ELGAMAL_Para *retPara = BSL_SAL_Malloc(sizeof(CRYPT_ELGAMAL_Para));
    if (retPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    retPara->bits = para->bits;
    retPara->k_bits = para->k_bits;
    retPara->q = BN_Create(para->k_bits);
    if (retPara->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    return retPara;
ERR:
    CRYPT_ELGAMAL_FreePara(retPara);
    return NULL;
}

void CRYPT_ELGAMAL_FreeCtx(CRYPT_ELGAMAL_Ctx *ctx)
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
    ELGAMAL_FREE_PRV_KEY(ctx->prvKey);
    ELGAMAL_FREE_PUB_KEY(ctx->pubKey);
    ELGAMAL_FREE_PARA(ctx->para);
    BSL_SAL_Free(ctx);
}

void CRYPT_ELGAMAL_FreePara(CRYPT_ELGAMAL_Para *para)
{
    if (para == NULL) {
        return;
    }
    BN_Destroy(para->q);
    BSL_SAL_Free(para);
}

void ELGAMAL_FreePrvKey(CRYPT_ELGAMAL_PrvKey *prvKey)
{
    if (prvKey == NULL) {
        return;
    }
    BN_Destroy(prvKey->p);
    BN_Destroy(prvKey->g);
    BN_Destroy(prvKey->x);
    BSL_SAL_Free(prvKey);
}

void ELGAMAL_FreePubKey(CRYPT_ELGAMAL_PubKey *pubKey)
{
    if (pubKey == NULL) {
        return;
    }
    BN_Destroy(pubKey->p);
    BN_Destroy(pubKey->q);
    BN_Destroy(pubKey->g);
    BN_Destroy(pubKey->y);
    BSL_SAL_Free(pubKey);
}

static int32_t IsELGAMALSetParaVaild(const CRYPT_ELGAMAL_Ctx *ctx, const CRYPT_ELGAMAL_Para *para)
{
    if (ctx == NULL || para == NULL || para->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->bits > ELGAMAL_MAX_MODULUS_BITS || para->bits <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_KEY_BITS);
        return CRYPT_ELGAMAL_ERR_KEY_BITS;
    }
    if (para->k_bits > ELGAMAL_MAX_MODULUS_BITS || para->k_bits <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_KEY_KBITS);
        return CRYPT_ELGAMAL_ERR_KEY_KBITS;
    }
    if (para->bits <= para->k_bits) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_KEY_BITS_KBITS);
        return CRYPT_ELGAMAL_ERR_KEY_BITS_KBITS;
    }
    return CRYPT_SUCCESS;
}

CRYPT_ELGAMAL_Para *CRYPT_ElGamal_DupPara(const CRYPT_ELGAMAL_Para *para)
{
    CRYPT_ELGAMAL_Para *paraCopy = BSL_SAL_Malloc(sizeof(CRYPT_ELGAMAL_Para));
    if (paraCopy == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    paraCopy->bits = para->bits;
    paraCopy->k_bits = para->k_bits;
    paraCopy->q = BN_Dup(para->q);
    if (paraCopy->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ELGAMAL_FREE_PARA(paraCopy);
        return NULL;
    }

    return paraCopy;
}

int32_t CRYPT_ELGAMAL_SetPara(CRYPT_ELGAMAL_Ctx *ctx, const CRYPT_ElGamalPara *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_ELGAMAL_Para *elGamalPara = CRYPT_ELGAMAL_NewPara(para);
    if (elGamalPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = IsELGAMALSetParaVaild(ctx, elGamalPara);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ELGAMAL_FreePara(elGamalPara);
        return ret;
    }

    ELGAMAL_FREE_PARA(ctx->para);
    ELGAMAL_FREE_PUB_KEY(ctx->pubKey);
    ELGAMAL_FREE_PRV_KEY(ctx->prvKey);
    ctx->para = elGamalPara;

    return CRYPT_SUCCESS;
}

#ifdef HITLS_BSL_PARAMS
int32_t CRYPT_ELGAMAL_SetParaEx(CRYPT_ELGAMAL_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_ElGamalPara elGamalPara = {0};
    uint32_t len = sizeof(uint32_t);
    int32_t ret = 0;
    (void)GetConstParamValue(para, CRYPT_PARAM_ELGAMAL_Q, &(elGamalPara.q), &(elGamalPara.qLen));
    const BSL_Param *temp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_ELGAMAL_BITS);
    if (temp != NULL) {
        RETURN_RET_IF_ERR(BSL_PARAM_GetValue(temp, CRYPT_PARAM_ELGAMAL_BITS,
            BSL_PARAM_TYPE_UINT32, &elGamalPara.bits, &len), ret);
    }
    temp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_ELGAMAL_KBITS);
    if (temp != NULL) {
        RETURN_RET_IF_ERR(BSL_PARAM_GetValue(temp, CRYPT_PARAM_ELGAMAL_KBITS,
            BSL_PARAM_TYPE_UINT32, &elGamalPara.k_bits, &len), ret);
    }
    return CRYPT_ELGAMAL_SetPara(ctx, &elGamalPara);
}
#endif

uint32_t CRYPT_ELGAMAL_GetBits(const CRYPT_ELGAMAL_Ctx *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    if (ctx->para != NULL) {
        return ctx->para->bits;
    }
    if (ctx->prvKey != NULL) {
        return BN_Bits(ctx->prvKey->p);
    }
    if (ctx->pubKey != NULL) {
        return BN_Bits(ctx->pubKey->p);
    }
    return 0;
}

uint32_t CRYPT_ELGAMAL_GetKBits(const CRYPT_ELGAMAL_Ctx *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    if (ctx->para != NULL) {
        return ctx->para->k_bits;
    }

    return 0;
}

CRYPT_ELGAMAL_PrvKey *ElGamal_NewPrvKey(uint32_t bits)
{
    CRYPT_ELGAMAL_PrvKey *prvKey = (CRYPT_ELGAMAL_PrvKey *)BSL_SAL_Malloc(sizeof(CRYPT_ELGAMAL_PrvKey));
    if (prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    prvKey->p = BN_Create(bits);
    prvKey->g = BN_Create(bits);
    prvKey->x = BN_Create(bits);

    if (prvKey->p == NULL || prvKey->g == NULL || prvKey->x == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ELGAMAL_FREE_PRV_KEY(prvKey);
    }

    return prvKey;
}

CRYPT_ELGAMAL_PubKey *ElGamal_NewPubKey(uint32_t bits)
{
    CRYPT_ELGAMAL_PubKey *pubKey = (CRYPT_ELGAMAL_PubKey *)BSL_SAL_Malloc(sizeof(CRYPT_ELGAMAL_PubKey));
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pubKey->p = BN_Create(bits);
    pubKey->g = BN_Create(bits);
    pubKey->y = BN_Create(bits);
    pubKey->q = BN_Create(bits);
    if (pubKey->p == NULL || pubKey->g == NULL || pubKey->y == NULL || pubKey->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ELGAMAL_FREE_PUB_KEY(pubKey);
    }

    return pubKey;
}

static int32_t ElGamal_GenP(void *libCtx, BN_BigNum *p, CRYPT_ELGAMAL_Para *para, BN_Optimizer *optimizer)
{
    uint32_t bits = para->bits;
    uint32_t k_bits = para->k_bits;
    BN_BigNum *k = BN_Create(bits - k_bits);
    BN_BigNum *kq = BN_Create(bits);
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    if (kq == NULL || k == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_GenPrime(para->q, NULL, k_bits, false, optimizer, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_RandEx(libCtx, k, (bits - k_bits), 1, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_Mul(kq, k, para->q, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_AddLimb(p, kq, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BN_Destroy(k);
    BN_Destroy(kq);
    return ret;
}

static int32_t ElGamal_CalcPrvKey(void *libCtx, CRYPT_ELGAMAL_PrvKey *prvKey, CRYPT_ELGAMAL_Para *para,
    BN_Optimizer *optimizer)
{
    int32_t ret = CRYPT_SUCCESS;
    BN_BigNum *xTop = BN_Create(para->bits);
    if (xTop == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = ElGamal_GenP(libCtx, prvKey->p, para, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = OriginalRoot(libCtx, prvKey->g, prvKey->p, para->q, para->bits);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_SubLimb(xTop, para->q, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_RandRangeEx(libCtx, prvKey->x, xTop);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BN_Destroy(xTop);
    return ret;
}

static int32_t ElGamal_CalcPubKey(CRYPT_ELGAMAL_PubKey *pubKey, CRYPT_ELGAMAL_PrvKey *prvKey, BN_Optimizer *optimizer)
{
    int32_t ret = BN_Copy(pubKey->p, prvKey->p);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Copy(pubKey->g, prvKey->g);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_ModExp(pubKey->y, pubKey->g, prvKey->x, pubKey->p, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_ELGAMAL_Gen(CRYPT_ELGAMAL_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    BN_Optimizer *optimizer = NULL;
    CRYPT_ELGAMAL_Ctx *newCtx = CRYPT_ELGAMAL_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    newCtx->para = CRYPT_ElGamal_DupPara(ctx->para);
    if (newCtx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }

    newCtx->prvKey = ElGamal_NewPrvKey(newCtx->para->bits);
    newCtx->pubKey = ElGamal_NewPubKey(newCtx->para->bits);
    optimizer = BN_OptimizerCreate();
    if (optimizer == NULL || newCtx->prvKey == NULL || newCtx->pubKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    BN_OptimizerSetLibCtx(ctx->libCtx, optimizer);
    ret = ElGamal_GenP(ctx->libCtx, newCtx->prvKey->p, newCtx->para, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = ElGamal_CalcPrvKey(ctx->libCtx, newCtx->prvKey, newCtx->para, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = ElGamal_CalcPubKey(newCtx->pubKey, newCtx->prvKey, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ELGAMAL_FREE_PARA(ctx->para);
    ELGAMAL_FREE_PRV_KEY(ctx->prvKey);
    ELGAMAL_FREE_PUB_KEY(ctx->pubKey);
    BSL_SAL_ReferencesFree(&(newCtx->references));

    ctx->prvKey = newCtx->prvKey;
    ctx->pubKey = newCtx->pubKey;
    ctx->para = newCtx->para;
    BSL_SAL_FREE(newCtx);
    BN_OptimizerDestroy(optimizer);

    return ret;

ERR:
    CRYPT_ELGAMAL_FreeCtx(newCtx);
    BN_OptimizerDestroy(optimizer);
    return ret;
}
#endif // HITLS_CRYPTO_ELGAMAL