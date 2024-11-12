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
#ifdef HITLS_CRYPTO_RSA

#include "crypt_rsa.h"
#include "rsa_local.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"

CRYPT_RSA_Ctx *CRYPT_RSA_NewCtx(void)
{
    CRYPT_RSA_Ctx *keyCtx = NULL;
    keyCtx = BSL_SAL_Malloc(sizeof(CRYPT_RSA_Ctx));
    if (keyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(keyCtx, sizeof(CRYPT_RSA_Ctx), 0, sizeof(CRYPT_RSA_Ctx));
    BSL_SAL_ReferencesInit(&(keyCtx->references));
    return keyCtx;
}

static CRYPT_RSA_PubKey *RSAPubKeyDupCtx(CRYPT_RSA_PubKey *pubKey)
{
    CRYPT_RSA_PubKey *newPubKey = BSL_SAL_Malloc(sizeof(CRYPT_RSA_PubKey));
    if (newPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newPubKey, sizeof(CRYPT_RSA_PubKey), 0, sizeof(CRYPT_RSA_PubKey));

    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->e, pubKey->e, BN_Dup(pubKey->e), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->n, pubKey->n, BN_Dup(pubKey->n), CRYPT_MEM_ALLOC_FAIL);

    newPubKey->mont = BN_MontCreate(pubKey->n);
    if (newPubKey->mont == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }

    return newPubKey;

ERR :
    RSA_FREE_PUB_KEY(newPubKey);
    return NULL;
}

static CRYPT_RSA_PrvKey *RSAPriKeyDupCtx(CRYPT_RSA_PrvKey *prvKey)
{
    CRYPT_RSA_PrvKey *newPriKey = BSL_SAL_Malloc(sizeof(CRYPT_RSA_PrvKey));
    if (newPriKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newPriKey, sizeof(CRYPT_RSA_PrvKey), 0, sizeof(CRYPT_RSA_PrvKey));

    GOTO_ERR_IF_SRC_NOT_NULL(newPriKey->n, prvKey->n, BN_Dup(prvKey->n), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPriKey->d, prvKey->d, BN_Dup(prvKey->d), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPriKey->p, prvKey->p, BN_Dup(prvKey->p), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPriKey->q, prvKey->q, BN_Dup(prvKey->q), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPriKey->dP, prvKey->dP, BN_Dup(prvKey->dP), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPriKey->dQ, prvKey->dQ, BN_Dup(prvKey->dQ), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPriKey->qInv, prvKey->qInv, BN_Dup(prvKey->qInv), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPriKey->e, prvKey->e, BN_Dup(prvKey->e), CRYPT_MEM_ALLOC_FAIL);

    return newPriKey;
ERR:
     RSA_FREE_PRV_KEY(newPriKey);
     return NULL;
}

static CRYPT_RSA_Para *RSAParaDupCtx(CRYPT_RSA_Para *para)
{
    CRYPT_RSA_Para *newPara = BSL_SAL_Malloc(sizeof(CRYPT_RSA_Para));
    if (newPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newPara, sizeof(CRYPT_RSA_Para), 0, sizeof(CRYPT_RSA_Para));

    newPara->bits = para->bits;
    GOTO_ERR_IF_SRC_NOT_NULL(newPara->e, para->e, BN_Dup(para->e), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPara->p, para->p, BN_Dup(para->p), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPara->q, para->q, BN_Dup(para->q), CRYPT_MEM_ALLOC_FAIL);
    return newPara;

ERR :
    RSA_FREE_PARA(newPara);
    return NULL;
}

static RSA_Blind *RSABlindDupCtx(RSA_Blind *blind)
{
    RSA_Blind *newBlind = BSL_SAL_Malloc(sizeof(RSA_Blind));
    if (newBlind == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newBlind, sizeof(RSA_Blind), 0, sizeof(RSA_Blind));

    GOTO_ERR_IF_SRC_NOT_NULL(newBlind->a, blind->a, BN_Dup(blind->a), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newBlind->ai, blind->ai, BN_Dup(blind->ai), CRYPT_MEM_ALLOC_FAIL);
    return newBlind;

ERR:
    RSA_BlindFreeCtx(newBlind);
    return NULL;
}

CRYPT_RSA_Ctx *CRYPT_RSA_DupCtx(CRYPT_RSA_Ctx *keyCtx)
{
    if (keyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_RSA_Ctx *newKeyCtx = NULL;
    newKeyCtx = BSL_SAL_Malloc(sizeof(CRYPT_RSA_Ctx));
    if (newKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newKeyCtx, sizeof(CRYPT_RSA_Ctx), 0, sizeof(CRYPT_RSA_Ctx));

    newKeyCtx->flags = keyCtx->flags;
    (void)memcpy_s(&(newKeyCtx->pad), sizeof(RSAPad), &(keyCtx->pad), sizeof(RSAPad));

    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->prvKey, keyCtx->prvKey, RSAPriKeyDupCtx(keyCtx->prvKey), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->pubKey, keyCtx->pubKey, RSAPubKeyDupCtx(keyCtx->pubKey), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->blind, keyCtx->blind, RSABlindDupCtx(keyCtx->blind), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->para, keyCtx->para, RSAParaDupCtx(keyCtx->para), CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_ReferencesInit(&(newKeyCtx->references));
    return newKeyCtx;

ERR :
    CRYPT_RSA_FreeCtx(newKeyCtx);
    return NULL;
}

static int32_t RsaNewParaBasicCheck(const CRYPT_RsaPara *para)
{
    if (para == NULL || para->e == NULL || para->eLen == 0 ||
        para->bits > RSA_MAX_MODULUS_BITS || para->bits < RSA_MIN_MODULUS_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    /* the length of e cannot be greater than bits */
    if (para->eLen > BN_BITS_TO_BYTES(para->bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}

CRYPT_RSA_Para *CRYPT_RSA_NewPara(const CRYPT_RsaPara *para)
{
    if (RsaNewParaBasicCheck(para) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    CRYPT_RSA_Para *retPara = BSL_SAL_Malloc(sizeof(CRYPT_RSA_Para));
    if (retPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    retPara->bits = para->bits;
    retPara->e = BN_Create(para->bits);
    retPara->p = BN_Create(para->bits);
    retPara->q = BN_Create(para->bits);
    if (retPara->e == NULL || retPara->p == NULL || retPara->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    int32_t ret;
    ret = BN_Bin2Bn(retPara->e, para->e, para->eLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (BN_BITS_TO_BYTES(para->bits) > RSA_SMALL_MODULUS_BYTES && BN_Bytes(retPara->e) > RSA_MAX_PUBEXP_BYTES) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        goto ERR;
    }
    return retPara;
ERR:
    CRYPT_RSA_FreePara(retPara);
    return NULL;
}

void CRYPT_RSA_FreePara(CRYPT_RSA_Para *para)
{
    if (para == NULL) {
        return;
    }
    BN_Destroy(para->e);
    BN_Destroy(para->p);
    BN_Destroy(para->q);
    BSL_SAL_FREE(para);
}

void RSA_FreePrvKey(CRYPT_RSA_PrvKey *prvKey)
{
    if (prvKey == NULL) {
        return;
    }
    BN_Destroy(prvKey->n);
    BN_Destroy(prvKey->d);
    BN_Destroy(prvKey->p);
    BN_Destroy(prvKey->q);
    BN_Destroy(prvKey->e);
    BN_Destroy(prvKey->dP);
    BN_Destroy(prvKey->dQ);
    BN_Destroy(prvKey->qInv);
    BSL_SAL_FREE(prvKey);
}

void RSA_FreePubKey(CRYPT_RSA_PubKey *pubKey)
{
    if (pubKey == NULL) {
        return;
    }
    BN_Destroy(pubKey->n);
    BN_Destroy(pubKey->e);
    BN_MontDestroy(pubKey->mont);
    BSL_SAL_FREE(pubKey);
}

void CRYPT_RSA_FreeCtx(CRYPT_RSA_Ctx *ctx)
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
    RSA_FREE_PARA(ctx->para);
    RSA_FREE_PRV_KEY(ctx->prvKey);
    RSA_FREE_PUB_KEY(ctx->pubKey);
    RSA_BlindFreeCtx(ctx->blind);
    ctx->blind = NULL;
    BSL_SAL_CleanseData((void *)(&(ctx->pad)), sizeof(RSAPad));
    BSL_SAL_FREE(ctx->label.data);
    BSL_SAL_FREE(ctx);
}

static int32_t IsRSASetParaVaild(const CRYPT_RSA_Ctx *ctx, const CRYPT_RSA_Para *para)
{
    if (ctx == NULL || para == NULL || para->e == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->bits > RSA_MAX_MODULUS_BITS || para->bits < RSA_MIN_MODULUS_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }

    if (BN_GetBit(para->e, 0) != true || BN_IsLimb(para->e, 1) == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_E_VALUE);
        return CRYPT_RSA_ERR_E_VALUE;
    }
    return CRYPT_SUCCESS;
}

CRYPT_RSA_Para *CRYPT_RSA_DupPara(const CRYPT_RSA_Para *para)
{
    CRYPT_RSA_Para *paraCopy = BSL_SAL_Malloc(sizeof(CRYPT_RSA_Para));
    if (paraCopy == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    paraCopy->bits = para->bits;
    paraCopy->e = BN_Dup(para->e);
    paraCopy->p = BN_Dup(para->p);
    paraCopy->q = BN_Dup(para->q);
    if (paraCopy->e == NULL || paraCopy->p == NULL || paraCopy->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        RSA_FREE_PARA(paraCopy);
        return NULL;
    }

    return paraCopy;
}

int32_t CRYPT_RSA_SetPara(CRYPT_RSA_Ctx *ctx, const CRYPT_Param *para)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_RSA_Para *rsaPara = CRYPT_RSA_NewPara((CRYPT_RsaPara *)para->param);
    if (rsaPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_NEW_PARA_FAIL);
        return CRYPT_EAL_ERR_NEW_PARA_FAIL;
    }
    int32_t ret = IsRSASetParaVaild(ctx, rsaPara);
    if (ret != CRYPT_SUCCESS) {
        RSA_FREE_PARA(rsaPara);
        return ret;
    }
    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    RSA_FREE_PARA(ctx->para);
    RSA_FREE_PRV_KEY(ctx->prvKey);
    RSA_FREE_PUB_KEY(ctx->pubKey);
    ctx->para = rsaPara;
    return CRYPT_SUCCESS;
}

CRYPT_RSA_PrvKey *RSA_NewPrvKey(uint32_t bits)
{
    CRYPT_RSA_PrvKey *priKey = BSL_SAL_Malloc(sizeof(CRYPT_RSA_PrvKey));
    if (priKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    priKey->n = BN_Create(bits);
    priKey->d = BN_Create(bits);
    priKey->p = BN_Create(bits);
    priKey->q = BN_Create(bits);
    priKey->e = BN_Create(bits);
    priKey->dP = BN_Create(bits);
    priKey->dQ = BN_Create(bits);
    priKey->qInv = BN_Create(bits);
    bool creatFailed = (priKey->n == NULL || priKey->d == NULL || priKey->e == NULL || priKey->p == NULL ||
        priKey->q == NULL || priKey->dP == NULL || priKey->dQ == NULL || priKey->qInv == NULL);
    if (creatFailed) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        RSA_FREE_PRV_KEY(priKey);
    }
    return priKey;
}

CRYPT_RSA_PubKey *RSA_NewPubKey(uint32_t bits)
{
    CRYPT_RSA_PubKey *pubKey = BSL_SAL_Malloc(sizeof(CRYPT_RSA_PubKey));
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pubKey->n = BN_Create(bits);
    pubKey->e = BN_Create(bits);
    pubKey->mont = NULL;
    if (pubKey->n == NULL || pubKey->e == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        RSA_FREE_PUB_KEY(pubKey);
    }
    return pubKey;
}

uint32_t CRYPT_RSA_GetBits(const CRYPT_RSA_Ctx *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    if (ctx->para != NULL) {
        return ctx->para->bits;
    }
    if (ctx->prvKey != NULL) {
        return BN_Bits(ctx->prvKey->n);
    }
    if (ctx->pubKey != NULL) {
        return BN_Bits(ctx->pubKey->n);
    }
    return 0;
}

uint32_t CRYPT_RSA_GetSignLen(const CRYPT_RSA_Ctx *ctx)
{
    return BN_BITS_TO_BYTES(CRYPT_RSA_GetBits(ctx));
}

static int32_t RSA_Filter(
    const BN_BigNum *p, uint32_t bits, const BN_BigNum *e, BN_Optimizer *optimizer)
{
    int32_t ret;
    BN_BigNum *pMinus1 = BN_Create(bits);
    BN_BigNum *u = BN_Create(bits);
    if (pMinus1 == NULL || u == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_SubLimb(pMinus1, p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Gcd(u, pMinus1, e, optimizer);
    if (ret == CRYPT_SUCCESS) {
        if (BN_IsOne(u) != true) {
            ret = CRYPT_RSA_NOR_KEYGEN_FAIL;
            BSL_ERR_PUSH_ERROR(ret);
        }
    }

ERR:
    BN_Destroy(pMinus1);
    BN_Destroy(u);
    return ret;
}

static int32_t RsaPGen(CRYPT_RSA_Para *para, CRYPT_RSA_PrvKey *priKey, BN_Optimizer *optimizer)
{
    uint32_t pBits = (para->bits + 1) / 2;
    int32_t ret = BN_GenPrime(priKey->p, pBits, true, optimizer, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return RSA_Filter(priKey->p, pBits, para->e, optimizer);
}

static int32_t RsaQGen(CRYPT_RSA_Para *para, CRYPT_RSA_PrvKey *priKey, BN_Optimizer *optimizer)
{
    uint32_t pBits = (para->bits + 1) / 2;
    uint32_t qBits = para->bits - pBits;
    int32_t ret = BN_GenPrime(priKey->q, qBits, true, optimizer, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return RSA_Filter(priKey->q, qBits, para->e, optimizer);
}

static int32_t RsaPQGen(CRYPT_RSA_Para *para, CRYPT_RSA_PrvKey *priKey, BN_Optimizer *optimizer)
{
    int32_t ret = CRYPT_BN_RAND_GEN_FAIL;
    uint32_t i;
    uint32_t halfBits = para->bits / 2;
    BN_BigNum *val = BN_Create(halfBits - 100);
    BN_BigNum *sub = BN_Create(para->bits);
    if (val == NULL || sub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    // FIPS 186-4 B.3.3 5.4, compare with 2^(nlen/2-100)
    GOTO_ERR_IF(BN_SetBit(val, halfBits - 100), ret);

    // FIPS 186-4 B.3.3 4.7, retry 5(nlen/2) times
    for (i = 0; i < 5 * halfBits; i++) {
        ret = RsaPGen(para, priKey, optimizer);
        if (ret == CRYPT_SUCCESS) {
            break;
        }
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // FIPS 186-4 B.3.3 5.8, retry 5(nlen/2) times
    for (i = 0; i < 5 * halfBits; i++) {
        ret = RsaQGen(para, priKey, optimizer);
        if (ret != CRYPT_SUCCESS) {
            continue;
        }
        GOTO_ERR_IF(BN_Sub(sub, priKey->p, priKey->q), ret);
        GOTO_ERR_IF(BN_SetSign(sub, false), ret);
        if (BN_Cmp(sub, val) <= 0) {
            continue;
        }
        break;
    }
    if (BN_Cmp(priKey->p, priKey->q) < 0) {
        BN_BigNum *tmp = priKey->p;
        priKey->p = priKey->q;
        priKey->q = tmp;
    }
ERR:
    BN_Destroy(val);
    BN_Destroy(sub);
    return ret;
}

static int32_t RsaPrvKeyCalcND(
    CRYPT_RSA_Ctx *ctx, BN_BigNum *pMinusOne, BN_BigNum *qMinusOne, BN_Optimizer *optimizer)
{
    int32_t ret;
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_RSA_PrvKey *prvKey = ctx->prvKey;
    BN_BigNum *l = BN_Create(ctx->para->bits);
    BN_BigNum *u = BN_Create(ctx->para->bits);
    if (l == NULL || u == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    ret = BN_Mul(prvKey->n, prvKey->p, prvKey->q, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Mul(l, pMinusOne, qMinusOne, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Gcd(u, pMinusOne, qMinusOne, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Div(l, NULL, l, u, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_ModInv(prvKey->d, ctx->para->e, l, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    BN_Destroy(l);
    BN_Destroy(u);
    return ret;
}

// p, q [ => n, d]  => dP dQ qInv
// ctx->para may be NULL when setting key
int32_t RSA_CalcPrvKey(CRYPT_RSA_Ctx *ctx, BN_Optimizer *optimizer)
{
    int32_t ret;
    CRYPT_RSA_PrvKey *prvKey = ctx->prvKey;
    BN_BigNum *pMinusOne = BN_Create(BN_Bits(prvKey->p));
    BN_BigNum *qMinusOne = BN_Create(BN_Bits(prvKey->q));
    if (pMinusOne == NULL || qMinusOne == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_SubLimb(pMinusOne, prvKey->p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_SubLimb(qMinusOne, prvKey->q, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (BN_IsZero(prvKey->n)) { // when generating key
        ret = RsaPrvKeyCalcND(ctx, pMinusOne, qMinusOne, optimizer);
        if (ret != CRYPT_SUCCESS) {
            goto ERR;
        }
    }
    ret = BN_ModInv(prvKey->qInv, prvKey->q, prvKey->p, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Div(NULL, prvKey->dP, prvKey->d, pMinusOne, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Div(NULL, prvKey->dQ, prvKey->d, qMinusOne, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    BN_Destroy(pMinusOne);
    BN_Destroy(qMinusOne);
    return ret;
}

int32_t CRYPT_RSA_Gen(CRYPT_RSA_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    BN_Optimizer *optimizer = NULL;
    CRYPT_RSA_Ctx *newCtx = CRYPT_RSA_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    newCtx->para = CRYPT_RSA_DupPara(ctx->para);
    if (newCtx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }

    newCtx->prvKey = RSA_NewPrvKey(newCtx->para->bits);
    newCtx->pubKey = RSA_NewPubKey(newCtx->para->bits);
    optimizer = BN_OptimizerCreate();
    if (optimizer == NULL || newCtx->prvKey == NULL || newCtx->pubKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = RsaPQGen(newCtx->para, newCtx->prvKey, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = RSA_CalcPrvKey(newCtx, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Copy(newCtx->pubKey->n, newCtx->prvKey->n), ret);
    GOTO_ERR_IF(BN_Copy(newCtx->pubKey->e, newCtx->para->e), ret);
    GOTO_ERR_IF(BN_Copy(newCtx->prvKey->e, newCtx->para->e), ret);

    if ((newCtx->pubKey->mont = BN_MontCreate(newCtx->pubKey->n)) == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ShallowCopyCtx(ctx, newCtx);
    BSL_SAL_FREE(newCtx);
    BN_OptimizerDestroy(optimizer);
    return ret;
ERR:
    CRYPT_RSA_FreeCtx(newCtx);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

void ShallowCopyCtx(CRYPT_RSA_Ctx *ctx, CRYPT_RSA_Ctx *newCtx)
{
    RSA_FREE_PARA(ctx->para);
    RSA_FREE_PRV_KEY(ctx->prvKey);
    RSA_FREE_PUB_KEY(ctx->pubKey);
    RSA_BlindFreeCtx(ctx->blind);
    BSL_SAL_ReferencesFree(&(newCtx->references));

    ctx->prvKey = newCtx->prvKey;
    ctx->pubKey = newCtx->pubKey;
    ctx->para = newCtx->para;
    ctx->blind = newCtx->blind;
    ctx->pad = newCtx->pad;
    ctx->flags = newCtx->flags;
}
#endif // HITLS_CRYPTO_RSA
