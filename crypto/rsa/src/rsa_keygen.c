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

CRYPT_RSA_Ctx *CRYPT_RSA_NewCtxEx(void *libCtx)
{
    CRYPT_RSA_Ctx *keyCtx = CRYPT_RSA_NewCtx();
    if (keyCtx == NULL) {
        return NULL;
    }
#ifdef HITLS_CRYPTO_PROVIDER
    keyCtx->libCtx = libCtx;
#else
    (void)libCtx;
#endif
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

ERR:
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

ERR:
    RSA_FREE_PARA(newPara);
    return NULL;
}

#if defined(HITLS_CRYPTO_RSA_BLINDING) || defined(HITLS_CRYPTO_RSA_BSSA)
static RSA_Blind *RSABlindDupCtx(RSA_Blind *blind)
{
    RSA_Blind *newBlind = BSL_SAL_Malloc(sizeof(RSA_Blind));
    if (newBlind == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newBlind, sizeof(RSA_Blind), 0, sizeof(RSA_Blind));

    GOTO_ERR_IF_SRC_NOT_NULL(newBlind->r, blind->r, BN_Dup(blind->r), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newBlind->rInv, blind->rInv, BN_Dup(blind->rInv), CRYPT_MEM_ALLOC_FAIL);
    return newBlind;

ERR:
    RSA_BlindFreeCtx(newBlind);
    return NULL;
}
#endif

#ifdef HITLS_CRYPTO_RSA_BSSA
static RSA_BlindParam *RSABssADupCtx(RSA_BlindParam *blind)
{
    RSA_BlindParam *newBlind = BSL_SAL_Calloc(1u, sizeof(RSA_BlindParam));
    if (newBlind == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    if (blind->type == RSABSSA) {
        GOTO_ERR_IF_SRC_NOT_NULL(newBlind->para.bssa, blind->para.bssa,
            RSABlindDupCtx(blind->para.bssa), CRYPT_MEM_ALLOC_FAIL);
        newBlind->type = RSABSSA;
        return newBlind;
    }
ERR:
    BSL_SAL_FREE(newBlind);
    return NULL;
}
#endif

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
    newKeyCtx->pad.salt.data = NULL;
    newKeyCtx->pad.salt.len = 0;

    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->prvKey, keyCtx->prvKey, RSAPriKeyDupCtx(keyCtx->prvKey), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->pubKey, keyCtx->pubKey, RSAPubKeyDupCtx(keyCtx->pubKey), CRYPT_MEM_ALLOC_FAIL);
#ifdef HITLS_CRYPTO_RSA_BLINDING
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->scBlind, keyCtx->scBlind, RSABlindDupCtx(keyCtx->scBlind),
        CRYPT_MEM_ALLOC_FAIL);
#endif
#ifdef HITLS_CRYPTO_RSA_BSSA
    if (keyCtx->blindParam != NULL) {
        GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->blindParam, keyCtx->blindParam,
            RSABssADupCtx(keyCtx->blindParam), CRYPT_MEM_ALLOC_FAIL);
    }
#endif
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->para, keyCtx->para, RSAParaDupCtx(keyCtx->para), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->mdAttr, keyCtx->mdAttr, BSL_SAL_Dump(keyCtx->mdAttr,
        strlen(keyCtx->mdAttr) + 1), CRYPT_MEM_ALLOC_FAIL);
    newKeyCtx->libCtx = keyCtx->libCtx;
    BSL_SAL_ReferencesInit(&(newKeyCtx->references));
    return newKeyCtx;

ERR:
    CRYPT_RSA_FreeCtx(newKeyCtx);
    return NULL;
}

#ifdef HITLS_CRYPTO_ACVP_TESTS
static int32_t ProcessRsaPrimeSeeds(const BSL_Param *para, CRYPT_RSA_Para *retPara, uint32_t bits)
{
    const BSL_Param *sp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_RSA_XP);
    if (sp != NULL && sp->valueLen > 0) {
        if ((retPara->acvpTests.primeSeed.fipsPrimeSeeds.xp = BN_Create(bits)) == NULL ||
            (BN_Bin2Bn(retPara->acvpTests.primeSeed.fipsPrimeSeeds.xp, sp->value, sp->valueLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    sp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_RSA_XP1);
    if (sp != NULL && sp->valueLen > 0) {
        if ((retPara->acvpTests.primeSeed.fipsPrimeSeeds.xp1 = BN_Create(bits)) == NULL ||
            (BN_Bin2Bn(retPara->acvpTests.primeSeed.fipsPrimeSeeds.xp1, sp->value, sp->valueLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    sp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_RSA_XP2);
    if (sp != NULL && sp->valueLen > 0) {
        if ((retPara->acvpTests.primeSeed.fipsPrimeSeeds.xp2 = BN_Create(bits)) == NULL ||
            (BN_Bin2Bn(retPara->acvpTests.primeSeed.fipsPrimeSeeds.xp2, sp->value, sp->valueLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    sp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_RSA_XQ);
    if (sp != NULL && sp->valueLen > 0) {
        if ((retPara->acvpTests.primeSeed.fipsPrimeSeeds.xq = BN_Create(bits)) == NULL ||
            (BN_Bin2Bn(retPara->acvpTests.primeSeed.fipsPrimeSeeds.xq, sp->value, sp->valueLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    sp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_RSA_XQ1);
    if (sp != NULL && sp->valueLen > 0) {
        if ((retPara->acvpTests.primeSeed.fipsPrimeSeeds.xq1 = BN_Create(bits)) == NULL ||
            (BN_Bin2Bn(retPara->acvpTests.primeSeed.fipsPrimeSeeds.xq1, sp->value, sp->valueLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    sp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_RSA_XQ2);
    if (sp != NULL && sp->valueLen > 0) {
        if ((retPara->acvpTests.primeSeed.fipsPrimeSeeds.xq2 = BN_Create(bits)) == NULL ||
            (BN_Bin2Bn(retPara->acvpTests.primeSeed.fipsPrimeSeeds.xq2, sp->value, sp->valueLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }

    return CRYPT_SUCCESS;
}
#endif

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
    CRYPT_RSA_Para *retPara = BSL_SAL_Calloc(1, sizeof(CRYPT_RSA_Para));
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
    int32_t ret = BN_Bin2Bn(retPara->e, para->e, para->eLen);
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
#ifdef HITLS_CRYPTO_ACVP_TESTS
    BN_Destroy(para->acvpTests.primeSeed.fipsPrimeSeeds.xp);
    BN_Destroy(para->acvpTests.primeSeed.fipsPrimeSeeds.xp1);
    BN_Destroy(para->acvpTests.primeSeed.fipsPrimeSeeds.xp2);
    BN_Destroy(para->acvpTests.primeSeed.fipsPrimeSeeds.xq);
    BN_Destroy(para->acvpTests.primeSeed.fipsPrimeSeeds.xq1);
    BN_Destroy(para->acvpTests.primeSeed.fipsPrimeSeeds.xq2);
#endif
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
#ifdef HITLS_CRYPTO_RSA_BLINDING
    RSA_BlindFreeCtx(ctx->scBlind);
    ctx->scBlind = NULL;
#endif
#ifdef HITLS_CRYPTO_RSA_BSSA
    if (ctx->blindParam != NULL) {
        if (ctx->blindParam->type == RSABSSA) {
            RSA_BlindFreeCtx(ctx->blindParam->para.bssa);
        }
        BSL_SAL_FREE(ctx->blindParam);
    }
#endif
    BSL_SAL_CleanseData((void *)(&(ctx->pad)), sizeof(RSAPad));
    BSL_SAL_FREE(ctx->label.data);
    BSL_SAL_FREE(ctx->mdAttr);
    BSL_SAL_FREE(ctx);
}

static int32_t IsRSASetParamValid(const CRYPT_RSA_Ctx *ctx, const CRYPT_RSA_Para *para)
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

#ifdef HITLS_CRYPTO_ACVP_TESTS
static int32_t DupRsaPrimeSeeds(const CRYPT_RSA_Para *para, CRYPT_RSA_Para *paraCopy)
{
    if (para->acvpTests.primeSeed.fipsPrimeSeeds.xp != NULL &&
        (paraCopy->acvpTests.primeSeed.fipsPrimeSeeds.xp =
            BN_Dup(para->acvpTests.primeSeed.fipsPrimeSeeds.xp)) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (para->acvpTests.primeSeed.fipsPrimeSeeds.xp1 != NULL &&
        (paraCopy->acvpTests.primeSeed.fipsPrimeSeeds.xp1 =
            BN_Dup(para->acvpTests.primeSeed.fipsPrimeSeeds.xp1)) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (para->acvpTests.primeSeed.fipsPrimeSeeds.xp2 != NULL &&
        (paraCopy->acvpTests.primeSeed.fipsPrimeSeeds.xp2 =
            BN_Dup(para->acvpTests.primeSeed.fipsPrimeSeeds.xp2)) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (para->acvpTests.primeSeed.fipsPrimeSeeds.xq != NULL &&
        (paraCopy->acvpTests.primeSeed.fipsPrimeSeeds.xq =
            BN_Dup(para->acvpTests.primeSeed.fipsPrimeSeeds.xq)) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (para->acvpTests.primeSeed.fipsPrimeSeeds.xq1 != NULL &&
        (paraCopy->acvpTests.primeSeed.fipsPrimeSeeds.xq1 =
            BN_Dup(para->acvpTests.primeSeed.fipsPrimeSeeds.xq1)) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (para->acvpTests.primeSeed.fipsPrimeSeeds.xq2 != NULL &&
        (paraCopy->acvpTests.primeSeed.fipsPrimeSeeds.xq2 =
            BN_Dup(para->acvpTests.primeSeed.fipsPrimeSeeds.xq2)) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}
#endif

CRYPT_RSA_Para *CRYPT_RSA_DupPara(const CRYPT_RSA_Para *para)
{
    CRYPT_RSA_Para *paraCopy = BSL_SAL_Calloc(1, sizeof(CRYPT_RSA_Para));
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

#ifdef HITLS_CRYPTO_ACVP_TESTS
    int32_t ret = DupRsaPrimeSeeds(para, paraCopy);
    if (ret != CRYPT_SUCCESS) {
        RSA_FREE_PARA(paraCopy);
        return NULL;
    }
#endif
    return paraCopy;
}

int32_t CRYPT_RSA_SetPara(CRYPT_RSA_Ctx *ctx, const CRYPT_RsaPara *para)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_RSA_Para *rsaPara = CRYPT_RSA_NewPara(para);
    if (rsaPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_NEW_PARA_FAIL);
        return CRYPT_EAL_ERR_NEW_PARA_FAIL;
    }
    int32_t ret = IsRSASetParamValid(ctx, rsaPara);
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

static int32_t SetRsaBitsAndE(CRYPT_RSA_Ctx *ctx, const BSL_Param *para)
{
    CRYPT_RsaPara rsaPara = {0};
    const BSL_Param *temp = EAL_FindConstParam(para, CRYPT_PARAM_RSA_BITS);
    if (temp == NULL) {
        return CRYPT_SUCCESS;
    }
    if (temp->value != NULL && temp->valueLen == sizeof(uint32_t)) {
        rsaPara.bits = *(uint32_t *)temp->value;
    }
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_E, &rsaPara.e, &rsaPara.eLen);
    int32_t ret = CRYPT_RSA_SetPara(ctx, &rsaPara);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

#ifdef HITLS_CRYPTO_ACVP_TESTS
    return ProcessRsaPrimeSeeds(para, ctx->para, rsaPara.bits);
#endif
    return ret;
}

int32_t CRYPT_RSA_SetParaEx(CRYPT_RSA_Ctx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
#ifdef HITLS_CRYPTO_PROVIDER
    int32_t ret;
    const BSL_Param *temp = NULL;
    if ((temp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_MD_ATTR)) != NULL) {
        ret = CRYPT_PkeySetMdAttr((const char *)(temp->value), temp->valueLen, &(ctx->mdAttr));
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
#endif
    return SetRsaBitsAndE(ctx, para);
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
    priKey->p = BN_Create(bits >> 1);
    priKey->q = BN_Create(bits >> 1);
    priKey->e = BN_Create(bits >> 1);
    priKey->dP = BN_Create(bits >> 1);
    priKey->dQ = BN_Create(bits >> 1);
    priKey->qInv = BN_Create(bits >> 1);
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

#if defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY)
uint32_t CRYPT_RSA_GetSignLen(const CRYPT_RSA_Ctx *ctx)
{
    return BN_BITS_TO_BYTES(CRYPT_RSA_GetBits(ctx));
}
#endif

#ifdef HITLS_CRYPTO_RSA_GEN
static int32_t GetRandomX(void *libCtx, BN_BigNum *X, uint32_t nlen, bool isP)
{
    /*
     *  The FIPS 185-5 Appendix B.9 required √2(2 ^(nlen/2 - 1)) <= x <= ((2 ^(nlen/2) - 1))
     *  hence we can limit it as follows:
     *      √2 ~= 1.41421 < 1.5 -->
     *          √2(2 ^(nlen/2 - 1)) < 1.5 * (2 ^(nlen/2 - 1))
     *          next, we need to prove 1.5 * (2 ^(nlen/2 - 1)) <= ((2 ^(nlen/2) - 1))
     *              --> let x = 2 ^(nlen/2),  1.5 * (x/2) ≤ x - 1
     *              --> (3/4) x ≤ x - 1
     *              --> x >= 4, obviously correct.
     *  And, 1.5 * 2 ^(nlen/2 - 1) = 2 ^ (nlen/2 - 1) + 2 ^ (nlen/2 - 2);
     *  If we follow these steps to construct the bigNum:
     *      i. Randomly generate a random number, the most significant bit is (nlen / 2).
     *      ii. Set the (nlen/2 - 1) bits.
     *  We can obtain the x, satisfied [ 1.5 * 2 ^(nlen/2 - 1), ((2 ^(nlen/2) - 1) ].
     */
    if ((nlen % 2) == 0) {
        return BN_RandEx(libCtx, X, nlen >> 1, BN_RAND_TOP_TWOBIT, BN_RAND_BOTTOM_NOBIT);
    }
    /*
     * Meanwhile, if nlen is odd, We need to consider p, q separately.
     */
    if (isP) {
        /*
         *  left : √2(2 ^(nlen/2 - 1)) < 2 ^ ⌊ (nlen / 2) ⌋
         *  right: if nlen is odd, 2 ^ (nlen/2) - 1 == 2 ^ ( ⌊ (nlen)/2 ⌋ + 1/2) - 1 == √2 * 2 ^ (⌊ (nlen)/2 ⌋) - 1
         *  if we want left <= right:
         *         2 ^ ⌊ (nlen / 2) ⌋ < √2 * 2 ^ (⌊ (nlen)/2 ⌋) - 1
         *    -->  2 ^ ⌊ (nlen / 2) ⌋ < 1.4 * 2 ^ (⌊ (nlen)/2 ⌋) - 1
         *    -->  1 < 0.4 * 2 ^ (⌊ (nlen)/2 ⌋)
         *    -->  nlen >= 3, obviously correct.
         *  hence, We can obtain the x, set the (nlen)/2 + 1 bits.
         */
        return BN_RandEx(libCtx, X, (nlen + 1) >> 1, BN_RAND_TOP_ONEBIT, BN_RAND_BOTTOM_NOBIT);
    }
    return BN_RandEx(libCtx, X, nlen >> 1, BN_RAND_TOP_TWOBIT, BN_RAND_BOTTOM_NOBIT);
}

/*
 * Ref: FIPS 186-5: Table A.1
 * Get the maximum lengths of p1, p2, q1, and q2.
 */
static uint32_t GetAuxiliaryPrimeBitLen(uint32_t nlen)
{
    if (nlen <= 3071) {
        return 141;
    } else if (nlen <= 4095) {
        return 171;
    } else {
        return 201;
    }
}

/*
 * Ref: FIPS 186-5: Table A.1
 * Get the maximum lengths of p, q.
 */
static uint32_t GetProbableNoLimitedBitLen(uint32_t nlen)
{
    if (nlen <= 3071) {
        return 1007;
    } else if (nlen <= 4095) {
        return 1518;
    } else {
        return 2030;
    }
}

/*
 * Ref: FIPS 186-5: Table B.1
 * Get minimum number of rounds of M-R testing when generating auxiliary primes.
 */
static uint32_t GetAuxPrimeMillerCheckTimes(uint32_t auxBits)
{
    if (auxBits <= 170) {
        return 38; // Error probability = 2 ^ (-112)
    } else if (auxBits <= 200) {
        return 41; // Error probability = 2 ^ (-128)
    } else {
        return 44; // Error probability = 2 ^ (-144)
    }
}

/*
 * Ref: FIPS 186-5: Table B.1
 * Get minimum number of rounds of M-R testing when generating probable primes.
 */
static uint32_t GetProbPrimeMillerCheckTimes(uint32_t proBits)
{
    if (proBits < 1536) {
        return 5;
    }
    return 4;
}

static int32_t GenAuxPrime(BN_BigNum *Xp, uint32_t auxBits, BN_Optimizer *opt, bool isSeed)
{
    int32_t ret = CRYPT_SUCCESS;
    if (!isSeed) {
        ret = BN_RandEx(BN_OptimizerGetLibCtx(opt), Xp, auxBits, BN_RAND_TOP_ONEBIT, BN_RAND_BOTTOM_ONEBIT);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    uint32_t auxPrimeCheck = GetAuxPrimeMillerCheckTimes(auxBits);
    do {
        ret = BN_PrimeCheck(Xp, auxPrimeCheck, opt, NULL);
        if (ret == CRYPT_SUCCESS) {
            return ret;
        }
        if (ret != CRYPT_BN_NOR_CHECK_PRIME) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = BN_AddLimb(Xp, Xp, 2); // Try with odd numbers every time.
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } while (true);
}

/*
 * Ref: FIPS 186-5 B.9 Compute a Probable Prime Factor Based on Auxiliary Primes.
 * The standard specifies that the length of two small primes should meet
 *                 len(r1) + len(r2) ≤ (nlen/2) – log2(nlen/2) – 7
 * If nlen = 1024, r1, r2 is obtained by search from 141 bits data, the above inequality is still satisfied.
 * Hence, it's a only performance consideration for us to use this standard for 1024-bit rsa key-Gen.
 */
static int32_t GenPrimeWithAuxiliaryPrime(uint32_t auxBits, uint32_t proBits, BN_BigNum *Xp, BN_BigNum *Xp0,
    BN_BigNum *Xp1, BN_BigNum *Xp2, BN_BigNum *p, const CRYPT_RSA_Para *para, bool isP, BN_Optimizer *opt)
{
    BN_BigNum *r1;
    BN_BigNum *r2;
    uint32_t auxRoom = BITS_TO_BN_UNIT(auxBits);
    int32_t ret = OptimizerStart(opt); // use the optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t probPrimeCheck = GetProbPrimeMillerCheckTimes(proBits);

    r1 = (Xp1 != NULL) ? Xp1 : OptimizerGetBn(opt, auxRoom);
    r2 = (Xp2 != NULL) ? Xp2 : OptimizerGetBn(opt, auxRoom);

    BN_BigNum *r1Double = OptimizerGetBn(opt, auxRoom);
    BN_BigNum *primeCheck = OptimizerGetBn(opt, auxRoom);
    BN_BigNum *r2Inv = OptimizerGetBn(opt, auxRoom);
    BN_BigNum *r1DoubleInv = OptimizerGetBn(opt, auxRoom);
    BN_BigNum *R = OptimizerGetBn(opt, auxRoom);
    BN_BigNum *pMinusOne = OptimizerGetBn(opt, BITS_TO_BN_UNIT(proBits));
    uint32_t bits = isP ? (para->bits + 1) >> 1 : (para->bits >> 1); // Avoid the bit is odd.
    uint32_t iterRound = 20 * bits; // Step 9 specifies that the iteration round is 20 * (nlen/2);
    if (r1 == NULL || r2 == NULL || r1Double == NULL || primeCheck == NULL || r2Inv == NULL ||
        r1DoubleInv == NULL || R == NULL || pMinusOne == NULL) {
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        OptimizerEnd(opt);
        return ret;
    }

    // Choose auxiliary prime r1, either from seed or generate randomly
    ret = GenAuxPrime(r1, auxBits, opt, (Xp1 != NULL));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        OptimizerEnd(opt);
        return ret;
    }
    GOTO_ERR_IF(GenAuxPrime(r2, auxBits, opt, (Xp2 != NULL)), ret);
    GOTO_ERR_IF(BN_Lshift(r1Double, r1, 1), ret);
    // Step 1: check 2r1, r2 are coprime.
    GOTO_ERR_IF(BN_Gcd(primeCheck, r1Double, r2, opt), ret);
    if (!BN_IsOne(primeCheck)) {
        ret = CRYPT_RSA_NOR_KEYGEN_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NOR_KEYGEN_FAIL);
        goto ERR;
    }
    // Step 2: cal R = (r2^-1 mod 2r1) * r2 - ((2 * r1)^-1 mod r2) * (2 * r1)
    GOTO_ERR_IF(BN_ModInv(r2Inv, r2, r1Double, opt), ret); // (r2^-1 mod 2r1) * r2
    GOTO_ERR_IF(BN_Mul(r2Inv, r2, r2Inv, opt), ret);
    // ((2 * r1)^-1 mod r2) * (2 * r1)
    GOTO_ERR_IF(BN_ModInv(r1DoubleInv, r1Double, r2, opt), ret);
    GOTO_ERR_IF(BN_Mul(r1DoubleInv, r1Double, r1DoubleInv, opt), ret);
    // get R.
    GOTO_ERR_IF(BN_Sub(R, r2Inv, r1DoubleInv), ret);
    do {
        // Step 3: get x via seed xp/xq or random
        if (Xp0 == NULL) {
            GOTO_ERR_IF(GetRandomX(BN_OptimizerGetLibCtx(opt), Xp, para->bits, isP), ret);
        }

        // Step 4: Y = X + ((R – X) mod 2r1r2
        GOTO_ERR_IF(BN_Mul(r1, r1Double, r2, opt), ret); // 2r1r2
        GOTO_ERR_IF(BN_ModSub(R, R, Xp, r1, opt), ret);
        GOTO_ERR_IF(BN_Add(p, Xp, R), ret);
        uint32_t i = 0;
        for (; i < iterRound; i++) {
            // Step 6: Check p ≥ 2 ^ (nlen/2)
            if (BN_Bits(p) > bits) {
                break;
            }
            // Step 7: Check the p - 1 and e are corprime.
            GOTO_ERR_IF(BN_SubLimb(pMinusOne, p, 1), ret);
            GOTO_ERR_IF(BN_Gcd(pMinusOne, pMinusOne, para->e, opt), ret);
            if (BN_IsOne(pMinusOne)) {
                // Step 7.1: Check the primality of p.
                ret = BN_PrimeCheck(p, probPrimeCheck, opt, NULL);
                if (ret == CRYPT_SUCCESS) { // We find a primes successfully.
                    goto ERR;
                }
                if (ret != CRYPT_BN_NOR_CHECK_PRIME) { // Another exception has occurred.
                    BSL_ERR_PUSH_ERROR(ret);
                    goto ERR;
                }
            }
            // Step 10: Update p.
            GOTO_ERR_IF(BN_Add(p, p, r1), ret);
        }
        // Step 9: check i ≥ 20 * (nlen/2).
        if (i == iterRound) {
            ret = CRYPT_RSA_NOR_KEYGEN_FAIL;
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
    } while (true);
ERR:
    if (Xp1 == NULL) {
        BN_Zeroize(r1);
    }
    if (Xp2 == NULL) {
        BN_Zeroize(r2);
    }
    OptimizerEnd(opt);
    return ret;
}

// ref: FIPS 186-5, A.1.6 & B.9
static int32_t GenPQBasedOnProbPrimes(const CRYPT_RSA_Para *para, CRYPT_RSA_PrvKey *priKey, BN_Optimizer *opt)
{
    BN_BigNum *Xp = NULL, *Xq = NULL, *Xp0 = NULL, *Xp1 = NULL, *Xp2 = NULL, *Xq0 = NULL, *Xq1 = NULL, *Xq2 = NULL;
    uint32_t proBits = GetProbableNoLimitedBitLen(para->bits);
    uint32_t auxBits = GetAuxiliaryPrimeBitLen(para->bits);
    // Used in check |Xp – Xq| ≤ 2^(nlen/2) – 100 or |p – q| ≤ 2^(nlen/2) – 100.
    uint32_t secBits = ((para->bits + 1) >> 1) - 100;
    uint32_t proRoom = BITS_TO_BN_UNIT(proBits);
    int32_t ret = OptimizerStart(opt); // use the optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

#ifdef HITLS_CRYPTO_ACVP_TESTS
    Xp0 = para->acvpTests.primeSeed.fipsPrimeSeeds.xp;
    Xp1 = para->acvpTests.primeSeed.fipsPrimeSeeds.xp1;
    Xp2 = para->acvpTests.primeSeed.fipsPrimeSeeds.xp2;
    Xq0 = para->acvpTests.primeSeed.fipsPrimeSeeds.xq;
    Xq1 = para->acvpTests.primeSeed.fipsPrimeSeeds.xq1;
    Xq2 = para->acvpTests.primeSeed.fipsPrimeSeeds.xq2;
#endif
    Xp = (Xp0 != NULL) ? Xp0 : OptimizerGetBn(opt, proRoom);
    Xq = (Xq0 != NULL) ? Xq0 : OptimizerGetBn(opt, proRoom);
    if (Xp == NULL || Xq == NULL) {
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        OptimizerEnd(opt);
        return ret;
    }

    // Step 4: get p
    ret = GenPrimeWithAuxiliaryPrime(auxBits, proBits, Xp, Xp0, Xp1, Xp2, priKey->p, para, true, opt);
    if (ret != CRYPT_SUCCESS) {
        BN_Zeroize(Xp);
        BSL_ERR_PUSH_ERROR(ret);
        OptimizerEnd(opt);
        return ret;
    }
    /*
     * If |Xp – Xq| ≤ 2 ^ (2nlen/2 – 100) or |p – q| ≤ 2 ^ (2nlen/2 – 100), need to try again.
     * We think there can ever be repeated many times here unless the 'random' is stuck.
     * For example, nlen = 2048 and |Xp – Xq| ≤ 2 ^ (1024 – 100), it means that the most significant
     * 99 bits of our Xq and Xp randomly generated are all identical. It's a low-probability event.
     */
    do {
        // Step 5: get q
        ret = GenPrimeWithAuxiliaryPrime(auxBits, proBits, Xq, Xq0, Xq1, Xq2, priKey->q, para, false, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        // Step 6: Check (|Xp – Xq| ≤ 2^(nlen/2) – 100) and (|p – q| ≤ 2^(nlen/2) – 100)
        ret = BN_Sub(Xq, Xp, Xq); // Xq dont needs anymore, but Xp may be used.
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        // |Xp – Xq| ≤ 2 ^ (2nlen/2 – 100) -> BN_Bits(Xp) <= secBits + 1 -> BN_Bits(Xp) < secBits
        if (BN_Bits(Xq) < secBits) {
            if (Xq0 != NULL && Xq1 != NULL && Xq2 != NULL) {
                ret = CRYPT_RSA_NOR_KEYGEN_FAIL;
                BSL_ERR_PUSH_ERROR(ret);
                goto ERR;
            }
            continue;
        }
        ret = BN_Sub(Xq, priKey->p, priKey->q);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        // |p – q| ≤ 2 ^ (2nlen/2 – 100)
        if (BN_Bits(Xq) < secBits) {
            if (Xq0 != NULL && Xq1 != NULL && Xq2 != NULL) {
                ret = CRYPT_RSA_NOR_KEYGEN_FAIL;
                BSL_ERR_PUSH_ERROR(ret);
                goto ERR;
            }
            continue;
        }
        break;
    } while (true);
ERR:
    if (Xp0 == NULL) {
        BN_Zeroize(Xp);
    }
    if (Xq0 == NULL) {
        BN_Zeroize(Xq);
    }
    OptimizerEnd(opt);
    return ret;
}
#endif

static int32_t RsaPrvKeyCalcND(
    const CRYPT_RSA_Para *para, CRYPT_RSA_Ctx *ctx, BN_BigNum *pMinusOne, BN_BigNum *qMinusOne, BN_Optimizer *optimizer)
{
    int32_t ret;
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ret = OptimizerStart(optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_RSA_PrvKey *prvKey = ctx->prvKey;
    BN_BigNum *l = OptimizerGetBn(optimizer, BITS_TO_BN_UNIT(para->bits));
    BN_BigNum *u = OptimizerGetBn(optimizer, BITS_TO_BN_UNIT(para->bits));
    if (l == NULL || u == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        goto EXIT;
    }
    ret = BN_Mul(prvKey->n, prvKey->p, prvKey->q, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Mul(l, pMinusOne, qMinusOne, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Gcd(u, pMinusOne, qMinusOne, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Div(l, NULL, l, u, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_ModInv(prvKey->d, para->e, l, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    OptimizerEnd(optimizer);
    return ret;
}

// p, q [ => n, d]  => dP dQ qInv
// ctx->para may be NULL when setting key
int32_t RSA_CalcPrvKey(const CRYPT_RSA_Para *para, CRYPT_RSA_Ctx *ctx, BN_Optimizer *optimizer)
{
    int32_t ret;
    CRYPT_RSA_PrvKey *prvKey = ctx->prvKey;
    uint32_t needRoom = BITS_TO_BN_UNIT(BN_Bits(prvKey->p));
    ret = OptimizerStart(optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *pMinusOne = OptimizerGetBn(optimizer, needRoom);
    BN_BigNum *qMinusOne = OptimizerGetBn(optimizer, needRoom);
    if (pMinusOne == NULL || qMinusOne == NULL) {
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_SubLimb(pMinusOne, prvKey->p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_SubLimb(qMinusOne, prvKey->q, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if (BN_IsZero(prvKey->n)) { // when generating key
        ret = RsaPrvKeyCalcND(para, ctx, pMinusOne, qMinusOne, optimizer);
        if (ret != CRYPT_SUCCESS) {
            goto EXIT;
        }
    }
    ret = BN_ModInv(prvKey->qInv, prvKey->q, prvKey->p, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Div(NULL, prvKey->dP, prvKey->d, pMinusOne, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Div(NULL, prvKey->dQ, prvKey->d, qMinusOne, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    OptimizerEnd(optimizer);
    return ret;
}

#ifdef HITLS_CRYPTO_RSA_GEN
/*
 * In NIST SP 800-56B, Section 6.4.1.1, requiring we should perform a successful key-pair validation
 * while generating the key pair.
 */
static int32_t RSA_KeyValidationCheck(CRYPT_RSA_Ctx *ctx, uint32_t bits)
{
    int32_t ret;
    BN_BigNum *val = BN_Create(1);
    BN_BigNum *expect = BN_Create(bits);
    if (val == NULL || expect == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    // for performance reasons, we choose test num = 2.
    (void)BN_SetLimb(val, 2); // val is not null, and the val-memory must be sufficient.
    GOTO_ERR_IF(BN_MontExp(expect, val, ctx->prvKey->e, ctx->pubKey->mont, NULL), ret);
    GOTO_ERR_IF(BN_MontExpConsttime(expect, expect, ctx->prvKey->d, ctx->pubKey->mont, NULL), ret);
    if (BN_Cmp(val, expect) != 0) {
        ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE);
        goto ERR;
    }
ERR:
    BN_Destroy(val);
    BN_Destroy(expect);
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

    newCtx->prvKey = RSA_NewPrvKey(ctx->para->bits);
    newCtx->pubKey = RSA_NewPubKey(ctx->para->bits);
    optimizer = BN_OptimizerCreate();
    if (optimizer == NULL || newCtx->prvKey == NULL || newCtx->pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    /*
     * Currently, although the FIPS 186-5 standard does not support key generation of 1024 bits
     * due to its low security, our interface does not lift this restriction.
     * Meanwhile, the check of e is not added to ensure compatibility.
     */
    BN_OptimizerSetLibCtx(ctx->libCtx, optimizer);
    ret = GenPQBasedOnProbPrimes(ctx->para, newCtx->prvKey, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BN_OptimizerDestroy(optimizer);
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = RSA_CalcPrvKey(ctx->para, newCtx, optimizer);
    BN_OptimizerDestroy(optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Copy(newCtx->pubKey->n, newCtx->prvKey->n), ret);
    GOTO_ERR_IF(BN_Copy(newCtx->pubKey->e, ctx->para->e), ret);

    GOTO_ERR_IF(BN_Copy(newCtx->prvKey->e, ctx->para->e), ret);

    if ((newCtx->pubKey->mont = BN_MontCreate(newCtx->pubKey->n)) == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = RSA_KeyValidationCheck(newCtx, ctx->para->bits);
    if (ret != CRYPT_SUCCESS) {
        goto ERR; // dont't push the stack repeatedly.
    }
    ShallowCopyCtx(ctx, newCtx);
    BSL_SAL_FREE(newCtx);
    return ret;
ERR:
    CRYPT_RSA_FreeCtx(newCtx);
    return ret;
}

void ShallowCopyCtx(CRYPT_RSA_Ctx *ctx, CRYPT_RSA_Ctx *newCtx)
{
    RSA_FREE_PRV_KEY(ctx->prvKey);
    RSA_FREE_PUB_KEY(ctx->pubKey);
#ifdef HITLS_CRYPTO_RSA_BLINDING
    RSA_BlindFreeCtx(ctx->scBlind);
#endif
    BSL_SAL_ReferencesFree(&(newCtx->references));

    ctx->prvKey = newCtx->prvKey;
    ctx->pubKey = newCtx->pubKey;
#ifdef HITLS_CRYPTO_RSA_BLINDING
    ctx->scBlind = newCtx->scBlind;
#endif
    ctx->pad = newCtx->pad;
    ctx->flags = newCtx->flags;
}

#endif // HITLS_CRYPTO_RSA_GEN

#ifdef HITLS_CRYPTO_PROVIDER
static bool IsExistPrvKeyParams(const BSL_Param *params)
{
    const BSL_Param *d = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_D);
    const BSL_Param *n = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_N);
    const BSL_Param *p = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_P);
    const BSL_Param *q = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_Q);
    const BSL_Param *dp = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_DP);
    const BSL_Param *dq = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_DQ);
    const BSL_Param *qInv = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_QINV);
    return n != NULL && d != NULL && (PARAMISNULL(p) == PARAMISNULL(q)) &&
        (PARAMISNULL(dp) == PARAMISNULL(dq)) && PARAMISNULL(dq) == PARAMISNULL(qInv);
}

static bool IsExistPubKeyParams(const BSL_Param *params)
{
    const BSL_Param *e = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_E);
    const BSL_Param *n = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_N);
    return e != NULL && n != NULL;
}

static bool IsExistRsaParam(const BSL_Param *params)
{
    const BSL_Param *bits = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_BITS);
    const BSL_Param *e = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_E);
    return bits != NULL && e != NULL;
}

int32_t CRYPT_RSA_Import(CRYPT_RSA_Ctx *ctx, const BSL_Param *params)
{
    int32_t ret = CRYPT_SUCCESS;
    if (IsExistRsaParam(params)) {
        ret = CRYPT_RSA_SetParaEx(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (IsExistPrvKeyParams(params)) {
        ret = CRYPT_RSA_SetPrvKeyEx(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (IsExistPubKeyParams(params)) {
        ret = CRYPT_RSA_SetPubKeyEx(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    const BSL_Param *mdIdParam = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_MD_ID);
    const BSL_Param *mgf1IdParam = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_MGF1_ID);
    const BSL_Param *saltLenParam = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_SALTLEN);
    if (mdIdParam != NULL && mgf1IdParam != NULL && saltLenParam != NULL) {
        ret = CRYPT_RSA_Ctrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PSS, (void *)(uintptr_t)params, 0);
    } else if (mdIdParam != NULL && mdIdParam->valueType == BSL_PARAM_TYPE_INT32 && mdIdParam->value != NULL) {
        int32_t mdId = *(int32_t *)mdIdParam->value;
        ret = CRYPT_RSA_Ctrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &mdId, sizeof(mdId));
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static void InitRsaPubKeyParams(BSL_Param *params, uint32_t *index, uint8_t *buffer, uint32_t len)
{
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_E,
        BSL_PARAM_TYPE_OCTETS, buffer + ((*index - 1) * len), len);
    (*index)++;
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_N,
        BSL_PARAM_TYPE_OCTETS, buffer + ((*index - 1) * len), len);
    (*index)++;
}

static void InitRsaPrvKeyParams(BSL_Param *params, uint32_t *index, uint8_t *buffer, uint32_t len)
{
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_D,
        BSL_PARAM_TYPE_OCTETS, buffer + ((*index - 1) * len), len);
    (*index)++;
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_P,
        BSL_PARAM_TYPE_OCTETS, buffer + ((*index - 1) * len), len);
    (*index)++;
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_Q,
        BSL_PARAM_TYPE_OCTETS, buffer + ((*index - 1) * len), len);
    (*index)++;
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_DP,
        BSL_PARAM_TYPE_OCTETS, buffer + ((*index - 1) * len), len);
    (*index)++;
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_DQ,
        BSL_PARAM_TYPE_OCTETS, buffer + ((*index - 1) * len), len);
    (*index)++;
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_QINV,
        BSL_PARAM_TYPE_OCTETS, buffer + ((*index - 1) * len), len);
    (*index)++;
}

static void ExportRsaPssParams(const CRYPT_RSA_Ctx *ctx, BSL_Param *params, uint32_t *index)
{
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_MD_ID,
        BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&ctx->pad.para.pss.mdId, sizeof(ctx->pad.para.pss.mdId));
    params[(*index)++].useLen = sizeof(ctx->pad.para.pss.mdId);
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_MGF1_ID,
        BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&ctx->pad.para.pss.mgfId, sizeof(ctx->pad.para.pss.mgfId));
    params[(*index)++].useLen = sizeof(ctx->pad.para.pss.mgfId);
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_SALTLEN,
        BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&ctx->pad.para.pss.saltLen, sizeof(ctx->pad.para.pss.saltLen));
    params[(*index)++].useLen = sizeof(ctx->pad.para.pss.saltLen);
}

static void ExportRsaPkcsParams(const CRYPT_RSA_Ctx *ctx, BSL_Param *params, uint32_t *index)
{
    (void)BSL_PARAM_InitValue(&params[*index], CRYPT_PARAM_RSA_MD_ID,
        BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&ctx->pad.para.pkcsv15.mdId, sizeof(ctx->pad.para.pkcsv15.mdId));
    params[(*index)++].useLen = sizeof(ctx->pad.para.pkcsv15.mdId);
}

int32_t CRYPT_RSA_Export(const CRYPT_RSA_Ctx *ctx, BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t index = 1;
    void *args = NULL;
    CRYPT_EAL_ProcessFuncCb processCb = NULL;
    uint32_t keyBits = CRYPT_RSA_GetBits(ctx);
    if (keyBits == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    uint32_t bytes = BN_BITS_TO_BYTES(keyBits);
    BSL_Param rsaParams[13] = {
        {CRYPT_PARAM_RSA_BITS, BSL_PARAM_TYPE_UINT32, &keyBits, sizeof(uint32_t), sizeof(uint32_t)},
        {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    int32_t ret = CRYPT_GetPkeyProcessParams(params, &processCb, &args);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *buffer = BSL_SAL_Calloc(8, bytes);
    if (buffer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (ctx->pubKey != NULL) {
        InitRsaPubKeyParams(rsaParams, &index, buffer, bytes);
        ret = CRYPT_RSA_GetPubKeyEx(ctx, rsaParams);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(buffer);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (ctx->prvKey != NULL) {
        InitRsaPrvKeyParams(rsaParams, &index, buffer, bytes);
        ret = CRYPT_RSA_GetPrvKeyEx(ctx, rsaParams);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(buffer);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (ctx->pad.type == EMSA_PSS) {
        ExportRsaPssParams(ctx, rsaParams, &index);
    } else if (ctx->pad.type == EMSA_PKCSV15) {
        ExportRsaPkcsParams(ctx, rsaParams, &index);
    }
    for (uint32_t i = 0; i < index; i++) {
        rsaParams[i].valueLen = rsaParams[i].useLen;
    }
    ret = processCb(rsaParams, args);
    BSL_SAL_Free(buffer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_CRYPTO_PROVIDER
#endif /* HITLS_CRYPTO_RSA */
