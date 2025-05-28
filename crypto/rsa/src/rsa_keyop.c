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

#include "crypt_types.h"
#include "crypt_rsa.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "rsa_local.h"
#include "crypt_errno.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_params_key.h"

typedef struct {
    BSL_Param *d;  /**< RSA private key parameter marked as d. */
    BSL_Param *n;  /**< RSA private key parameter marked as n. */
    BSL_Param *p;  /**< RSA private key parameter marked as p. */
    BSL_Param *q;  /**< RSA private key parameter marked as q. */
    BSL_Param *dP; /**< RSA private key parameter marked as dP. */
    BSL_Param *dQ; /**< RSA private key parameter marked as dQ. */
    BSL_Param *qInv; /**< RSA private key parameter marked as qInv. */
    BSL_Param *e;    /**< RSA public key parameter marked as e. */
} CRYPT_RsaPrvParam;

static int32_t SetPrvPara(const CRYPT_RSA_PrvKey *prvKey, const CRYPT_RsaPrvParam *prv)
{
    int32_t ret = BN_Bin2Bn(prvKey->n, prv->n->value, prv->n->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t bnBits = BN_Bits(prvKey->n);
    if (bnBits > RSA_MAX_MODULUS_BITS || bnBits < RSA_MIN_MODULUS_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    ret = BN_Bin2Bn(prvKey->d, prv->d->value, prv->d->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // d cannot be 0 or 1. The mathematical logic of e and d is that
    // d and e are reciprocal in mod((p-1) * (q-1)); When d is 1, e and d must be 1. When d is 0, e doesn't exist.
    if (BN_IsZero(prvKey->d) || BN_IsOne(prvKey->d)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    if (BN_Cmp(prvKey->n, prvKey->d) <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    if (!PARAMISNULL(prv->e)) {
        ret = BN_Bin2Bn(prvKey->e, prv->e->value, prv->e->valueLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (BN_Cmp(prvKey->n, prvKey->e) <= 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
            return CRYPT_RSA_ERR_INPUT_VALUE;
        }
    }
    if (!PARAMISNULL(prv->p)) {
        GOTO_ERR_IF_EX(BN_Bin2Bn(prvKey->p, prv->p->value, prv->p->valueLen), ret);
        GOTO_ERR_IF_EX(BN_Bin2Bn(prvKey->q, prv->q->value, prv->q->valueLen), ret);
        if (BN_IsZero(prvKey->p) == true || BN_IsZero(prvKey->q) == true) {
            BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
            return CRYPT_RSA_ERR_INPUT_VALUE;
        }
        if (!PARAMISNULL(prv->dP)) {
            GOTO_ERR_IF_EX(BN_Bin2Bn(prvKey->dP, prv->dP->value, prv->dP->valueLen), ret);
            GOTO_ERR_IF_EX(BN_Bin2Bn(prvKey->dQ, prv->dQ->value, prv->dQ->valueLen), ret);
            GOTO_ERR_IF_EX(BN_Bin2Bn(prvKey->qInv, prv->qInv->value, prv->qInv->valueLen), ret);
        }
    }
ERR:
    return ret;
}

static int32_t GetAndCheckPrvKey(CRYPT_RSA_Ctx *ctx, BSL_Param *para, CRYPT_RsaPrvParam *prv)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    prv->n = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_N);
    prv->d = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_D);
    prv->e = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_E);
    prv->p = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_P);
    prv->q = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_Q);
    prv->dP = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_DP);
    prv->dQ = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_DQ);
    prv->qInv = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_QINV);
    if (PARAMISNULL(prv->n) || prv->n->valueLen == 0 || PARAMISNULL(prv->d)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->n->valueLen > RSA_MAX_MODULUS_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    // prv->p\q and prv->dP\dQ\qInv must be both empty or not.
    // If prv->p is empty, prv->dP must be empty.
    if ((PARAMISNULL(prv->p) != PARAMISNULL(prv->q)) || (PARAMISNULL(prv->p) && !PARAMISNULL(prv->dP))) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    if ((PARAMISNULL(prv->dP) || PARAMISNULL(prv->dQ) || PARAMISNULL(prv->qInv)) &&
        (!PARAMISNULL(prv->dP) || !PARAMISNULL(prv->dQ) || !PARAMISNULL(prv->qInv))) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    return CRYPT_SUCCESS;
}

static int32_t SetPrvBnLenCheck(const CRYPT_RsaPrvParam *prv)
{
    /* The length of n is used as the length of a BigNum. The lengths of d, p, and q are not greater than n. */
    uint32_t bnBytes = prv->n->valueLen;
    if (prv->d->valueLen > bnBytes || prv->p->valueLen > bnBytes || prv->q->valueLen > bnBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_SetPrvKey(CRYPT_RSA_Ctx *ctx, const BSL_Param *para)
{
    CRYPT_RsaPrvParam prv = {0};
    int32_t ret = GetAndCheckPrvKey(ctx, (BSL_Param *)(uintptr_t)para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = SetPrvBnLenCheck(&prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_RSA_Ctx *newCtx = CRYPT_RSA_NewCtx();
    if (newCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    newCtx->prvKey = RSA_NewPrvKey(prv.n->valueLen * 8); // Bit length is obtained by multiplying byte length by 8.
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
    if (!PARAMISNULL(prv.p) && PARAMISNULL(prv.dP)) {
        BN_Optimizer *optimizer = BN_OptimizerCreate();
        if (optimizer == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        ret = RSA_CalcPrvKey(newCtx->para, newCtx, optimizer);
        BN_OptimizerDestroy(optimizer);
        if (ret != CRYPT_SUCCESS) {
            goto ERR;
        }
    }

    RSA_FREE_PRV_KEY(ctx->prvKey);
#ifdef HITLS_CRYPTO_RSA_BLINDING
    RSA_BlindFreeCtx(ctx->scBlind);
    ctx->scBlind = newCtx->scBlind;
#endif

    ctx->prvKey = newCtx->prvKey;
    ctx->pad = newCtx->pad;

    BSL_SAL_ReferencesFree(&(newCtx->references));
    BSL_SAL_FREE(newCtx);
    return ret;
ERR:
    CRYPT_RSA_FreeCtx(newCtx);
    return ret;
}

static int32_t SetPubBasicCheckAndGet(const CRYPT_RSA_Ctx *ctx, const BSL_Param *para, const BSL_Param *n,
    const BSL_Param *e)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (PARAMISNULL(n)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (PARAMISNULL(e)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (n->valueLen > RSA_MAX_MODULUS_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    /* The length of n is used as the length of a BigNum, and the length of e is not greater than n. */
    if (e->valueLen > n->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_SetPubKey(CRYPT_RSA_Ctx *ctx, const BSL_Param *para)
{
    const BSL_Param *nParam = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_RSA_N);
    const BSL_Param *eParam = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_RSA_E);
    int32_t ret = SetPubBasicCheckAndGet(ctx, para, nParam, eParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t bnBits;
    CRYPT_RSA_PubKey *newPub = NULL;
    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    /* Bit length is obtained by multiplying byte length by 8. */
    newPub = RSA_NewPubKey(nParam->valueLen * 8);
    if (newPub == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->n, nParam->value, nParam->valueLen), ret);
    bnBits = BN_Bits(newPub->n);
    if (bnBits > RSA_MAX_MODULUS_BITS || bnBits < RSA_MIN_MODULUS_BITS) {
        ret = CRYPT_RSA_ERR_KEY_BITS;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->e, eParam->value, eParam->valueLen), ret);
    if (nParam->valueLen > RSA_SMALL_MODULUS_BYTES && BN_Bytes(newPub->e) > RSA_MAX_PUBEXP_BYTES) {
        ret = CRYPT_RSA_ERR_KEY_BITS;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    /**
     * n > e
     * e cannot be 0 or 1; The mathematical logic of e and d is that
     * d and e are reciprocal in mod((p - 1) * (q - 1));
     * When e is 1, both e and d must be 1. When e is 0, d does not exist.
     */
    if (BN_Cmp(newPub->n, newPub->e) <= 0 || BN_IsZero(newPub->e) || BN_IsOne(newPub->e)) {
        ret = CRYPT_RSA_ERR_INPUT_VALUE;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    newPub->mont = BN_MontCreate(newPub->n);
    if (newPub->mont == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
}

    RSA_FREE_PUB_KEY(ctx->pubKey);
    ctx->pubKey = newPub;
    return ret;
ERR:
    RSA_FREE_PUB_KEY(newPub);
    return ret;
}

static int32_t GetPrvBasicCheck(const CRYPT_RSA_Ctx *ctx, BSL_Param *para, CRYPT_RsaPrvParam *prv)
{
    if (ctx == NULL || ctx->prvKey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    prv->n = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_N);
    prv->d = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_D);
    prv->e = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_E);
    prv->p = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_P);
    prv->q = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_Q);
    prv->dP = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_DP);
    prv->dQ = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_DQ);
    prv->qInv = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_QINV);
    // ctx\ctx->prvKey\prv is not empty.
    // prv->p\q and prv->dP\dQ\qInv are both null or non-null.
    // If prv->p is empty, prv->dP is empty.
    if ((PARAMISNULL(prv->p) != PARAMISNULL(prv->q)) ||
        ((PARAMISNULL(prv->dP) || PARAMISNULL(prv->dQ) || PARAMISNULL(prv->qInv)) &&
         (!PARAMISNULL(prv->dP) || !PARAMISNULL(prv->dQ) || !PARAMISNULL(prv->qInv))) ||
        (PARAMISNULL(prv->p) && !PARAMISNULL(prv->dP))) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_GetPrvKey(const CRYPT_RSA_Ctx *ctx, BSL_Param *para)
{
    CRYPT_RsaPrvParam prv = {0};
    int32_t ret = GetPrvBasicCheck(ctx, para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    prv.n->useLen = prv.n->valueLen;
    GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->n, prv.n->value, &(prv.n->useLen)), ret);
    prv.d->useLen = prv.d->valueLen;
    GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->d, prv.d->value, &(prv.d->useLen)), ret);
    if (!PARAMISNULL(prv.e)) {
        prv.e->useLen = prv.e->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->e, prv.e->value, &(prv.e->useLen)), ret);
    }
    if (!PARAMISNULL(prv.p)) {
        prv.p->useLen = prv.p->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->p, prv.p->value, &(prv.p->useLen)), ret);
        prv.q->useLen = prv.q->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->q, prv.q->value, &(prv.q->useLen)), ret);
    }
    if (!PARAMISNULL(prv.dQ)) {
        prv.dQ->useLen = prv.dQ->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->dQ, prv.dQ->value, &(prv.dQ->useLen)), ret);
        prv.dP->useLen = prv.dP->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->dP, prv.dP->value, &(prv.dP->useLen)), ret);
        prv.qInv->useLen = prv.qInv->valueLen;
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->qInv, prv.qInv->value, &(prv.qInv->useLen)), ret);
    }
    return CRYPT_SUCCESS;

ERR:
    if (!PARAMISNULL(prv.d) && prv.d->useLen != 0) {
        BSL_SAL_CleanseData(prv.d->value, prv.d->useLen);
        prv.d->useLen = 0;
    }
    if (!PARAMISNULL(prv.p) && prv.p->useLen != 0) {
        BSL_SAL_CleanseData(prv.p->value, prv.p->useLen);
        prv.p->useLen = 0;
    }
    if (!PARAMISNULL(prv.q) && prv.q->useLen != 0) {
        BSL_SAL_CleanseData(prv.q->value, prv.q->useLen);
        prv.q->useLen = 0;
    }
    if (!PARAMISNULL(prv.dQ) && prv.dQ->useLen != 0) {
        BSL_SAL_CleanseData(prv.dQ->value, prv.dQ->useLen);
        prv.dQ->useLen = 0;
    }
    if (!PARAMISNULL(prv.dP) && prv.dP->useLen != 0) {
        BSL_SAL_CleanseData(prv.dP->value, prv.dP->useLen);
        prv.dP->useLen = 0;
    }
    if (!PARAMISNULL(prv.qInv) && prv.qInv->useLen != 0) {
        BSL_SAL_CleanseData(prv.qInv->value, prv.qInv->useLen);
        prv.qInv->useLen = 0;
    }
    return ret;
}

int32_t CRYPT_RSA_GetPubKey(const CRYPT_RSA_Ctx *ctx, BSL_Param *para)
{
    if (ctx == NULL || ctx->pubKey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *e = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_E);
    if (e == NULL || e->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t eLen = e->valueLen;
    int32_t ret = BN_Bn2Bin(ctx->pubKey->e, e->value, &eLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Param *n = BSL_PARAM_FindParam(para, CRYPT_PARAM_RSA_N);
    if (n == NULL || n->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t nLen = n->valueLen;
    ret = BN_Bn2Bin(ctx->pubKey->n, n->value, &nLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    e->useLen = eLen;
    n->useLen = nLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_Cmp(const CRYPT_RSA_Ctx *a, const CRYPT_RSA_Ctx *b)
{
    RETURN_RET_IF(a == NULL || b == NULL, CRYPT_NULL_INPUT);

    RETURN_RET_IF(a->pubKey == NULL || b->pubKey == NULL, CRYPT_RSA_NO_KEY_INFO);

    RETURN_RET_IF(BN_Cmp(a->pubKey->n, b->pubKey->n) != 0 ||
                  BN_Cmp(a->pubKey->e, b->pubKey->e) != 0,
                  CRYPT_RSA_PUBKEY_NOT_EQUAL);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_GetSecBits(const CRYPT_RSA_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    int32_t bits = (int32_t)CRYPT_RSA_GetBits(ctx);
    return BN_SecBits(bits, -1);
}
#endif // HITLS_CRYPTO_RSA
