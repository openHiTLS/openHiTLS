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


static int32_t SetPrvPara(const CRYPT_RSA_PrvKey *prvKey, const CRYPT_RsaPrv *prv)
{
    int32_t ret = BN_Bin2Bn(prvKey->n, prv->n, prv->nLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t bnBits = BN_Bits(prvKey->n);
    if (bnBits > RSA_MAX_MODULUS_BITS || bnBits < RSA_MIN_MODULUS_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    ret = BN_Bin2Bn(prvKey->d, prv->d, prv->dLen);
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
    if (prv->e != NULL) {
        ret = BN_Bin2Bn(prvKey->e, prv->e, prv->eLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (BN_Cmp(prvKey->n, prvKey->e) <= 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
            return CRYPT_RSA_ERR_INPUT_VALUE;
        }
    }
    if (prv->p != NULL) {
        GOTO_ERR_IF_EX(BN_Bin2Bn(prvKey->p, prv->p, prv->pLen), ret);
        GOTO_ERR_IF_EX(BN_Bin2Bn(prvKey->q, prv->q, prv->qLen), ret);
        if (BN_IsZero(prvKey->p) == true || BN_IsZero(prvKey->q) == true) {
            BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
            return CRYPT_RSA_ERR_INPUT_VALUE;
        }
        if (prv->dP != NULL) {
            GOTO_ERR_IF_EX(BN_Bin2Bn(prvKey->dP, prv->dP, prv->dPLen), ret);
            GOTO_ERR_IF_EX(BN_Bin2Bn(prvKey->dQ, prv->dQ, prv->dQLen), ret);
            GOTO_ERR_IF_EX(BN_Bin2Bn(prvKey->qInv, prv->qInv, prv->qInvLen), ret);
        }
    }
ERR:
    return ret;
}

// If n and d are not NULL, p and q are optional. If p and q exist, qInv, dP, and dQ need to be calculated.
static int32_t SetPrvBasicCheck(const CRYPT_RSA_Ctx *ctx, const CRYPT_RsaPrv *prv)
{
    if (ctx == NULL || prv == NULL || prv->n == NULL || prv->d == NULL || prv->nLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->nLen > RSA_MAX_MODULUS_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    // prv->p\q and prv->dP\dQ\qInv must be both empty or not.
    // If prv->p is empty, prv->dP must be empty.
    if ((prv->p == NULL) != (prv->q == NULL) || (prv->p == NULL && prv->dP != NULL) ||
        ((prv->dP == NULL || prv->dQ == NULL || prv->qInv == NULL) && (prv->dP || prv->dQ || prv->qInv))) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    return CRYPT_SUCCESS;
}

static int32_t SetPrvBnLenCheck(const CRYPT_RsaPrv *prv)
{
    /* The length of n is used as the length of a BigNum. The lengths of d, p, and q are not greater than n. */
    uint32_t bnBytes = prv->nLen;
    if (prv->dLen > bnBytes || prv->pLen > bnBytes || prv->qLen > bnBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_SetPrvKey(CRYPT_RSA_Ctx *ctx, const CRYPT_Param *para)
{
    CRYPT_RsaPrv *prv = (CRYPT_RsaPrv *)para->param;
    int32_t ret = SetPrvBasicCheck(ctx, prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = SetPrvBnLenCheck(prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_RSA_Ctx *newCtx = CRYPT_RSA_NewCtx();
    if (newCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    newCtx->prvKey = RSA_NewPrvKey(prv->nLen * 8); // Bit length is obtained by multiplying byte length by 8.
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
    if (prv->p != NULL && prv->dP == NULL) {
        BN_Optimizer *optimizer = BN_OptimizerCreate();
        if (optimizer == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        ret = RSA_CalcPrvKey(newCtx, optimizer);
        if (ret != CRYPT_SUCCESS) {
            BN_OptimizerDestroy(optimizer);
            goto ERR;
        }
        BN_OptimizerDestroy(optimizer);
    }

    RSA_FREE_PRV_KEY(ctx->prvKey);
    RSA_BlindFreeCtx(ctx->blind);

    ctx->prvKey = newCtx->prvKey;
    ctx->blind = newCtx->blind;
    ctx->pad = newCtx->pad;

    BSL_SAL_FREE(newCtx);
    return ret;
ERR:
    CRYPT_RSA_FreeCtx(newCtx);
    return ret;
}

static int32_t SetPubBasicCheck(const CRYPT_RSA_Ctx *ctx, const CRYPT_RsaPub *pub)
{
    if (ctx == NULL || pub == NULL || pub->n == NULL || pub->e == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->nLen > RSA_MAX_MODULUS_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    /* The length of n is used as the length of a BigNum, and the length of e is not greater than n. */
    if (pub->eLen > pub->nLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_SetPubKey(CRYPT_RSA_Ctx *ctx, const CRYPT_Param *para)
{
    CRYPT_RsaPub *pub = (CRYPT_RsaPub *)para->param;
    int32_t ret = SetPubBasicCheck(ctx, pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t bnBits;
    CRYPT_RSA_PubKey *newPub = NULL;
    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    /* Bit length is obtained by multiplying byte length by 8. */
    newPub = RSA_NewPubKey(pub->nLen * 8);
    if (newPub == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->n, pub->n, pub->nLen), ret);
    bnBits = BN_Bits(newPub->n);
    if (bnBits > RSA_MAX_MODULUS_BITS || bnBits < RSA_MIN_MODULUS_BITS) {
        ret = CRYPT_RSA_ERR_KEY_BITS;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Bin2Bn(newPub->e, pub->e, pub->eLen), ret);
    if (pub->nLen > RSA_SMALL_MODULUS_BYTES && BN_Bytes(newPub->e) > RSA_MAX_PUBEXP_BYTES) {
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

static int32_t GetPrvBasicCheck(const CRYPT_RSA_Ctx *ctx, const CRYPT_RsaPrv *prv)
{
    // ctx\ctx->prvKey\prv is not empty.
    // prv->p\q and prv->dP\dQ\qInv are both null or non-null.
    // If prv->p is empty, prv->dP is empty.
    if (ctx == NULL || ctx->prvKey == NULL || prv == NULL || ((prv->p == NULL) != (prv->q == NULL)) ||
        ((prv->dP == NULL || prv->dQ == NULL || prv->qInv == NULL) && (prv->dP || prv->dQ || prv->qInv)) ||
        (prv->p == NULL && prv->dP != NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_GetPrvKey(const CRYPT_RSA_Ctx *ctx, CRYPT_Param *para)
{
    CRYPT_RsaPrv *prv = (CRYPT_RsaPrv *)para->param;
    int32_t ret = GetPrvBasicCheck(ctx, prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->n, prv->n, &prv->nLen), ret);
    GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->d, prv->d, &prv->dLen), ret);
    if (prv->e != NULL) {
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->e, prv->e, &prv->eLen), ret);
    }
    if (prv->p != NULL) {
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->p, prv->p, &prv->pLen), ret);
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->q, prv->q, &prv->qLen), ret);
    }
    if (prv->dQ != NULL) {
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->dQ, prv->dQ, &prv->dQLen), ret);
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->dP, prv->dP, &prv->dPLen), ret);
        GOTO_ERR_IF(BN_Bn2Bin(ctx->prvKey->qInv, prv->qInv, &prv->qInvLen), ret);
    }
    return CRYPT_SUCCESS;

ERR:
    if (prv->d != NULL && prv->dLen != 0) {
        BSL_SAL_CleanseData(prv->d, prv->dLen);
    }
    if (prv->p != NULL && prv->pLen != 0) {
        BSL_SAL_CleanseData(prv->p, prv->pLen);
    }
    if (prv->q != NULL && prv->qLen != 0) {
        BSL_SAL_CleanseData(prv->q, prv->qLen);
    }
    if (prv->dQ != NULL && prv->dQLen != 0) {
        BSL_SAL_CleanseData(prv->dQ, prv->dQLen);
    }
    if (prv->dP != NULL && prv->dPLen != 0) {
        BSL_SAL_CleanseData(prv->dP, prv->dPLen);
    }
    if (prv->qInv != NULL && prv->qInvLen != 0) {
        BSL_SAL_CleanseData(prv->qInv, prv->qInvLen);
    }
    return ret;
}

int32_t CRYPT_RSA_GetPubKey(const CRYPT_RSA_Ctx *ctx, CRYPT_Param *para)
{
    CRYPT_RsaPub *pub = (CRYPT_RsaPub *)para->param;
    if (ctx == NULL || ctx->pubKey == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = BN_Bn2Bin(ctx->pubKey->e, pub->e, &pub->eLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Bn2Bin(ctx->pubKey->n, pub->n, &pub->nLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
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
    return BN_SecBit(bits, -1);
}
#endif // HITLS_CRYPTO_RSA
