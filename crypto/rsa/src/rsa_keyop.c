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
    bool invalidIn = ctx == NULL || prv == NULL || prv->n == NULL || prv->d == NULL || prv->nLen == 0;
    if (invalidIn == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->nLen > RSA_MAX_MODULUS_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    // prv->p\q and prv->dP\dQ\qInv must be both empty or not.
    // If prv->p is empty, prv->dP must be empty.
    invalidIn = (prv->p == NULL) != (prv->q == NULL) || (prv->p == NULL && prv->dP != NULL) ||
        ((prv->dP == NULL || prv->dQ == NULL || prv->qInv == NULL) && (prv->dP || prv->dQ || prv->qInv));
    if (invalidIn == true) {
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

int32_t CRYPT_RSA_SetPrvKey(CRYPT_RSA_Ctx *ctx, const CRYPT_RsaPrv *prv)
{
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

    GOTO_ERR_IF(SetPrvPara(newCtx->prvKey, prv), ret);
    if (prv->p != NULL && prv->dP == NULL) {
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

int32_t CRYPT_RSA_SetPubKey(CRYPT_RSA_Ctx *ctx, const CRYPT_RsaPub *pub)
{
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
    bool nullInput = ctx == NULL || ctx->prvKey == NULL || prv == NULL || ((prv->p == NULL) != (prv->q == NULL)) ||
        ((prv->dP == NULL || prv->dQ == NULL || prv->qInv == NULL) && (prv->dP || prv->dQ || prv->qInv)) ||
        (prv->p == NULL && prv->dP != NULL);
    if (nullInput == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_GetPrvKey(const CRYPT_RSA_Ctx *ctx, CRYPT_RsaPrv *prv)
{
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

int32_t CRYPT_RSA_GetPubKey(const CRYPT_RSA_Ctx *ctx, CRYPT_RsaPub *pub)
{
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

#ifdef HITLS_BSL_PARAMS
int32_t CRYPT_RSA_SetPrvKeyEx(CRYPT_RSA_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_RsaPrv prv = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_N, &prv.n, &prv.nLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_D, &prv.d, &prv.dLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_E, &prv.e, &prv.eLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_P, &prv.p, &prv.pLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_Q, &prv.q, &prv.qLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_DP, &prv.dP, &prv.dPLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_DQ, &prv.dQ, &prv.dQLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_QINV, &prv.qInv, &prv.qInvLen);
    return CRYPT_RSA_SetPrvKey(ctx, &prv);
}

int32_t CRYPT_RSA_SetPubKeyEx(CRYPT_RSA_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_RsaPub pub = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_N, &pub.n, &pub.nLen);
    (void)GetConstParamValue(para, CRYPT_PARAM_RSA_E, &pub.e, &pub.eLen);
    return CRYPT_RSA_SetPubKey(ctx, &pub);
}

int32_t CRYPT_RSA_GetPrvKeyEx(const CRYPT_RSA_Ctx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_RsaPrv prv =  {0};
    BSL_Param *paramN = GetParamValue(para, CRYPT_PARAM_RSA_N, &prv.n, &prv.nLen);
    BSL_Param *paramD = GetParamValue(para, CRYPT_PARAM_RSA_D, &prv.d, &prv.dLen);
    BSL_Param *paramE = GetParamValue(para, CRYPT_PARAM_RSA_E, &prv.e, &prv.eLen);
    BSL_Param *paramP = GetParamValue(para, CRYPT_PARAM_RSA_P, &prv.p, &prv.pLen);
    BSL_Param *paramQ = GetParamValue(para, CRYPT_PARAM_RSA_Q, &prv.q, &prv.qLen);
    BSL_Param *paramDP = GetParamValue(para, CRYPT_PARAM_RSA_DP, &prv.dP, &prv.dPLen);
    BSL_Param *paramDQ = GetParamValue(para, CRYPT_PARAM_RSA_DQ, &prv.dQ, &prv.dQLen);
    BSL_Param *paramQInv = GetParamValue(para, CRYPT_PARAM_RSA_QINV, &prv.qInv, &prv.qInvLen);
    int32_t ret = CRYPT_RSA_GetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramN->useLen = prv.nLen;
    paramD->useLen = prv.dLen;
    if (paramE != NULL) {
        paramE->useLen = prv.eLen;
    }
    if (paramP != NULL) {
        paramP->useLen = prv.pLen;
    }
    if (paramQ != NULL) {
        paramQ->useLen = prv.qLen;
    }
    if (paramDP != NULL) {
        paramDP->useLen = prv.dPLen;
    }
    if (paramDQ != NULL) {
        paramDQ->useLen = prv.dQLen;
    }
    if (paramQInv != NULL) {
        paramQInv->useLen = prv.qInvLen;
    }
    return ret;
}

int32_t CRYPT_RSA_GetPubKeyEx(const CRYPT_RSA_Ctx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_RsaPub pub =  {0};
    BSL_Param *paramN = GetParamValue(para, CRYPT_PARAM_RSA_N, &pub.n, &pub.nLen);
    BSL_Param *paramE = GetParamValue(para, CRYPT_PARAM_RSA_E, &pub.e, &pub.eLen);
    int32_t ret = CRYPT_RSA_GetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramN->useLen = pub.nLen;
    paramE->useLen = pub.eLen;
    return ret;
}
#endif

#ifdef HITLS_CRYPTO_RSA_CMP
int32_t CRYPT_RSA_Cmp(const CRYPT_RSA_Ctx *a, const CRYPT_RSA_Ctx *b)
{
    RETURN_RET_IF(a == NULL || b == NULL, CRYPT_NULL_INPUT);

    if (a->pubKey != NULL && b->pubKey != NULL) {
        RETURN_RET_IF(BN_Cmp(a->pubKey->n, b->pubKey->n) != 0 ||
                      BN_Cmp(a->pubKey->e, b->pubKey->e) != 0,
                      CRYPT_RSA_PUBKEY_NOT_EQUAL);
        return CRYPT_SUCCESS;
    }
    if (a->prvKey != NULL && b->pubKey != NULL) {
        RETURN_RET_IF(BN_Cmp(a->prvKey->n, b->pubKey->n) != 0 ||
                      BN_Cmp(a->prvKey->e, b->pubKey->e) != 0,
                      CRYPT_RSA_PUBKEY_NOT_EQUAL);
        return CRYPT_SUCCESS;
    }
    if (a->pubKey != NULL && b->prvKey != NULL) {
        RETURN_RET_IF(BN_Cmp(a->pubKey->n, b->prvKey->n) != 0 ||
                      BN_Cmp(a->pubKey->e, b->prvKey->e) != 0,
                      CRYPT_RSA_PUBKEY_NOT_EQUAL);
        return CRYPT_SUCCESS;
    }
    return CRYPT_RSA_NO_KEY_INFO;
}
#endif

int32_t CRYPT_RSA_GetSecBits(const CRYPT_RSA_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    int32_t bits = (int32_t)CRYPT_RSA_GetBits(ctx);
    return BN_SecBits(bits, -1);
}

#ifdef HITLS_CRYPTO_RSA_CHECK

#define RSA_CHECK_PQ_RECOVER 1 // recover p q and check.
#define RSA_CHECK_PQD_CHECK 2 // check prime p q
#define RSA_CHECK_CRT_CHECK 3 // check crt

// m = 2^t * r, m != 0. cal Max(t) and bn = m / 2^t.
static void CalMaxT(BN_BigNum *bn, uint32_t *res)
{
    uint32_t t = 0;
    while (BN_GetBit(bn, t) == false) {
        t++;
    }
    *res = t;
    (void)BN_Rshift(bn, bn, t); // bn will decrease, and the memory will definitely be sufficient
    return;
}

static int32_t BasicKeypairCheck(const CRYPT_RSA_PubKey *pubKey, const CRYPT_RSA_PrvKey *prvKey)
{
    if (pubKey->n == NULL || pubKey->e == NULL) {
        return CRYPT_RSA_ERR_NO_PUBKEY_INFO;
    }
    // Currently, the check for p and q being null is not supported.
    if (prvKey->n == NULL || prvKey->d == NULL) {
        return CRYPT_RSA_ERR_NO_PRVKEY_INFO;
    }
    uint32_t eBits1 = BN_Bits(pubKey->e); // not check e == NULL repeatedly.
    uint32_t eBits2 = BN_Bits(prvKey->e); // prvKey->e can be empty, unless in crt mode
    // e <= 2^16 or e >= 2^256 -> e shoule be [17, 256].
    bool flag = (eBits2 != 0 && eBits2 != eBits1) || eBits1 < 17 || eBits1 > 256 || !BN_IsOdd(pubKey->e);
    if (flag == true) {
        return CRYPT_RSA_ERR_E_VALUE;
    }
    uint32_t nBbits = BN_Bits(pubKey->n);
    if (nBbits % 2 != 0) { // mod 2 to check nBits is a positive even integer or not.
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    int32_t ret = BN_Cmp(pubKey->n, prvKey->n); // If n_pub != n_priv
    if (ret != 0) { // not equal
        return CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
    }
    ret = BN_SecBits((int32_t)nBbits, -1); // no need to consider prvLen.
    /* SP800-56B requires that its should in the interval [112, 256]
     * Because the current rsa specification supports 1024 bits, so the lower limit is 80. */
    if (ret < 80 || ret > 256) {
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}

/*
 * if lower < p < upper, return success, otherwise return error.
 */
static int32_t RangeCheck(const BN_BigNum *lower, const BN_BigNum *p, const BN_BigNum *upper)
{
    int32_t ret = BN_Cmp(lower, p);
    if (ret >= 0) {
        return CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
    }
    ret = BN_Cmp(p, upper);
    if (ret >= 0) {
        return CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
    }
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_SP800_STRICT_CHECK
/*
 * if (p < √2)(2nBits/2−1)) or (p > 2nBits/2 – 1), return error.
*/
static int32_t FactorPQcheck(const BN_BigNum *e, const BN_BigNum *p, const BN_BigNum *n1, const BN_BigNum *n2,
    BN_Optimizer *opt)
{
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *pSqr = OptimizerGetBn(opt, p->size);
    BN_BigNum *tmp = OptimizerGetBn(opt, p->size);
    if (tmp == NULL || pSqr == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    GOTO_ERR_IF(BN_Sqr(pSqr, p, opt), ret);
    if (BN_Cmp(pSqr, n1) < 0) { // check (p < (√2)(2^(nBits/2−1))
        ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (BN_Cmp(p, n2) > 0) { // check (p > (2^(nBits - 1)))
        ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_SubLimb(tmp, p, 1), ret);
    GOTO_ERR_IF(BN_Gcd(tmp, e, tmp, opt), ret); // check gcd(p-1, e_pub) != 1
    if (!BN_IsOne(tmp)) {
        ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    OptimizerEnd(opt);
    return ret;
}
#endif

static int32_t FactorPrimeCheck(const BN_BigNum *n, const BN_BigNum *e, const BN_BigNum *p, const BN_BigNum *q,
    BN_Optimizer *opt)
{
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t nBits = BN_Bits(n);
    uint32_t checkTimes = nBits < 1536 ? 5 : 4; // ref. FIPS 186-5, Table B.1
    uint32_t needRoom = nBits / BN_UINT_BITS;
    BN_BigNum *tmp1 = OptimizerGetBn(opt, needRoom);
    BN_BigNum *tmp2 = OptimizerGetBn(opt, needRoom);
    if (tmp1 == NULL || tmp2 == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    GOTO_ERR_IF(BN_Mul(tmp1, p, q, opt), ret);
    if (BN_Cmp(tmp1, n) != 0) { // if n_pub != p * q.
        ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE);
        goto ERR;
    }

#ifdef HITLS_CRYPTO_SP800_STRICT_CHECK
    // get ((√2)(2^(nBits/2 - 1)))^2
    (void)BN_SetLimb(tmp1, 1);
    GOTO_ERR_IF(BN_Lshift(tmp1, tmp1, nBits - 2), ret); // secLen can guarantee nBits > 2.
    GOTO_ERR_IF(BN_Add(tmp1, tmp1, tmp1), ret);

    // get 2^(nBits/2) - 1.
    (void)BN_SetLimb(tmp2, 1);
    GOTO_ERR_IF(BN_Lshift(tmp2, tmp2, nBits << 1), ret);
    GOTO_ERR_IF(BN_SubLimb(tmp2, tmp2, 1), ret);

    GOTO_ERR_IF(FactorPQcheck(e, p, tmp1, tmp2, opt), ret);
    GOTO_ERR_IF(FactorPQcheck(e, q, tmp1, tmp2, opt), ret);
#else
    (void)e;
#endif
    GOTO_ERR_IF(BN_Sub(tmp1, p, q), ret);
    (void)BN_SetSign(tmp1, false); // tmp1 = |p - q|
    (void)BN_SetLimb(tmp2, 1);
    GOTO_ERR_IF(BN_Lshift(tmp2, tmp2, (nBits >> 1) - 100), ret); // 2^(nBits/2 - 100)
    if (BN_Cmp(tmp1, tmp2) <= 0) { // check |p - q| <= (2^(nBits/2 - 100))
        ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_PrimeCheck(p, checkTimes, opt, NULL);
    if (ret != CRYPT_SUCCESS) {
        if (ret == CRYPT_BN_NOR_CHECK_PRIME) {
            ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
    }
    ret = BN_PrimeCheck(q, checkTimes, opt, NULL);
    if (ret != CRYPT_SUCCESS) {
        if (ret == CRYPT_BN_NOR_CHECK_PRIME) {
            ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
            BSL_ERR_PUSH_ERROR(ret);
        }
    }
ERR:
    OptimizerEnd(opt);
    return ret;
}

static int32_t FactorDCheck(const BN_BigNum *n, const BN_BigNum *e, const BN_BigNum *p, const BN_BigNum *q,
    const BN_BigNum *d, BN_Optimizer *opt)
{
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t nBits = BN_Bits(n);
    uint32_t needRoom = nBits / BN_UINT_BITS;
    BN_BigNum *tmp0 = OptimizerGetBn(opt, needRoom);
    BN_BigNum *tmp1 = OptimizerGetBn(opt, needRoom);
    BN_BigNum *tmp2 = OptimizerGetBn(opt, needRoom);
    if (tmp0 == NULL || tmp1 == NULL || tmp2 == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    // get 2^(nBits / 2)
    (void)BN_SetLimb(tmp0, 1);
    GOTO_ERR_IF(BN_Lshift(tmp0, tmp0, nBits >> 1), ret);

    GOTO_ERR_IF(BN_SubLimb(tmp1, p, 1), ret);
    GOTO_ERR_IF(BN_SubLimb(tmp2, q, 1), ret);
    // tmp1 = LCM(p – 1, q – 1)
    GOTO_ERR_IF(BN_Lcm(tmp1, tmp1, tmp2, opt), ret);
#ifdef HITLS_CRYPTO_SP800_STRICT_CHECK
    // In the original RSA paper <A Method for Obtaining Digital Signatures and Public-Key Cryptosystems>,
    // the Euler totient function is φ(n) = (p – 1)(q – 1), hence d < LCM(p – 1, q – 1) will be incompatible.
    // check 2^(nBits / 2) < d < LCM(p – 1, q – 1).
    GOTO_ERR_IF(RangeCheck(tmp0, d, tmp1), ret);
#endif
    GOTO_ERR_IF(BN_Mul(tmp0, e, d, opt), ret);
    GOTO_ERR_IF(BN_Mod(tmp2, tmp0, tmp1, opt), ret);
    // check. 1 = (d * epub) mod LCM(p – 1, q – 1).
    if (!BN_IsOne(tmp2)) {
        ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    OptimizerEnd(opt);
    return ret;
}

/*
 * Recover prime factors p and q from n, e, and d.
 * ref SP800.56b Appendix C
*/
static int32_t RecoverPrimeFactorsAndCheck(const CRYPT_RSA_Ctx *pubKey, const CRYPT_RSA_Ctx *prvKey,
    BN_Optimizer *opt)
{
    int ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bool flag = false;
    uint32_t tFactor;
    uint32_t nBits = BN_Bits(pubKey->pubKey->n);
    uint32_t needRoom = nBits / BN_UINT_BITS;
    BN_BigNum *g = OptimizerGetBn(opt, needRoom);
    BN_BigNum *x = OptimizerGetBn(opt, needRoom);
    BN_BigNum *y = OptimizerGetBn(opt, needRoom);
    BN_BigNum *nSubOne = OptimizerGetBn(opt, needRoom);
    BN_BigNum *p = OptimizerGetBn(opt, needRoom);
    BN_BigNum *q = OptimizerGetBn(opt, needRoom);
    BN_BigNum *r = OptimizerGetBn(opt, needRoom);
    if (g == NULL || x == NULL || y == NULL || nSubOne == NULL || p == NULL || q == NULL || r == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    GOTO_ERR_IF(BN_SubLimb(nSubOne, pubKey->pubKey->n, 1), ret); // n - 1
    // step 1: compute r = d * e - 1
    GOTO_ERR_IF(BN_Mul(r, prvKey->prvKey->d, pubKey->pubKey->e, opt), ret); // d * e
    GOTO_ERR_IF(BN_SubLimb(r, r, 1), ret); // d * e - 1
    if (BN_IsOdd(r)) {
        ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // step 2: find t and m = (2^t) * r, r is the largest odd integer.
    CalMaxT(r, &tFactor); // r = m / 2^t
    // step 3: find prime factors p and q.
    for (uint32_t i = 0; i < 100; i++) { // try 100 times
        GOTO_ERR_IF(BN_RandRangeEx(LIBCTX_FROM_RSA_CTX(pubKey), g, pubKey->pubKey->n), ret); // rand(0, n)
        GOTO_ERR_IF(BN_ModExp(y, g, r, pubKey->pubKey->n, opt), ret); // y = g ^ r % n
        if (BN_IsOne(y) == true || BN_Cmp(y, nSubOne) == 0) { // y == 1 or y == n - 1
            continue;
        }
        for (uint32_t j = 1; j < tFactor; j++) { // 1 -> t - 1
            GOTO_ERR_IF(BN_ModSqr(x, y, pubKey->pubKey->n, opt), ret); // y ^ 2 mod n
            if (BN_IsOne(x) == true) {
                flag = true;
                break;
            }
            if (BN_Cmp(x, nSubOne) == 0) {
                continue;
            }
            GOTO_ERR_IF(BN_Copy(y, x), ret); // update y.
        }
        GOTO_ERR_IF(BN_ModSqr(x, y, pubKey->pubKey->n, opt), ret); // y ^ 2 mod n
        if (BN_IsOne(x) == true) {
            flag = true;
            break;
        }
    }
    // step 4: check if flag is true.
    if (!flag) {
        ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_SubLimb(y, y, 1), ret); // y - 1
    // step 5: compute p = gcd(y, n) and q = n / p.
    GOTO_ERR_IF(BN_Gcd(p, y, pubKey->pubKey->n, opt), ret); // p = gcd(y, n)
    GOTO_ERR_IF(BN_Div(q, NULL, pubKey->pubKey->n, p, opt), ret); // q = n / p
    GOTO_ERR_IF(FactorPrimeCheck(pubKey->pubKey->n, pubKey->pubKey->e, p, q, opt), ret);
    GOTO_ERR_IF(FactorDCheck(pubKey->pubKey->n, pubKey->pubKey->e, p, q, prvKey->prvKey->d, opt), ret);
ERR:
    OptimizerEnd(opt);
    return ret;
}

static int32_t FactorCRTCheck(const CRYPT_RSA_PrvKey *prvKey, BN_Optimizer *opt)
{
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t nBits = BN_Bits(prvKey->n);
    uint32_t needRoom = nBits / BN_UINT_BITS;
    BN_BigNum *pMinusOne = OptimizerGetBn(opt, needRoom);
    BN_BigNum *qMinusOne = OptimizerGetBn(opt, needRoom);
    BN_BigNum *one = OptimizerGetBn(opt, needRoom);
    if (pMinusOne == NULL || qMinusOne == NULL || one == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    GOTO_ERR_IF(BN_SubLimb(pMinusOne, prvKey->p, 1), ret); // p - 1
    GOTO_ERR_IF(BN_SubLimb(qMinusOne, prvKey->q, 1), ret); // q - 1
    (void)BN_SetLimb(one, 1);
    GOTO_ERR_IF(RangeCheck(one, prvKey->dP, pMinusOne), ret); // 1 < dP < (p – 1).
    GOTO_ERR_IF(RangeCheck(one, prvKey->dQ, qMinusOne), ret); // 1 < dQ < (q – 1).
    GOTO_ERR_IF(RangeCheck(one, prvKey->qInv, prvKey->p), ret); // 1 < qInv < p.

    GOTO_ERR_IF(BN_ModMul(pMinusOne, prvKey->dP, prvKey->e, pMinusOne, opt), ret); // (dP * e) mod (p - 1)
    GOTO_ERR_IF(BN_ModMul(qMinusOne, prvKey->dQ, prvKey->e, qMinusOne, opt), ret); // (dQ * e) mod (q - 1)
    GOTO_ERR_IF(BN_ModMul(one, prvKey->qInv, prvKey->q, prvKey->p, opt), ret); // (qInv * q) mod p
    if (!BN_IsOne(pMinusOne) || !BN_IsOne(qMinusOne) || !BN_IsOne(one)) {
        ret = CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    OptimizerEnd(opt);
    return ret;
}

static int32_t CheckLevel(const CRYPT_RSA_PrvKey *prvKey)
{
    if (!BN_IsZero(prvKey->e) && !BN_IsZero(prvKey->dP) && !BN_IsZero(prvKey->dQ) && !BN_IsZero(prvKey->qInv) &&
        !BN_IsZero(prvKey->p) && !BN_IsZero(prvKey->q)) {
        return RSA_CHECK_CRT_CHECK; // check crt.
    }
    if (!BN_IsZero(prvKey->p) && !BN_IsZero(prvKey->q)) {
        return RSA_CHECK_PQD_CHECK; // check prime p q.
    }
    return RSA_CHECK_PQ_RECOVER; // recover p q and check.
}

/*
 * ref. SP800-56B 6.4.3.1 RSA Key-Pair Validation (Random Public Exponent)
 */
static int32_t RsaKeyPairCheck(const CRYPT_RSA_Ctx *pubKey, const CRYPT_RSA_Ctx *prvKey)
{
    if (pubKey == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_NO_PUBKEY_INFO);
        return CRYPT_RSA_ERR_NO_PUBKEY_INFO;
    }
    if (prvKey->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_NO_PRVKEY_INFO);
        return CRYPT_RSA_ERR_NO_PRVKEY_INFO;
    }
    /* basic check */
    int32_t ret = BasicKeypairCheck(pubKey->pubKey, prvKey->prvKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)BN_OptimizerSetLibCtx(pubKey->libCtx, opt);
    switch (CheckLevel(prvKey->prvKey)) {
        case RSA_CHECK_PQ_RECOVER:
            ret = RecoverPrimeFactorsAndCheck(pubKey, prvKey, opt);
            break;
        case RSA_CHECK_PQD_CHECK:
            /* prime p q check */
            ret = FactorPrimeCheck(pubKey->pubKey->n, pubKey->pubKey->e, prvKey->prvKey->p, prvKey->prvKey->q, opt);
            if (ret != CRYPT_SUCCESS) {
                goto ERR;
            }
            /* factor d check */
            ret = FactorDCheck(pubKey->pubKey->n, pubKey->pubKey->e, prvKey->prvKey->p, prvKey->prvKey->q,
                prvKey->prvKey->d, opt);
            break;
        default:
            /* prime p q check */
            ret = FactorPrimeCheck(pubKey->pubKey->n, pubKey->pubKey->e, prvKey->prvKey->p, prvKey->prvKey->q, opt);
            if (ret != CRYPT_SUCCESS) {
                goto ERR;
            }
            /* factor d check */
            ret = FactorDCheck(pubKey->pubKey->n, pubKey->pubKey->e, prvKey->prvKey->p, prvKey->prvKey->q,
                prvKey->prvKey->d, opt);
            if (ret != CRYPT_SUCCESS) {
                goto ERR;
            }
            ret = FactorCRTCheck(prvKey->prvKey, opt); /* factor crt check */
            break;
    }
ERR:
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t RsaPrvKeyCheck(const CRYPT_RSA_Ctx *pkey)
{
    if (pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_NO_PRVKEY_INFO);
        return CRYPT_RSA_ERR_NO_PRVKEY_INFO;
    }
    if (pkey->prvKey->n == NULL || pkey->prvKey->d == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_NO_PRVKEY_INFO);
        return CRYPT_RSA_ERR_NO_PRVKEY_INFO;
    }
    if (BN_IsZero(pkey->prvKey->n) || BN_IsZero(pkey->prvKey->d)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INVALID_PRVKEY);
        return CRYPT_RSA_ERR_INVALID_PRVKEY;
    }
    if (BN_Cmp(pkey->prvKey->n, pkey->prvKey->d) <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INVALID_PRVKEY);
        return CRYPT_RSA_ERR_INVALID_PRVKEY;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RSA_Check(uint32_t checkType, const CRYPT_RSA_Ctx *pkey1, const CRYPT_RSA_Ctx *pkey2)
{
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            return RsaKeyPairCheck(pkey1, pkey2);
        case CRYPT_PKEY_CHECK_PRVKEY:
            return RsaPrvKeyCheck(pkey1);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}

#endif // HITLS_CRYPTO_RSA_CHECK

#endif // HITLS_CRYPTO_RSA
