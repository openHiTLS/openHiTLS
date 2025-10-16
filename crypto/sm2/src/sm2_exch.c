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
#if defined(HITLS_CRYPTO_SM2_EXCH) || defined(HITLS_CRYPTO_SM2_CRYPT)

#include <stdbool.h>
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_bn.h"
#include "crypt_ecc.h"
#include "crypt_ecc_pkey.h"
#include "crypt_local_types.h"
#include "crypt_sm2.h"
#include "sm2_local.h"

/*  GM/T003_2012 Defined Key Derive Function  */
int32_t KdfGmt0032012(uint8_t *out, const uint32_t *outlen, const uint8_t *z, uint32_t zlen,
    const EAL_MdMethod *hashMethod)
{
    if (out == NULL || outlen == NULL || *outlen == 0 || (z == NULL && zlen != 0)  ||  hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t counter;
    uint8_t ctr[4];
    uint32_t mdlen;
    int32_t ret;
    uint32_t len = MAX_MD_SIZE;
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    uint8_t dgst[MAX_MD_SIZE];
    uint8_t *tmp = out;
    uint32_t tmplen = *outlen;
    if (mdCtx == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    mdlen = (uint32_t)hashMethod->mdSize;
    for (counter = 1;; counter++) {
        GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
        PUT_UINT32_BE(counter, ctr, 0);
        GOTO_ERR_IF(hashMethod->update(mdCtx, z, zlen), ret);
        GOTO_ERR_IF(hashMethod->update(mdCtx, ctr, sizeof(ctr)), ret);
        GOTO_ERR_IF(hashMethod->final(mdCtx, dgst, &len), ret);
        if (tmplen > mdlen) {
            (void)memcpy_s(tmp, tmplen, dgst, mdlen);
            tmp += mdlen;
            tmplen -= mdlen;
        } else {
            (void)memcpy_s(tmp, tmplen, dgst, tmplen);
            (void)memset_s(dgst, mdlen, 0, mdlen);
            break;
        }
    }
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

void Sm2CleanR(CRYPT_SM2_Ctx *ctx)
{
    BN_Destroy(ctx->r);
    ctx->r = NULL;
    ECC_FreePoint(ctx->pointR);
    ctx->pointR = NULL;
    return;
}

static int32_t Sm2CalculateKey(const CRYPT_SM2_Ctx *selfCtx, const CRYPT_SM2_Ctx *peerCtx, ECC_Point *uorv,
    uint8_t *out, uint32_t *outlen)
{
    uint32_t keyBits = CRYPT_SM2_GetBits(selfCtx);
    uint32_t elementLen = (keyBits + 7) / 8; // Multiply keyBits by 8. Add 7 to round up the result.
    int32_t ret;
    uint32_t bufLen = elementLen * 2 + SM3_MD_SIZE * 2 + 1; /* add 1 byte tag; 2: 2 coordinates x and y, 2 z values */
    uint32_t dataLen = 0; // length of actual data;
    uint32_t curLen = 0; // length of buffer reserved for the current operation.
    uint8_t *buf = (uint8_t *)BSL_SAL_Calloc(bufLen, sizeof(uint8_t));
    if (buf == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    /* 1 : Get public key for uorv, Notice: the first byte is a tag, not a valid char */
    curLen = elementLen * 2 + 1; // add 1 byte tag; 2: 2 coordinates x and y
    GOTO_ERR_IF(ECC_EncodePoint(selfCtx->pkey->para, uorv, buf, &curLen, CRYPT_POINT_UNCOMPRESSED), ret);
    dataLen += curLen;
    if (selfCtx->server == 1) {
        /* SIDE A, Z_A || Z_B, server is initiator(Z_A), client is responder(Z_B) */
        curLen = SM3_MD_SIZE;
        GOTO_ERR_IF_EX(Sm2ComputeZDigest(selfCtx, buf + dataLen, &curLen), ret);
        dataLen += curLen;
    }
    /* Caculate Peer z */
    curLen = SM3_MD_SIZE;
    GOTO_ERR_IF_EX(Sm2ComputeZDigest(peerCtx, buf + dataLen, &curLen), ret);
    dataLen += curLen;
    if (selfCtx->server == 0) {
        /* SIDE B */
        curLen = SM3_MD_SIZE;
        GOTO_ERR_IF_EX(Sm2ComputeZDigest(selfCtx, buf + dataLen, &curLen), ret);
        dataLen += curLen;
    }
    GOTO_ERR_IF(KdfGmt0032012(out, outlen, (const uint8_t *)(buf + 1), dataLen - 1, selfCtx->hashMethod), ret);
ERR:
    BSL_SAL_FREE(buf);
    return ret;
}

static int32_t IsParamValid(const CRYPT_SM2_Ctx *selfCtx, const CRYPT_SM2_Ctx *peerCtx)
{
    if (selfCtx->pkey->prvkey == NULL || peerCtx->pkey->pubkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_EMPTY_KEY);
        return CRYPT_SM2_ERR_EMPTY_KEY;
    }

    if (selfCtx->hashMethod == NULL || peerCtx->hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_NO_HASH_METHOD);
        return CRYPT_SM2_ERR_NO_HASH_METHOD;
    }

    if (peerCtx->pointR == NULL || selfCtx->r == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_R_NOT_SET);
        return CRYPT_SM2_R_NOT_SET;
    }

    if (selfCtx->pkey->pubkey == NULL) {
        int32_t ret = ECC_GenPublicKey(selfCtx->pkey);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return CRYPT_SUCCESS;
}

void BnMemDestroy(BN_BigNum *xs, BN_BigNum *xp, BN_BigNum *t, BN_BigNum *twoPowerW, BN_BigNum *order)
{
    BN_Destroy(xs);
    BN_Destroy(xp);
    BN_Destroy(t);
    BN_Destroy(twoPowerW);
    BN_Destroy(order);
}

static int32_t Sm3MsgHash(const EAL_MdMethod *hashMethod, const uint8_t *yBuf, const uint8_t *hashBuf,
    uint8_t *out, uint32_t *outlen, uint8_t tag)
{
    int32_t ret;
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, &tag, 1), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, yBuf, SM3_MD_SIZE), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, hashBuf, SM3_MD_SIZE), ret);
    GOTO_ERR_IF(hashMethod->final(mdCtx, out, outlen), ret);
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

static int32_t Sm3InnerHash(const EAL_MdMethod *hashMethod, const uint8_t *coordinate, const uint8_t *zBuf,
    uint32_t zlen, const uint8_t *rBuf, uint8_t *out, uint32_t *outlen)
{
    int32_t ret;
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, coordinate, SM2_X_LEN), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, zBuf, zlen), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, rBuf, SM2_TWO_POINT_COORDINATE_LEN), ret);
    GOTO_ERR_IF(hashMethod->final(mdCtx, out, outlen), ret);
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

int32_t Sm2KapFinalCheck(CRYPT_SM2_Ctx *sCtx, CRYPT_SM2_Ctx *pCtx, ECC_Point *uorv)
{
    int32_t ret;
    uint32_t len = SM3_MD_SIZE;
    uint8_t r1Buf[SM2_POINT_COORDINATE_LEN];
    uint8_t r2Buf[SM2_POINT_COORDINATE_LEN];
    uint8_t rBuf[SM2_TWO_POINT_COORDINATE_LEN];
    uint8_t xBuf[SM2_X_LEN];
    uint8_t yBuf[SM2_X_LEN];
    uint8_t zBuf[SM2_POINT_COORDINATE_LEN - 1];
    uint8_t stmpBuf[SM3_MD_SIZE];
    uint32_t buflen = SM2_POINT_COORDINATE_LEN;
    uint32_t zlen = 0;
    uint8_t tag1 = 0x03;
    uint8_t tag2 = 0x02;
    // Xv
    GOTO_ERR_IF(ECC_EncodePoint(sCtx->pkey->para, uorv, r1Buf, &buflen, CRYPT_POINT_UNCOMPRESSED), ret);
    (void)memcpy_s(xBuf, SM2_X_LEN, r1Buf + 1, SM2_X_LEN);
    (void)memcpy_s(yBuf, SM2_X_LEN, r1Buf + 1 + SM2_X_LEN, SM2_X_LEN);
    // Calculate ZA || ZB
    if (sCtx->server == 1) {
        /* SIDE A, Z_A || Z_B, server is initiator(Z_A), client is responder(Z_B) */
        GOTO_ERR_IF_EX(Sm2ComputeZDigest(sCtx, zBuf, &len), ret);
        zlen += len;
        GOTO_ERR_IF(ECC_EncodePoint(sCtx->pkey->para, sCtx->pointR, r1Buf, &buflen, CRYPT_POINT_UNCOMPRESSED), ret);
        GOTO_ERR_IF(ECC_EncodePoint(sCtx->pkey->para, pCtx->pointR, r2Buf, &buflen, CRYPT_POINT_UNCOMPRESSED), ret);
    }
    /* Calculate Peer z  */
    GOTO_ERR_IF_EX(Sm2ComputeZDigest(pCtx, zBuf + zlen, &len), ret);
    zlen += len;
    if (sCtx->server == 0) {
        /* SIDE B */
        GOTO_ERR_IF_EX(Sm2ComputeZDigest(sCtx, zBuf + zlen, &len), ret);
        zlen += len;
        GOTO_ERR_IF(ECC_EncodePoint(sCtx->pkey->para, pCtx->pointR, r1Buf, &buflen, CRYPT_POINT_UNCOMPRESSED), ret);
        GOTO_ERR_IF(ECC_EncodePoint(sCtx->pkey->para, sCtx->pointR, r2Buf, &buflen, CRYPT_POINT_UNCOMPRESSED), ret);
        tag1 = 0x02;
        tag2 = 0x03;
    }
    (void)memcpy_s(rBuf, SM2_TWO_POINT_COORDINATE_LEN, r1Buf + 1, SM2_POINT_COORDINATE_LEN - 1);
    (void)memcpy_s(rBuf + SM2_POINT_COORDINATE_LEN - 1, SM2_TWO_POINT_COORDINATE_LEN - SM2_POINT_COORDINATE_LEN + 1,
        r2Buf + 1, SM2_POINT_COORDINATE_LEN - 1);
    // Calculate the hash value.
    GOTO_ERR_IF_EX(Sm3InnerHash(sCtx->hashMethod, xBuf, zBuf, zlen, rBuf, stmpBuf, &len), ret);
    // Calculate the hash value sent to the peer end.
    GOTO_ERR_IF_EX(Sm3MsgHash(sCtx->hashMethod, yBuf, stmpBuf, sCtx->sumSend, &len, tag1), ret);
    // Computes the hash value for validation
    GOTO_ERR_IF_EX(Sm3MsgHash(sCtx->hashMethod, yBuf, stmpBuf, sCtx->sumCheck, &len, tag2), ret);
    sCtx->isSumValid = 1;
    return ret;
ERR:
    sCtx->isSumValid = 0; // Reset checksum validity flag
    return ret;
}

static int SM2_PKG_Kdf(const CRYPT_SM2_Ctx *ctx, uint8_t *in, const uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    const uint32_t shareKeyLen = 16;
    const EAL_MdMethod *hashMethod = ctx->hashMethod;
    uint8_t *tmp = BSL_SAL_Malloc(hashMethod->mdSize);
    uint32_t tmpLen = hashMethod->mdSize;
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL || tmp == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, in, inLen), ret);
    GOTO_ERR_IF(hashMethod->final(mdCtx, tmp, &tmpLen), ret);
    if (memcpy_s(out, *outLen, tmp, shareKeyLen) != EOK) {
        ret = CRYPT_SECUREC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    *outLen = shareKeyLen;
ERR:
    hashMethod->freeCtx(mdCtx);
    BSL_SAL_ClearFree(tmp, hashMethod->mdSize);
    return ret;
}

static int32_t SM2_PKGComputeKey(const CRYPT_SM2_Ctx *selfCtx, const CRYPT_SM2_Ctx *peerCtx,
    uint8_t *out, uint32_t *outlen)
{
    if (selfCtx->pkey == NULL || peerCtx->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (selfCtx->hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_NO_HASH_METHOD);
        return CRYPT_SM2_ERR_NO_HASH_METHOD;
    }
    int32_t ret;
    uint8_t sharePointCode[65] = {0};
    uint32_t codeLen = sizeof(sharePointCode);
    const ECC_Pkey *eccPkey = selfCtx->pkey;
    BN_BigNum *tmpPrvkey = BN_Dup(eccPkey->prvkey);
    ECC_Point *sharePoint = ECC_NewPoint(eccPkey->para);
    if ((tmpPrvkey == NULL) || (sharePoint == NULL)) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(ECC_PointMul(eccPkey->para, sharePoint, eccPkey->prvkey, peerCtx->pkey->pubkey), ret);
    GOTO_ERR_IF(ECC_PointCheck(sharePoint), ret);
    GOTO_ERR_IF_EX(ECC_EncodePoint(eccPkey->para, sharePoint, sharePointCode, &codeLen, CRYPT_POINT_UNCOMPRESSED), ret);
    GOTO_ERR_IF_EX(SM2_PKG_Kdf(selfCtx, sharePointCode + 1, codeLen - 1, out, outlen), ret);
ERR:
    BN_Destroy(tmpPrvkey);
    ECC_FreePoint(sharePoint);
    return ret;
}

int32_t CRYPT_SM2_KapComputeKey(const CRYPT_SM2_Ctx *selfCtx, const CRYPT_SM2_Ctx *peerCtx,
    uint8_t *out, uint32_t *outlen)
{
    if (selfCtx == NULL || peerCtx == NULL || out == NULL || outlen == NULL || *outlen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (selfCtx->pkgImpl != 0) {
        return SM2_PKGComputeKey(selfCtx, peerCtx, out, outlen);
    }
    ECC_Point *uorv = ECC_NewPoint(selfCtx->pkey->para);
    uint32_t keyBits = CRYPT_SM2_GetBits(selfCtx);
    BN_BigNum *xs = BN_Create(keyBits);
    BN_BigNum *xp = BN_Create(keyBits);
    BN_BigNum *t = BN_Create(keyBits);
    BN_BigNum *twoPowerW = BN_Create(keyBits);
    BN_BigNum *order = ECC_GetParaN(selfCtx->pkey->para);
    uint32_t w;
    int32_t ret;
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (uorv == NULL || xs == NULL || xp == NULL || t == NULL || twoPowerW == NULL || order == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(IsParamValid(selfCtx, peerCtx), ret);
    /* Second: Caculate -- w */
    // w is equal to the number of digits of n rounded up, divided by 2, and then subtracted by 1.
    w = (BN_Bits(order) + 1) / 2 - 1;
    GOTO_ERR_IF(BN_Zeroize(twoPowerW), ret);
    GOTO_ERR_IF(BN_SetBit(twoPowerW, w), ret);
    /* Third: Caculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w) */
    /* Get x */
    GOTO_ERR_IF(ECC_GetPointDataX(selfCtx->pkey->para, selfCtx->pointR, xs), ret);
    GOTO_ERR_IF(ECC_GetPointDataX(peerCtx->pkey->para, peerCtx->pointR, xp), ret);
    /* x mod 2 ^ w */
    /* Caculate Self x */
    GOTO_ERR_IF(BN_Mod(xs, xs, twoPowerW, opt), ret);
    GOTO_ERR_IF(BN_Add(xs, xs, twoPowerW), ret);
    /* Caculate Peer x */
    GOTO_ERR_IF(BN_Mod(xp, xp, twoPowerW, opt), ret);
    GOTO_ERR_IF(BN_Add(xp, xp, twoPowerW), ret);
    /* Forth: Caculate t */
    GOTO_ERR_IF(BN_ModMul(t, xs, selfCtx->r, order, opt), ret);
    GOTO_ERR_IF(BN_ModAddQuick(t, t, selfCtx->pkey->prvkey, order, opt), ret);
    /* Fifth: Caculate V or U */
    GOTO_ERR_IF(ECC_PointMul(peerCtx->pkey->para, uorv, xp, peerCtx->pointR), ret);
    /* P + [x]R */
    GOTO_ERR_IF(ECC_PointAddAffine(selfCtx->pkey->para, uorv, uorv, peerCtx->pkey->pubkey), ret);
    GOTO_ERR_IF(ECC_PointMul(selfCtx->pkey->para, uorv, t, uorv), ret);
    /* Detect uorv is in */
    GOTO_ERR_IF(ECC_PointCheck(uorv), ret);
    /* Sixth: Caculate Key -- Need Xuorv, Yuorv, Zc, Zs, klen */
    GOTO_ERR_IF_EX(Sm2CalculateKey(selfCtx, peerCtx, uorv, out, outlen), ret);
    GOTO_ERR_IF_EX(Sm2KapFinalCheck((CRYPT_SM2_Ctx *)(uintptr_t)selfCtx, (CRYPT_SM2_Ctx *)(uintptr_t)peerCtx, uorv),
        ret);
ERR:
    BnMemDestroy(xs, xp, t, twoPowerW, order);
    ECC_FreePoint(uorv);
    Sm2CleanR((CRYPT_SM2_Ctx *)(uintptr_t)selfCtx);
    BN_OptimizerDestroy(opt);
    return ret;
}
#endif
