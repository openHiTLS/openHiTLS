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
#ifdef HITLS_CRYPTO_SM2_CRYPT
#include <limits.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_bn.h"
#include "crypt_ecc.h"
#include "crypt_ecc_pkey.h"
#include "crypt_local_types.h"
#include "sm2_local.h"
#include "crypt_sm2.h"
#include "crypt_encode.h"

static void EncryptMemFree(ECC_Point *c1, ECC_Point *tmp, BN_BigNum *k,
    BN_BigNum *order, uint8_t *c2)
{
    ECC_FreePoint(c1);
    ECC_FreePoint(tmp);
    BN_Destroy(k);
    BN_Destroy(order);
    BSL_SAL_FREE(c2);
}

static int32_t ParaCheckAndCalculate(CRYPT_SM2_Ctx *ctx, ECC_Point *tmp, BN_BigNum *k)
{
    int32_t ret;
    // Check whether [h]PB is equal to infinity point.
    GOTO_ERR_IF(ECC_PointCheck(ctx->pkey->pubkey), ret);
    // Calculate [k] * PB
    GOTO_ERR_IF(ECC_PointMul(ctx->pkey->para, tmp, k, ctx->pkey->pubkey), ret);
ERR:
    return ret;
}

static int32_t Sm3Hash(const EAL_MdMethod *hashMethod, const uint8_t *pbBuf, const uint8_t *data, uint32_t datalen,
    uint8_t *c3Buf, uint32_t *c3BufLen)
{
    int32_t ret;
    void *mdCtx = hashMethod->newCtx();
    if (mdCtx == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, pbBuf + 1,
        SM2_POINT_SINGLE_COORDINATE_LEN), ret); // Horizontal coordinate x2 of PB
    GOTO_ERR_IF(hashMethod->update(mdCtx, data, datalen), ret); // M
    GOTO_ERR_IF(hashMethod->update(mdCtx, pbBuf + SM2_POINT_SINGLE_COORDINATE_LEN + 1,
        SM2_POINT_SINGLE_COORDINATE_LEN), ret); // Vertical coordinate y2 of PB
    // Calculated c3, in c3Buf
    GOTO_ERR_IF(hashMethod->final(mdCtx, c3Buf, c3BufLen), ret);
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

static int32_t IsDataZero(const uint8_t *data, uint32_t datalen)
{
    uint8_t check = 0;
    for (uint32_t i = 0; i < datalen; i++) {
        check |= data[i];
    }
    if (check == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_DECRYPT_FAIL);
        return CRYPT_SM2_DECRYPT_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t MemAllocCheck(const BN_BigNum *k, const BN_BigNum *order,
    const ECC_Point *c1, const ECC_Point *tmp, const uint8_t *c2)
{
    int32_t ret;
    if (k == NULL || order == NULL || c1 == NULL || tmp == NULL || c2 == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static void XorCalculate(uint8_t *c2, const uint8_t *data, uint32_t datalen)
{
    uint32_t i;
    for (i = 0; i < datalen; ++i) {
        c2[i] ^= data[i];
    }
    return;
}

static int32_t EncryptInputCheck(const CRYPT_SM2_Ctx *ctx, const uint8_t *data, uint32_t datalen,
    const uint8_t *out, const uint32_t *outlen)
{
    int32_t ret;
    // 0-length plaintext encryption is not supported.
    if (ctx == NULL || data == NULL || datalen == 0 || out == NULL || outlen == NULL || *outlen == 0) {
        ret = CRYPT_NULL_INPUT;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint64_t tmpdatalen = ASN1_Sm2GetEnCodeLen(datalen);
    if ((uint64_t)*outlen < tmpdatalen || tmpdatalen > UINT32_MAX) {
        ret = CRYPT_SM2_BUFF_LEN_NOT_ENOUGH;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ctx->pkey == NULL) {
        ret = CRYPT_SM2_ERR_EMPTY_KEY;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ctx->pkey->pubkey == NULL) {
        ret = CRYPT_SM2_NO_PUBKEY;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM2_Encrypt(CRYPT_SM2_Ctx *ctx, const uint8_t *data, uint32_t datalen, uint8_t *out, uint32_t *outlen)
{
    int32_t ret = EncryptInputCheck(ctx, data, datalen, out, outlen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t keyBits = CRYPT_SM2_GetBits(ctx);
    uint32_t i;
    uint8_t *outTmp = BSL_SAL_Calloc(1u, SM2_POINT_COORDINATE_LEN + SM3_MD_SIZE + datalen);
    if (outTmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t outTmpLen = *outlen;
    BN_BigNum *k = BN_Create(keyBits);
    BN_BigNum *order = ECC_GetParaN(ctx->pkey->para);
    ECC_Point *c1 = ECC_NewPoint(ctx->pkey->para);
    ECC_Point *tmp = ECC_NewPoint(ctx->pkey->para);
    uint32_t buflen = SM2_POINT_COORDINATE_LEN;
    uint8_t c1Buf[SM2_POINT_COORDINATE_LEN];
    uint8_t tmpBuf[SM2_POINT_COORDINATE_LEN];
    uint8_t *c2 = BSL_SAL_Malloc(datalen);
    uint8_t c3Buf[SM3_MD_SIZE];
    uint32_t c3BufLen = SM3_MD_SIZE;
    GOTO_ERR_IF(MemAllocCheck(k, order, c1, tmp, c2), ret);
    for (i = 0; i < CRYPT_ECC_TRY_MAX_CNT; i++) {
        GOTO_ERR_IF(BN_RandRange(k, order), ret);
        if (BN_IsZero(k)) {
            continue;
        }
        // c1 = k * G
        GOTO_ERR_IF(ECC_PointMul(ctx->pkey->para, c1, k, NULL), ret);
        // Convert the point format into binary data stream and save the data stream in tmpbuf.
        GOTO_ERR_IF(ECC_EncodePoint(ctx->pkey->para, c1, c1Buf, &buflen, CRYPT_POINT_UNCOMPRESSED), ret);
        GOTO_ERR_IF(ParaCheckAndCalculate(ctx, tmp, k), ret);
        GOTO_ERR_IF(ECC_EncodePoint(ctx->pkey->para, tmp, tmpBuf, &buflen, CRYPT_POINT_UNCOMPRESSED), ret);
        // Calculate the kdf.
        GOTO_ERR_IF(KdfGmt0032012(c2, &datalen, tmpBuf + 1, buflen - 1, ctx->hashMethod), ret);
        if (IsDataZero(c2, datalen) == CRYPT_SUCCESS) {
            break;
        }
    }
    if (i == CRYPT_ECC_TRY_MAX_CNT) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_TRY_CNT);
        ret = CRYPT_SM2_ERR_TRY_CNT;
        goto ERR;
    }
    // Bitwise XOR
    XorCalculate(c2, data, datalen);
    // x2 || M || y2, calculate the hash value
    GOTO_ERR_IF(Sm3Hash(ctx->hashMethod, tmpBuf, data, datalen, c3Buf, &c3BufLen), ret);
    (void)memcpy_s(outTmp, outTmpLen, c1Buf, buflen); // c1
    (void)memcpy_s(outTmp + buflen, outTmpLen - buflen, c3Buf, c3BufLen); // c3
    (void)memcpy_s(outTmp + buflen + c3BufLen, outTmpLen - buflen - c3BufLen, c2, datalen); // c2
    outTmpLen = datalen + c3BufLen + buflen;
    // outTmp, outTmpLen need to offset 1 bytes for skipping first bits which indicating identifiers of ecc point code.
    GOTO_ERR_IF(ASN1_Sm2EncryptDataEncode(outTmp + 1, outTmpLen - 1, out, outlen), ret);
ERR:
    BSL_SAL_FREE(outTmp);
    EncryptMemFree(c1, tmp, k, order, c2);
    return ret;
}

static int32_t IsUEqualToC3(const uint8_t *data, const uint8_t *sm3Buf, uint32_t sm3BufLen)
{
    int32_t ret;
    uint8_t check = 0;
    for (uint32_t i = 0; i < sm3BufLen; i++) {
        check |= sm3Buf[i] ^ data[i + SM2_POINT_COORDINATE_LEN];
    }
    if (check != 0) {
        ret = CRYPT_SM2_DECRYPT_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static int32_t DecryptInputCheck(const CRYPT_SM2_Ctx *ctx, const uint8_t *data, const uint32_t datalen,
    const uint8_t *out, const uint32_t *outlen)
{
    int32_t ret;
    // 0-length plaintext decryption is not supported.
    if (ctx == NULL || data == NULL || datalen == 0 || out == NULL || outlen == NULL || *outlen == 0) {
        ret = CRYPT_NULL_INPUT;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ASN1_Sm2GetEnCodeLen(*outlen) < datalen) {
        ret = CRYPT_SM2_BUFF_LEN_NOT_ENOUGH;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ctx->pkey == NULL) {
        ret = CRYPT_SM2_ERR_EMPTY_KEY;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ctx->pkey->prvkey == NULL) {
        ret = CRYPT_SM2_NO_PRVKEY;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM2_Decrypt(CRYPT_SM2_Ctx *ctx, const uint8_t *data, uint32_t datalen, uint8_t *out, uint32_t *outlen)
{
    // take out the c1
    int32_t ret = DecryptInputCheck(ctx, data, datalen, out, outlen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t decodeLen = datalen - 1; // '04' requires one byte
    uint8_t *decode = BSL_SAL_Calloc(1u, datalen); // The decoded length will be smaller than the original length.
    if (decode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = ASN1_Sm2EncryptDataDecode(data, datalen, decode + 1, &decodeLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(decode);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    decode[0] = 0x04; // 0x04 indicate uncompressed.
    // add 1 for marking '0x40' in pubkey decoode
    uint32_t klen = decodeLen + 1 - SM2_POINT_COORDINATE_LEN - SM3_MD_SIZE;
    ECC_Point *c1 = ECC_NewPoint(ctx->pkey->para);
    ECC_Point *tmp = ECC_NewPoint(ctx->pkey->para);
    uint8_t sm3Buf[SM3_MD_SIZE];
    uint32_t sm3BufLen = SM3_MD_SIZE;
    uint32_t tmplen = SM2_POINT_COORDINATE_LEN;
    uint8_t tmpBuf[SM2_POINT_COORDINATE_LEN];
    uint8_t *t = BSL_SAL_Malloc(klen);
    if (c1 == NULL || tmp == NULL || t == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(ECC_DecodePoint(ctx->pkey->para, c1, decode, SM2_POINT_COORDINATE_LEN), ret);
    // Calculate [dB]C1 = (x2, y2) and save it to the point tmp.
    GOTO_ERR_IF(ECC_PointMul(ctx->pkey->para, tmp, ctx->pkey->prvkey, c1), ret);
    // Extract x and y of the point tmp and save them to tmpbuf.
    GOTO_ERR_IF(ECC_EncodePoint(ctx->pkey->para, tmp, tmpBuf, &tmplen, CRYPT_POINT_UNCOMPRESSED), ret);
    // Calculate kdf(x2 || y2, klen), klen is msglen
    GOTO_ERR_IF(KdfGmt0032012(t, &klen, tmpBuf + 1, tmplen - 1, ctx->hashMethod), ret);
    // Check whether t is all 0s. If yes, report an error and exit.
    GOTO_ERR_IF(IsDataZero(t, klen), ret);
    // Calculate M' = C2 ^ t
    // Bitwise XOR, and the result is still stored in t.
    for (uint32_t i = 0; i < klen; ++i) {
        t[i] ^= decode[i + SM2_POINT_COORDINATE_LEN + SM3_MD_SIZE];
    }
    // Calculate hash（x2 || t || y2)
    GOTO_ERR_IF(Sm3Hash(ctx->hashMethod, tmpBuf, t, klen, sm3Buf, &sm3BufLen), ret);
    // Check whether u is equal to c3.
    GOTO_ERR_IF(IsUEqualToC3(decode, sm3Buf, sm3BufLen), ret);
    // The verification is successful. M' is the last plaintext.
    (void)memcpy_s(out, *outlen, t, klen);
    *outlen = klen;
ERR:
    BSL_SAL_FREE(decode);
    ECC_FreePoint(c1);
    ECC_FreePoint(tmp);
    BSL_SAL_CleanseData((void*)t, klen);
    BSL_SAL_FREE(t);
    return ret;
}
#endif // HITLS_CRYPTO_SM2_CRYPT
