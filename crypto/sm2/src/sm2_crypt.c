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

#define SM2_POINT_SINGLE_COORDINATE_LEN 32
#define SM2_POINT_COORDINATE_LEN 65

static void EncryptMemFree(ECC_Point *c1, ECC_Point *tmp, BN_BigNum *k, bool isInternal,
    BN_BigNum *order, uint8_t *c2)
{
    ECC_FreePoint(c1);
    ECC_FreePoint(tmp);
    if (isInternal) {
        BN_Destroy(k);
    }
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
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
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
    if (k == NULL || order == NULL || c1 == NULL || tmp == NULL || c2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
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

#ifdef HITLS_CRYPTO_ACVP_TESTS
int32_t CRYPT_SM2_SetK(CRYPT_SM2_Ctx *ctx, uint8_t *val, uint32_t len)
{
    if (ctx == NULL || val == NULL || len <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->paraEx.k != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_K_REPEAT_SET_ERROR);
        return CRYPT_SM2_K_REPEAT_SET_ERROR;
    }
    BN_BigNum *k = BN_Create(CRYPT_SM2_GetBits(ctx));
    if (k == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_Bin2Bn(k, val, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if (BN_IsZero(k)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        ret = BSL_INVALID_ARG;
        goto EXIT;
    }
    ctx->paraEx.k = k;
    return CRYPT_SUCCESS;
EXIT:
    BN_Destroy(k);
    return ret;
}
#endif

static int32_t EncryptInputCheck(const CRYPT_SM2_Ctx *ctx, const uint8_t *data, uint32_t datalen,
    const uint8_t *out, const uint32_t *outlen)
{
    // 0-length plaintext encryption is not supported.
    if (ctx == NULL || data == NULL || datalen == 0 || out == NULL || outlen == NULL || *outlen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t encodeLen = 0;
    int32_t ret = CRYPT_EAL_GetSm2EncryptDataEncodeLen(SM2_POINT_SINGLE_COORDINATE_LEN, SM2_POINT_SINGLE_COORDINATE_LEN,
        SM3_MD_SIZE, datalen, &encodeLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (*outlen < encodeLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_SM2_BUFF_LEN_NOT_ENOUGH;
    }
    if (ctx->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_EMPTY_KEY);
        return CRYPT_SM2_ERR_EMPTY_KEY;
    }
    if (ctx->pkey->pubkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_NO_PUBKEY);
        return CRYPT_SM2_NO_PUBKEY;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM2_Encrypt(CRYPT_SM2_Ctx *ctx, const uint8_t *data, uint32_t datalen, uint8_t *out, uint32_t *outlen)
{
    int32_t ret = EncryptInputCheck(ctx, data, datalen, out, outlen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t i;
    BN_BigNum *k = NULL;
    bool isInternal = false;
#ifdef HITLS_CRYPTO_ACVP_TESTS
    k = ctx->paraEx.k;
#endif
    if (k == NULL) {
        k = BN_Create(CRYPT_SM2_GetBits(ctx));
        isInternal = true;
    }
    BN_BigNum *order = ECC_GetParaN(ctx->pkey->para);
    ECC_Point *c1 = ECC_NewPoint(ctx->pkey->para);
    ECC_Point *tmp = ECC_NewPoint(ctx->pkey->para);
    uint32_t buflen = SM2_POINT_COORDINATE_LEN;
    uint8_t c1Buf[SM2_POINT_COORDINATE_LEN];
    uint8_t tmpBuf[SM2_POINT_COORDINATE_LEN];
    uint8_t *c2 = BSL_SAL_Malloc(datalen);
    uint8_t c3Buf[SM3_MD_SIZE];
    uint32_t c3BufLen = SM3_MD_SIZE;
    CRYPT_SM2_EncryptData encData = {
        // +1: Skip one byte for '04'
        .x = c1Buf + 1,                                   .xLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .y = c1Buf + SM2_POINT_SINGLE_COORDINATE_LEN + 1, .yLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .hash = c3Buf,                                    .hashLen = c3BufLen,
        .cipher = c2,                                     .cipherLen = datalen,
    };
    GOTO_ERR_IF(MemAllocCheck(k, order, c1, tmp, c2), ret);
    for (i = 0; i < CRYPT_ECC_TRY_MAX_CNT; i++) {
#ifdef HITLS_CRYPTO_ACVP_TESTS
        if (isInternal) {
#endif
            GOTO_ERR_IF(BN_RandRangeEx(ctx->pkey->libCtx, k, order), ret);
            if (BN_IsZero(k)) {
                continue;
            }
#ifdef HITLS_CRYPTO_ACVP_TESTS
        }
#endif
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

    GOTO_ERR_IF(CRYPT_EAL_EncodeSm2EncryptData(&encData, out, outlen), ret);
ERR:
    EncryptMemFree(c1, tmp, k, isInternal, order, c2);
    return ret;
}

static int32_t IsUEqualToC3(const uint8_t *data, const uint8_t *sm3Buf, uint32_t sm3BufLen)
{
    uint8_t check = 0;
    for (uint32_t i = 0; i < sm3BufLen; i++) {
        check |= sm3Buf[i] ^ data[i + SM2_POINT_COORDINATE_LEN];
    }
    if (check != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_DECRYPT_FAIL);
        return CRYPT_SM2_DECRYPT_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t DecryptInputCheck(const CRYPT_SM2_Ctx *ctx, const uint8_t *data, uint32_t datalen,
    const uint8_t *out, const uint32_t *outlen)
{
    // 0-length plaintext decryption is not supported.
    if (ctx == NULL || data == NULL || datalen == 0 || out == NULL || outlen == NULL || *outlen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_EMPTY_KEY);
        return CRYPT_SM2_ERR_EMPTY_KEY;
    }
    if (ctx->pkey->prvkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_NO_PRVKEY);
        return CRYPT_SM2_NO_PRVKEY;
    }
    return CRYPT_SUCCESS;
}

static int32_t DecodeEncryptData(const uint8_t *data, uint32_t datalen, uint8_t **decode,
    const uint8_t **cipher, uint32_t *cipherLen)
{
    *decode = BSL_SAL_Calloc(1u, datalen);
    if (*decode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // Add uncompressed point identifier
    (*decode)[0] = 0x04;
    CRYPT_SM2_EncryptData encData = {
        .x = *decode + 1,                        // Reserve one byte for '04'
        .xLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .y = *decode + SM2_POINT_SINGLE_COORDINATE_LEN + 1,
        .yLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .hash = *decode + SM2_POINT_COORDINATE_LEN,
        .hashLen = SM3_MD_SIZE,
        .cipher = *decode + SM2_POINT_COORDINATE_LEN + SM3_MD_SIZE,
        .cipherLen = datalen - SM2_POINT_COORDINATE_LEN - SM3_MD_SIZE
    };

    int32_t ret = CRYPT_EAL_DecodeSm2EncryptData(data, datalen, &encData);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(*decode);
        *decode = NULL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Return cipher related information
    *cipher = encData.cipher;
    *cipherLen = encData.cipherLen;

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

    uint8_t *decode = NULL;
    const uint8_t *cipher = NULL;
    uint32_t cipherLen = 0;
    ret = DecodeEncryptData(data, datalen, &decode, &cipher, &cipherLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (*outlen < cipherLen) {
        BSL_SAL_Free(decode);
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_SM2_BUFF_LEN_NOT_ENOUGH;
    }

    uint8_t sm3Buf[SM3_MD_SIZE];
    uint32_t sm3BufLen = SM3_MD_SIZE;
    uint32_t tmplen = SM2_POINT_COORDINATE_LEN;
    uint8_t tmpBuf[SM2_POINT_COORDINATE_LEN];
    ECC_Point *c1 = ECC_NewPoint(ctx->pkey->para);
    ECC_Point *tmp = ECC_NewPoint(ctx->pkey->para);
    uint8_t *t = BSL_SAL_Malloc(cipherLen);
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
    // Calculate the kdf(x2 || y2, cipherLen).
    GOTO_ERR_IF(KdfGmt0032012(t, &cipherLen, tmpBuf + 1, tmplen - 1, ctx->hashMethod), ret);
    // Check whether t is all 0s. If yes, report an error and exit.
    GOTO_ERR_IF(IsDataZero(t, cipherLen), ret);

    // Calculate M' = C2 ^ t
    // Bitwise XOR, and the result is still stored in t.
    for (uint32_t i = 0; i < cipherLen; ++i) {
        t[i] ^= cipher[i];
    }
    // Calculate hash（x2 || t || y2)
    GOTO_ERR_IF(Sm3Hash(ctx->hashMethod, tmpBuf, t, cipherLen, sm3Buf, &sm3BufLen), ret);
    // Check whether u is equal to c3.
    GOTO_ERR_IF(IsUEqualToC3(decode, sm3Buf, sm3BufLen), ret);
    // The verification is successful. M' is the last plaintext.
    (void)memcpy_s(out, *outlen, t, cipherLen);
    *outlen = cipherLen;

ERR:
    BSL_SAL_FREE(decode);
    ECC_FreePoint(c1);
    ECC_FreePoint(tmp);
    BSL_SAL_CleanseData((void*)t, cipherLen);
    BSL_SAL_FREE(t);
    return ret;
}
#endif // HITLS_CRYPTO_SM2_CRYPT
