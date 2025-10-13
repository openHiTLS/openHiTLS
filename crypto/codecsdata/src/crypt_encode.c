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
#if defined(HITLS_CRYPTO_SM2_SIGN) || defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ECDSA) || \
    defined(HITLS_CRYPTO_SM2_CRYPT)
#include "securec.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "bsl_obj_internal.h"
#include "crypt_encode_internal.h"
#include "bsl_asn1_internal.h"

/**
 * Common function to encode ASN.1 template and copy result
 */
static int32_t EncodeAsn1Template(BSL_ASN1_Template *templ, BSL_ASN1_Buffer *asnArr, uint32_t asnArrLen,
    uint8_t *encode, uint32_t *encodeLen)
{
    uint8_t *outBuf = NULL;
    uint32_t outLen = 0;

    int32_t ret = BSL_ASN1_EncodeTemplate(templ, asnArr, asnArrLen, &outBuf, &outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (outLen > *encodeLen) {
        BSL_SAL_Free(outBuf);
        BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_BUFF_NOT_ENOUGH);
        return CRYPT_ENCODE_BUFF_NOT_ENOUGH;
    }

    (void)memcpy_s(encode, *encodeLen, outBuf, outLen);
    BSL_SAL_Free(outBuf);
    *encodeLen = outLen;

    return CRYPT_SUCCESS;
}

/**
 * Common function to decode ASN.1 template and check remaining length
 */
static int32_t DecodeAsn1Template(const uint8_t *encode, uint32_t encodeLen, BSL_ASN1_Template *templ,
    BSL_ASN1_Buffer *asnArr, uint32_t asnArrLen)
{
    uint8_t *tmpEnc = (uint8_t *)(uintptr_t)encode;
    uint32_t tmpEncLen = encodeLen;

    int32_t ret = BSL_ASN1_DecodeTemplate(templ, NULL, &tmpEnc, &tmpEncLen, asnArr, asnArrLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    for (uint32_t i = 0; i < asnArrLen; i++) {
        if (asnArr[i].len == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ASN1_BUFF_LEN_ZERO);
            return CRYPT_DECODE_ASN1_BUFF_LEN_ZERO;
        }
    }

    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_SM2_SIGN) || defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ECDSA)
int32_t CRYPT_EAL_GetSignEncodeLen(uint32_t rLen, uint32_t sLen, uint32_t *maxLen)
{
    /**
     * https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-integer
     * If the integer is positive but the high order bit is set to 1,
     * a leading 0x00 is added to the content to indicate that the number is not negative
     */
    if (rLen == 0 || rLen > UINT32_MAX - 1 || sLen == 0 || sLen > UINT32_MAX - 1 || maxLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t rEncodeLen = 0;
    uint32_t sEncodeLen = 0;
    int32_t ret = BSL_ASN1_GetEncodeLen(rLen + 1, &rEncodeLen); // + 1: if high bit is 1, should add a leading 0x00
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_GetEncodeLen(sLen + 1, &sEncodeLen); // + 1: if high bit is 1, should add a leading 0x00
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (rEncodeLen > UINT32_MAX - sEncodeLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_ERR_SIGN_LEN_OVERFLOW);
        return CRYPT_ENCODE_ERR_SIGN_LEN_OVERFLOW;
    }
    ret = BSL_ASN1_GetEncodeLen(rEncodeLen + sEncodeLen, maxLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static BSL_ASN1_TemplateItem g_signTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_INTEGER, 0, 1},
        {BSL_ASN1_TAG_INTEGER, 0, 1},
};

static int32_t CheckSignBnParams(const BN_BigNum *r, const BN_BigNum *s, uint8_t *encode, uint32_t *encodeLen)
{
    if (r == NULL || s == NULL || encode == NULL || encodeLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    // The big number must be non-negative.
    if (BN_IsNegative(r) || BN_IsNegative(s)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    // The big number must be non-zero.
    if (BN_IsZero(r) || BN_IsZero(s)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    return CRYPT_SUCCESS;
}

static int32_t ConvertBNToBuffer(const BN_BigNum *bn, uint8_t **outBuf, uint32_t *outLen)
{
    uint32_t len = BN_Bytes(bn);
    uint8_t *buf = (uint8_t *)BSL_SAL_Malloc(len);
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = BN_Bn2Bin(bn, buf, &len);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(buf);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *outBuf = buf;
    *outLen = len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_EncodeSign(const BN_BigNum *r, const BN_BigNum *s, uint8_t *encode, uint32_t *encodeLen)
{
    int32_t ret = CheckSignBnParams(r, s, encode, encodeLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint8_t *rBuf = NULL;
    uint8_t *sBuf = NULL;
    uint32_t rLen = 0;
    uint32_t sLen = 0;

    // Prepare the buffer for r.
    ret = ConvertBNToBuffer(r, &rBuf, &rLen);
    if (ret != CRYPT_SUCCESS) {
        return ret; // no need to push err
    }

    // Prepare the buffer for s.
    ret = ConvertBNToBuffer(s, &sBuf, &sLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(rBuf);
        return ret; // no need to push err
    }

    BSL_ASN1_Buffer asnArr[2] = {
        {BSL_ASN1_TAG_INTEGER, rLen, rBuf},
        {BSL_ASN1_TAG_INTEGER, sLen, sBuf}
    };
    BSL_ASN1_Template templ = {g_signTempl, sizeof(g_signTempl) / sizeof(g_signTempl[0])};
    ret = EncodeAsn1Template(&templ, asnArr, 2, encode, encodeLen);

    BSL_SAL_Free(rBuf);
    BSL_SAL_Free(sBuf);

    return ret;
}

int32_t CRYPT_EAL_DecodeSign(const uint8_t *encode, uint32_t encodeLen, BN_BigNum *r, BN_BigNum *s)
{
    if (encode == NULL || encodeLen == 0 || r == NULL || s == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    // Decode ASN.1 sequence to get r and s components
    BSL_ASN1_Buffer asnArr[2] = {0};  // 2: r and s
    BSL_ASN1_Template templ = {g_signTempl, sizeof(g_signTempl) / sizeof(g_signTempl[0])};
    int32_t ret = DecodeAsn1Template(encode, encodeLen, &templ, asnArr, 2);  // 2: r and s
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Convert decoded buffers to big numbers
    ret = BN_Bin2Bn(r, asnArr[0].buff, asnArr[0].len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BN_Bin2Bn(s, asnArr[1].buff, asnArr[1].len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}
#endif

#ifdef HITLS_CRYPTO_SM2_CRYPT
int32_t CRYPT_EAL_GetSm2EncryptDataEncodeLen(uint32_t xLen, uint32_t yLen, uint32_t hashLen, uint32_t dataLen,
    uint32_t *maxLen)
{
    if (maxLen == NULL || xLen > UINT32_MAX - 1 || yLen > UINT32_MAX - 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t xEncodeLen = 0;
    uint32_t yEncodeLen = 0;
    uint32_t hashEncodeLen = 0;
    uint32_t cipherEncodeLen = 0;

    int32_t ret = BSL_ASN1_GetEncodeLen(xLen + 1, &xEncodeLen); // + 1: if high bit is 1, should add a leading 0x00
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_ASN1_GetEncodeLen(yLen + 1, &yEncodeLen); // + 1: if high bit is 1, should add a leading 0x00
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_ASN1_GetEncodeLen(hashLen, &hashEncodeLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_ASN1_GetEncodeLen(dataLen, &cipherEncodeLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (xEncodeLen > UINT32_MAX - yEncodeLen ||
        (xEncodeLen + yEncodeLen) > UINT32_MAX - hashEncodeLen ||
        (xEncodeLen + yEncodeLen + hashEncodeLen) > UINT32_MAX - cipherEncodeLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_ERR_SM2_ENCRYPT_DATA_LEN_OVERFLOW);
        return CRYPT_ENCODE_ERR_SM2_ENCRYPT_DATA_LEN_OVERFLOW;
    }

    // Calculate the total length of the encoded data
    ret = BSL_ASN1_GetEncodeLen(xEncodeLen + yEncodeLen + hashEncodeLen + cipherEncodeLen, maxLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/**
 * Reference: GM/T 0009-2012 7.2
 * Define template for SM2 encryption data structure:
 * SM2Cipher ::= SEQUENCE {
 *     XCoordinate          INTEGER,
 *     YCoordinate          INTEGER,
 *     HASH                 OCTET STRING SIZE(32),
 *     CipherText           OCTET STRING
 * }
 */
static BSL_ASN1_TemplateItem g_sm2EncryptTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_INTEGER, 0, 1},           // x coordinate
        {BSL_ASN1_TAG_INTEGER, 0, 1},           // y coordinate
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1},      // hash (c3)
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1}       // ciphertext (c2)
};
#define SM2_ENCRYPT_DATA_ITEM_NUM 4

int32_t CheckSm2EncryptData(const CRYPT_SM2_EncryptData *data)
{
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    // Check x and y coordinate
    if (data->x == NULL || data->xLen == 0 || data->y == NULL || data->yLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    // Check hash
    if (data->hash == NULL || data->hashLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    // Check cipher
    if (data->cipher == NULL || data->cipherLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_EncodeSm2EncryptData(const CRYPT_SM2_EncryptData *data, uint8_t *encode, uint32_t *encodeLen)
{
    int32_t ret = CheckSm2EncryptData(data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (encode == NULL || encodeLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_ASN1_Buffer asnArr[SM2_ENCRYPT_DATA_ITEM_NUM] = {
        {BSL_ASN1_TAG_INTEGER, data->xLen, data->x},        // x coordinate
        {BSL_ASN1_TAG_INTEGER, data->yLen, data->y},        // y coordinate
        {BSL_ASN1_TAG_OCTETSTRING, data->hashLen, data->hash},       // hash
        {BSL_ASN1_TAG_OCTETSTRING, data->cipherLen, data->cipher}    // ciphertext
    };
    BSL_ASN1_Template templ = {g_sm2EncryptTempl, sizeof(g_sm2EncryptTempl) / sizeof(g_sm2EncryptTempl[0])};

    return EncodeAsn1Template(&templ, asnArr, SM2_ENCRYPT_DATA_ITEM_NUM, encode, encodeLen);
}

int32_t CRYPT_EAL_DecodeSm2EncryptData(const uint8_t *encode, uint32_t encodeLen, CRYPT_SM2_EncryptData *data)
{
    int32_t ret = CheckSm2EncryptData(data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (encode == NULL || encodeLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_ASN1_Buffer asnArr[SM2_ENCRYPT_DATA_ITEM_NUM] = {0};
    BSL_ASN1_Template templ = {g_sm2EncryptTempl, sizeof(g_sm2EncryptTempl) / sizeof(g_sm2EncryptTempl[0])};
    ret = DecodeAsn1Template(encode, encodeLen, &templ, asnArr, SM2_ENCRYPT_DATA_ITEM_NUM);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Validate lengths
    if (asnArr[0].len > data->xLen || asnArr[1].len > data->yLen ||
        asnArr[2].len > data->hashLen ||   // 2: hash
        asnArr[3].len > data->cipherLen) { // 3: cipher
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_BUFF_NOT_ENOUGH);
        return CRYPT_DECODE_BUFF_NOT_ENOUGH;
    }
    // 1: point xy
    (void)memcpy_s(data->x + (data->xLen - asnArr[0].len), asnArr[0].len, asnArr[0].buff, asnArr[0].len);
    (void)memcpy_s(data->y + (data->yLen - asnArr[1].len), asnArr[1].len, asnArr[1].buff, asnArr[1].len);
    (void)memcpy_s(data->hash, data->hashLen, asnArr[2].buff, asnArr[2].len);     // 2: hash
    (void)memcpy_s(data->cipher, data->cipherLen, asnArr[3].buff, asnArr[3].len); // 3: cipher
    data->hashLen = asnArr[2].len;   // 2: hash
    data->cipherLen = asnArr[3].len; // 3: cipher

    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_SM2_CRYPT

#endif
