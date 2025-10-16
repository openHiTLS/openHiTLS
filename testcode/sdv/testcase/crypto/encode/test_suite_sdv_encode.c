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

/* BEGIN_HEADER */
#include "crypt_codecskey.h"
#include "crypt_encode_internal.h"
#include "crypt_sm2.h"
#include "crypt_bn.h"
#include "crypt_errno.h"

#define MAX_ENCODE_LEN 1024
#define SM2_POINT_COORDINATE_LEN 65
#define SM2_POINT_SINGLE_COORDINATE_LEN 32
#define SM3_MD_SIZE 32
#define MAX_BN_BITS 2048
#define BITS_IN_A_BYTE 8

/* END_HEADER */

/**
 * @test   SDV_ENCODE_SIGN_BN_FUNC_TC001
 * @title  Test CRYPT_EAL_EncodeSign normal encode function
 */
/* BEGIN_CASE */
void SDV_ENCODE_SIGN_BN_FUNC_TC001(Hex *r, Hex *s, Hex *expect)
{
    uint8_t encode[MAX_ENCODE_LEN] = {0};
    uint32_t encodeLen = sizeof(encode);
    BN_BigNum *bnR = NULL;
    BN_BigNum *bnS = NULL;

    ASSERT_TRUE((bnR = BN_Create(MAX_BN_BITS)) != NULL);
    ASSERT_TRUE((bnS = BN_Create(MAX_BN_BITS)) != NULL);

    ASSERT_TRUE(r->len * BITS_IN_A_BYTE <= MAX_BN_BITS);
    ASSERT_TRUE(s->len * BITS_IN_A_BYTE <= MAX_BN_BITS);

    ASSERT_EQ(BN_Bin2Bn(bnR, r->x, r->len), CRYPT_SUCCESS);
    ASSERT_EQ(BN_SetSign(bnR, false), CRYPT_SUCCESS);

    ASSERT_EQ(BN_Bin2Bn(bnS, s->x, s->len), CRYPT_SUCCESS);
    ASSERT_EQ(BN_SetSign(bnS, false), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_EncodeSign(bnR, bnS, encode, &encodeLen), CRYPT_SUCCESS);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_TRUE(memcmp(encode, expect->x, expect->len) == 0);

EXIT:
    BN_Destroy(bnR);
    BN_Destroy(bnS);
}
/* END_CASE */

/**
 * @test   SDV_ENCODE_SIGN_BN_API_TC001
 * @title  Test CRYPT_EAL_EncodeSign abnormal input parameter
 */
/* BEGIN_CASE */
void SDV_ENCODE_SIGN_BN_API_TC001(Hex *r, Hex *s)
{
    uint8_t encode[MAX_ENCODE_LEN] = {0};
    uint32_t encodeLen = sizeof(encode);
    BN_BigNum *bnR = NULL;
    BN_BigNum *bnS = NULL;

    ASSERT_TRUE((bnR = BN_Create(MAX_BN_BITS)) != NULL);
    ASSERT_TRUE((bnS = BN_Create(MAX_BN_BITS)) != NULL);

    // Test big number is zero
    ASSERT_EQ(CRYPT_EAL_EncodeSign(bnR, bnS, encode, &encodeLen), CRYPT_INVALID_ARG);
    ASSERT_TRUE(BN_Bin2Bn(bnR, r->x, r->len) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeSign(bnR, bnS, encode, &encodeLen), CRYPT_INVALID_ARG);
    ASSERT_TRUE(BN_Bin2Bn(bnS, s->x, s->len) == CRYPT_SUCCESS);

    // Test null pointer
    ASSERT_EQ(CRYPT_EAL_EncodeSign(NULL, bnS, encode, &encodeLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_EncodeSign(bnR, NULL, encode, &encodeLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_EncodeSign(bnR, bnS, NULL, &encodeLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_EncodeSign(bnR, bnS, encode, NULL), CRYPT_NULL_INPUT);

    // Test big number is negative
    ASSERT_EQ(BN_SetSign(bnR, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeSign(bnR, bnS, encode, &encodeLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(BN_SetSign(bnR, false), CRYPT_SUCCESS);
    ASSERT_EQ(BN_SetSign(bnS, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeSign(bnR, bnS, encode, &encodeLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(BN_SetSign(bnS, false), CRYPT_SUCCESS);

    // Test buffer length is not enough
    encodeLen = 1;
    ASSERT_EQ(CRYPT_EAL_EncodeSign(bnR, bnS, encode, &encodeLen), CRYPT_ENCODE_BUFF_NOT_ENOUGH);

EXIT:
    BN_Destroy(bnR);
    BN_Destroy(bnS);
}
/* END_CASE */

/**
 * @test   SDV_DECODE_SIGN_BN_FUNC_TC001
 * @title  Test CRYPT_EAL_DecodeSign normal decode function
 */
/* BEGIN_CASE */
void SDV_DECODE_SIGN_BN_FUNC_TC001(Hex *encode, Hex *expectR, Hex *expectS, int ret)
{
    BN_BigNum *bnR = NULL;
    BN_BigNum *bnS = NULL;
    uint8_t rBuf[MAX_ENCODE_LEN] = {0};
    uint8_t sBuf[MAX_ENCODE_LEN] = {0};
    uint32_t rLen = sizeof(rBuf);
    uint32_t sLen = sizeof(sBuf);

    ASSERT_TRUE((bnR = BN_Create(MAX_BN_BITS)) != NULL);
    ASSERT_TRUE((bnS = BN_Create(MAX_BN_BITS)) != NULL);

    ASSERT_EQ(CRYPT_EAL_DecodeSign(encode->x, encode->len, bnR, bnS), ret);

    if (ret == CRYPT_SUCCESS) {
        ASSERT_TRUE(!BN_IsNegative(bnR));
        ASSERT_TRUE(!BN_IsNegative(bnS));
        ASSERT_EQ(BN_Bn2Bin(bnR, rBuf, &rLen), CRYPT_SUCCESS);
        ASSERT_EQ(BN_Bn2Bin(bnS, sBuf, &sLen), CRYPT_SUCCESS);

        ASSERT_EQ(rLen, expectR->len);
        ASSERT_EQ(sLen, expectS->len);
        ASSERT_TRUE(memcmp(rBuf, expectR->x, rLen) == 0);
        ASSERT_TRUE(memcmp(sBuf, expectS->x, sLen) == 0);
    }

EXIT:
    BN_Destroy(bnR);
    BN_Destroy(bnS);
}
/* END_CASE */

/**
 * @test   SDV_DECODE_SIGN_BN_API_TC001
 * @title  Test CRYPT_EAL_DecodeSign abnormal input parameter
 */
/* BEGIN_CASE */
void SDV_DECODE_SIGN_BN_API_TC001(Hex *encode)
{
    BN_BigNum *bnR = NULL;
    BN_BigNum *bnS = NULL;

    ASSERT_TRUE((bnR = BN_Create(MAX_BN_BITS)) != NULL);
    ASSERT_TRUE((bnS = BN_Create(MAX_BN_BITS)) != NULL);

    // Test null pointer
    ASSERT_EQ(CRYPT_EAL_DecodeSign(NULL, encode->len, bnR, bnS), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_DecodeSign(encode->x, 0, bnR, bnS), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_DecodeSign(encode->x, encode->len, NULL, bnS), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_DecodeSign(encode->x, encode->len, bnR, NULL), CRYPT_NULL_INPUT);

EXIT:
    BN_Destroy(bnR);
    BN_Destroy(bnS);
}
/* END_CASE */

/**
 * @test   SDV_ENCODE_SM2_ENCRYPT_DATA_FUNC_TC001
 * @title  Test CRYPT_EAL_EncodeSm2EncryptData normal encode function
 */
/* BEGIN_CASE */
void SDV_ENCODE_SM2_ENCRYPT_DATA_FUNC_TC001(Hex *x, Hex *y, Hex *hash, Hex *cipher, Hex *expect, int ret)
{
    uint8_t encode[MAX_ENCODE_LEN] = {0};
    uint32_t encodeLen = sizeof(encode);
    CRYPT_SM2_EncryptData data = {
        .x = x->x,                  .xLen = x->len,
        .y = y->x,                  .yLen = y->len,
        .hash = hash->x,            .hashLen = hash->len,
        .cipher = cipher->x,        .cipherLen = cipher->len
    };

    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), ret);
    if (ret == CRYPT_SUCCESS) {
        ASSERT_EQ(encodeLen, expect->len);
        ASSERT_TRUE(memcmp(encode, expect->x, expect->len) == 0);
    }

EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_ENCODE_SM2_ENCRYPT_DATA_API_TC001
 * @title  Test CRYPT_EAL_EncodeSm2EncryptData abnormal input parameter
 */
/* BEGIN_CASE */
void SDV_ENCODE_SM2_ENCRYPT_DATA_API_TC001(Hex *x, Hex *y, Hex *hash, Hex *cipher)
{
    uint8_t encode[MAX_ENCODE_LEN] = {0};
    uint32_t encodeLen = sizeof(encode);
    CRYPT_SM2_EncryptData data = {
        .x = x->x,                  .xLen = x->len,
        .y = y->x,                  .yLen = y->len,
        .hash = hash->x,            .hashLen = hash->len,
        .cipher = cipher->x,        .cipherLen = cipher->len
    };

    // Test null pointer
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(NULL, encode, &encodeLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, NULL, &encodeLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, NULL), CRYPT_NULL_INPUT);

    // Test invalid x
    data.x = NULL;
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), CRYPT_INVALID_ARG);
    data.x = x->x;
    data.xLen = 0;
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), CRYPT_INVALID_ARG);
    data.xLen = x->len;
    // Test invalid y
    data.y = NULL;
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), CRYPT_INVALID_ARG);
    data.y = y->x;
    data.yLen = 0;
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), CRYPT_INVALID_ARG);
    data.yLen = y->len;

    // Test invalid hash
    data.hash = NULL;
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), CRYPT_INVALID_ARG);
    data.hash = hash->x;
    data.hashLen = 0;
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), CRYPT_INVALID_ARG);
    data.hashLen = hash->len;

    // Test invalid cipher
    data.cipher = NULL;
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), CRYPT_INVALID_ARG);
    data.cipher = cipher->x;
    data.cipherLen = 0;
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), CRYPT_INVALID_ARG);
    data.cipherLen = cipher->len;

    // Test buffer length is not enough
    data.xLen = x->len;
    encodeLen = 1;
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), CRYPT_ENCODE_BUFF_NOT_ENOUGH);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_DECODE_SM2_ENCRYPT_DATA_FUNC_TC001
 * @title  Test CRYPT_EAL_DecodeSm2EncryptData normal decode function
 */
/* BEGIN_CASE */
void SDV_DECODE_SM2_ENCRYPT_DATA_FUNC_TC001(Hex *encode, Hex *expectX, Hex *expectY, Hex *expectHash, Hex *expectCipher,
    int ret)
{
    uint8_t decode[MAX_ENCODE_LEN] = {0};
    CRYPT_SM2_EncryptData data = {
        .x = decode,
        .xLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .y = decode + SM2_POINT_SINGLE_COORDINATE_LEN,
        .yLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .hash = decode + SM2_POINT_COORDINATE_LEN,
        .hashLen = SM3_MD_SIZE,
        .cipher = decode + SM2_POINT_COORDINATE_LEN + SM3_MD_SIZE,
        .cipherLen = sizeof(decode) - SM2_POINT_COORDINATE_LEN - SM3_MD_SIZE
    };

    ASSERT_EQ(CRYPT_EAL_DecodeSm2EncryptData(encode->x, encode->len, &data), ret);

    if (ret == CRYPT_SUCCESS) {
        ASSERT_EQ(data.hashLen, expectHash->len);
        ASSERT_EQ(data.cipherLen, expectCipher->len);
        ASSERT_TRUE(memcmp(data.x + (data.xLen - expectX->len), expectX->x, expectX->len) == 0);
        ASSERT_TRUE(memcmp(data.y + (data.yLen - expectY->len), expectY->x, expectY->len) == 0);
        ASSERT_TRUE(memcmp(data.hash, expectHash->x, data.hashLen) == 0);
        ASSERT_TRUE(memcmp(data.cipher, expectCipher->x, data.cipherLen) == 0);
    }

EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_DECODE_SM2_ENCRYPT_DATA_API_TC001
 * @title  Test CRYPT_EAL_DecodeSm2EncryptData abnormal input parameter
 */
/* BEGIN_CASE */
void SDV_DECODE_SM2_ENCRYPT_DATA_API_TC001(Hex *encode)
{
    uint8_t x;
    uint8_t y;
    uint8_t hash;
    uint8_t cipher;
    CRYPT_SM2_EncryptData data = {
        .x = &x,                  .xLen = 1,
        .y = &y,                  .yLen = 1,
        .hash = &hash,            .hashLen = 1,
        .cipher = &cipher,        .cipherLen = 1
    };

    // Test null pointer
    ASSERT_EQ(CRYPT_EAL_DecodeSm2EncryptData(NULL, encode->len, &data), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_DecodeSm2EncryptData(encode->x, encode->len, NULL), CRYPT_NULL_INPUT);

    // Test invlaid data
    data.x = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeSm2EncryptData(encode->x, encode->len, &data), CRYPT_INVALID_ARG);
    data.x = &x;
    data.xLen = 0;
    ASSERT_EQ(CRYPT_EAL_DecodeSm2EncryptData(encode->x, encode->len, &data), CRYPT_INVALID_ARG);
    data.xLen = 1;

    // Test buffer length is not enough
    ASSERT_EQ(CRYPT_EAL_DecodeSm2EncryptData(encode->x, encode->len, &data), CRYPT_DECODE_BUFF_NOT_ENOUGH);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_ENCODE_GET_SIGN_LEN_API_TC001
 * @title  Test CRYPT_EAL_GetSignEncodeLen
 */
/* BEGIN_CASE */
void SDV_ENCODE_GET_SIGN_LEN_API_TC001(void)
{
    uint32_t maxLen = 0;
    // Normal case test
    ASSERT_EQ(CRYPT_SUCCESS, CRYPT_EAL_GetSignEncodeLen(32, 32, &maxLen));
    ASSERT_EQ(72, maxLen);  // (32 + 1(leading 0x00) + 1(len) + 1(tag)) * 2(r,s) + 1(tag) + 1(len) = 72

    // Invalid parameter test
    ASSERT_EQ(CRYPT_EAL_GetSignEncodeLen(0, 32, &maxLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_GetSignEncodeLen(32, 0, &maxLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_GetSignEncodeLen(32, 32, NULL), CRYPT_INVALID_ARG);

    // Overflow test
    ASSERT_EQ(CRYPT_EAL_GetSignEncodeLen(UINT32_MAX, 32, &maxLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_GetSignEncodeLen(32, UINT32_MAX, &maxLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_GetSignEncodeLen(UINT32_MAX - 1, 32, &maxLen), BSL_ASN1_ERR_LEN_OVERFLOW);
    ASSERT_EQ(CRYPT_EAL_GetSignEncodeLen(32, UINT32_MAX - 1, &maxLen), BSL_ASN1_ERR_LEN_OVERFLOW);

    // 1(tag) + 1(len) + 1(integer)
    // Indefinite form: 1(tag) + 1 + 1(lenNum) + 1(len)
    ASSERT_EQ(CRYPT_EAL_GetSignEncodeLen(1, UINT32_MAX - (1 + 1 + 1) - (1 + 1 + 4), &maxLen),
        CRYPT_ENCODE_ERR_SIGN_LEN_OVERFLOW);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_ENCODE_GET_SM2_ENC_LEN_API_TC001
 * @title  Test CRYPT_EAL_GetSm2EncryptDataEncodeLen
 */
/* BEGIN_CASE */
void SDV_ENCODE_GET_SM2_ENC_LEN_API_TC001(void)
{
    uint32_t encodeLen = 0;
    // Normal case test
    ASSERT_EQ(CRYPT_EAL_GetSm2EncryptDataEncodeLen(32, 32, 32, 64, &encodeLen), CRYPT_SUCCESS);
    ASSERT_EQ(encodeLen, 173);  //  (32 + 1 + 1 + 1) * 2 + (32+1+1) + (64+1+1) + 2(length > 127) + 1 = 173

    // Minimum valid input test
    ASSERT_EQ(CRYPT_EAL_GetSm2EncryptDataEncodeLen(1, 1, 1, 1, &encodeLen), CRYPT_SUCCESS);
    ASSERT_EQ(encodeLen, 16);  //  (1 + 1 + 1 + 1) * 2 + (1+1+1) + (1+1+1) + 1 + 1 = 16

    // Invalid parameter test
    ASSERT_EQ(CRYPT_INVALID_ARG, CRYPT_EAL_GetSm2EncryptDataEncodeLen(32, 32, 32, 32, NULL));

    // Overflow test
    ASSERT_EQ(CRYPT_EAL_GetSm2EncryptDataEncodeLen(UINT32_MAX - 1, UINT32_MAX - 1, 32, 32, &encodeLen),
        BSL_ASN1_ERR_LEN_OVERFLOW);

    ASSERT_EQ(CRYPT_EAL_GetSm2EncryptDataEncodeLen(1000, 1000, UINT32_MAX - 2000, 32, &encodeLen),
        CRYPT_ENCODE_ERR_SM2_ENCRYPT_DATA_LEN_OVERFLOW);

    ASSERT_EQ(CRYPT_EAL_GetSm2EncryptDataEncodeLen(1000, 1000, 1000, UINT32_MAX - 3000, &encodeLen),
        CRYPT_ENCODE_ERR_SM2_ENCRYPT_DATA_LEN_OVERFLOW);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_ENCODE_DECODE_SIGN_COMBO_TC001
 * @title  Test combined encode and decode for signature
 */
/* BEGIN_CASE */
void SDV_ENCODE_DECODE_SIGN_COMBO_TC001(Hex *r, Hex *s)
{
    uint32_t maxLen = 0;
    uint8_t *encode = NULL;
    BN_BigNum *bnR = NULL;
    BN_BigNum *bnS = NULL;
    BN_BigNum *decR = NULL;
    BN_BigNum *decS = NULL;
    uint8_t rBuf[MAX_ENCODE_LEN] = {0};
    uint8_t sBuf[MAX_ENCODE_LEN] = {0};
    uint32_t rLen = sizeof(rBuf);
    uint32_t sLen = sizeof(sBuf);

    // Create big numbers
    ASSERT_TRUE((bnR = BN_Create(MAX_BN_BITS)) != NULL);
    ASSERT_TRUE((bnS = BN_Create(MAX_BN_BITS)) != NULL);
    ASSERT_TRUE((decR = BN_Create(MAX_BN_BITS)) != NULL);
    ASSERT_TRUE((decS = BN_Create(MAX_BN_BITS)) != NULL);

    // Convert input hex to big numbers
    ASSERT_TRUE(r->len * BITS_IN_A_BYTE <= MAX_BN_BITS);
    ASSERT_TRUE(s->len * BITS_IN_A_BYTE <= MAX_BN_BITS);
    ASSERT_EQ(BN_Bin2Bn(bnR, r->x, r->len), CRYPT_SUCCESS);
    ASSERT_EQ(BN_SetSign(bnR, false), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Bin2Bn(bnS, s->x, s->len), CRYPT_SUCCESS);
    ASSERT_EQ(BN_SetSign(bnS, false), CRYPT_SUCCESS);

    // Get encode length and allocate buffer
    ASSERT_EQ(CRYPT_EAL_GetSignEncodeLen(r->len, s->len, &maxLen), CRYPT_SUCCESS);
    ASSERT_TRUE((encode = (uint8_t *)BSL_SAL_Malloc(maxLen)) != NULL);

    // Encode signature
    uint32_t encodeLen = maxLen;
    ASSERT_EQ(CRYPT_EAL_EncodeSign(bnR, bnS, encode, &encodeLen), CRYPT_SUCCESS);

    // Decode signature
    ASSERT_EQ(CRYPT_EAL_DecodeSign(encode, encodeLen, decR, decS), CRYPT_SUCCESS);

    // Convert decoded big numbers back to binary and compare
    ASSERT_EQ(BN_Bn2Bin(decR, rBuf, &rLen), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Bn2Bin(decS, sBuf, &sLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("Compare r", rBuf, rLen, r->x, r->len);
    ASSERT_COMPARE("Compare s", sBuf, sLen, s->x, s->len);

EXIT:
    BSL_SAL_Free(encode);
    BN_Destroy(bnR);
    BN_Destroy(bnS);
    BN_Destroy(decR);
    BN_Destroy(decS);
}
/* END_CASE */

/**
 * @test   SDV_ENCODE_DECODE_SM2_ENCRYPT_COMBO_TC001
 * @title  Test combined encode and decode for SM2 encryption data
 */
/* BEGIN_CASE */
void SDV_ENCODE_DECODE_SM2_ENCRYPT_COMBO_TC001(Hex *x, Hex *y, Hex *hash, Hex *cipher)
{
    uint32_t maxLen = 0;
    uint8_t *encode = NULL;
    uint8_t decBuf[MAX_ENCODE_LEN] = {0};

    // Original data
    CRYPT_SM2_EncryptData data = {
        .x = x->x,                  .xLen = x->len,
        .y = y->x,                  .yLen = y->len,
        .hash = hash->x,            .hashLen = hash->len,
        .cipher = cipher->x,        .cipherLen = cipher->len
    };

    // Prepare decode buffer
    decBuf[0] = 0x04;
    CRYPT_SM2_EncryptData decData = {
        .x = decBuf + 1,                                        .xLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .y = decBuf + 1 + SM2_POINT_SINGLE_COORDINATE_LEN,      .yLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .hash = decBuf +  SM2_POINT_COORDINATE_LEN,             .hashLen = SM3_MD_SIZE,
        .cipher = decBuf + SM2_POINT_COORDINATE_LEN + hash->len, .cipherLen = sizeof(decBuf) - SM3_MD_SIZE - SM2_POINT_COORDINATE_LEN
    };

    // Get encode length and allocate buffer
    ASSERT_EQ(CRYPT_EAL_GetSm2EncryptDataEncodeLen(x->len, y->len, hash->len, cipher->len, &maxLen), CRYPT_SUCCESS);
    ASSERT_TRUE((encode = (uint8_t *)BSL_SAL_Malloc(maxLen)) != NULL);

    // Encode SM2 encryption data
    uint32_t encodeLen = maxLen;
    ASSERT_EQ(CRYPT_EAL_EncodeSm2EncryptData(&data, encode, &encodeLen), CRYPT_SUCCESS);

    // Decode SM2 encryption data
    ASSERT_EQ(CRYPT_EAL_DecodeSm2EncryptData(encode, encodeLen, &decData), CRYPT_SUCCESS);

    // Compare decoded data with original data
    ASSERT_COMPARE("Compare x", decData.x + (decData.xLen - x->len), x->len, x->x, x->len);
    ASSERT_COMPARE("Compare y", decData.y + (decData.yLen - y->len), y->len, y->x, y->len);
    ASSERT_COMPARE("Compare hash", decData.hash, decData.hashLen, hash->x, hash->len);
    ASSERT_COMPARE("Compare cipher", decData.cipher, decData.cipherLen, cipher->x, cipher->len);

EXIT:
    BSL_SAL_Free(encode);
}
/* END_CASE */
