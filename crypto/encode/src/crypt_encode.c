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
#ifdef HITLS_CRYPTO_ENCODE
#include "securec.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_encode.h"

/**
 * https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types asn1 encoding format
 * https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-integer interger encoding format
 */

#define CONS_SEQ_TAG 0x30
#define PRIM_INT_TAG 0x02

static uint32_t GetBytes(uint32_t num)
{
    uint32_t val = num;
    uint32_t ret = 0;
    while (val != 0) {
        ret++;
        val >>= 8; // right shifting 8 bits equals the offset of 1 byte.
    }
    return ret;
}

/**
 * ANS1 encoding format: When the length is less than 0x80, the first byte indicates the data length.
 * If the length is greater than 0x80, the most significant bit of the first byte is set to 1,
 * the least significant seven bits indicate the length of the len data.
 * For example:
 * The length is 0x40, and the encoded data is represented as 0x40 data...
 * The length is 0x85, and the encoded data is 0x81 0x85 data...
 * The length is 0x50FF, and the encoded data is 0x82 0x50 0xFF data...
 */
static uint32_t GetEnCodeLen(uint32_t dataLen)
{
    uint32_t ret = 2; // tag + len need 2 bytes
    if (dataLen > 0x7F) { // if the most significant bit is 1
        ret += GetBytes(dataLen);
    }
    return ret;
}

/** Internal function, which is not supported when rLen/sLen is greater than 32764.
 * When r and s exceed 32764, the total length exceeds 65536 (that is, 0xFFFF) 32764 * 2 + 4 * 2 = 65536.
 * Currently, the DSA key is limited to 3072 bits, that is, 384 bytes. This code can be used to cover this case.
 */
uint32_t ASN1_SignEnCodeLen(uint32_t rLen, uint32_t sLen)
{
    uint32_t rEncodeLen = GetEnCodeLen(rLen) + rLen;
    uint32_t sEncodeLen = GetEnCodeLen(sLen) + sLen;
    uint32_t enCodeLen = GetEnCodeLen(rEncodeLen + sEncodeLen);
    return rEncodeLen + sEncodeLen + enCodeLen;
}

static void TagLenEncode(uint8_t *data, uint32_t *off, uint8_t tag, uint32_t len)
{
    uint32_t offset = *off;
    data[offset] = tag;
    offset++;
    if (len > 0x7F) {
        uint32_t bytes = GetBytes(len);
        data[offset++] = 0x80 | (bytes & 0x7F);
        while (bytes > 0) {
            data[offset++] = (len >> ((bytes - 1) * 8)) & 0xFF; // * 8 to calculate the number of offset bits.
            bytes--;
        }
    } else {
        data[offset] = len & 0xFF;
        offset++;
    }
    *off = offset;
}

uint32_t ASN1_SignStringLenOfBn(const BN_BigNum *num)
{
    uint32_t bits = BN_Bits(num);
    /**
     * https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-integer
     * If the integer is positive but the high order bit is set to 1,
     * a leading 0x00 is added to the content to indicate that the number is not negative
     */
    // When the bit is a multiple of 8, and the most significant bit is 1, 0x00 needs to be added.
    // If the bit is not a multiple of 8, an extra byte needs to be added to store the data less than 8 bits.
    return (bits / 8) + 1;
}

// Encode num into sign.
static int32_t StringEncode(uint8_t *sign, uint32_t *signLen, const BN_BigNum *num)
{
    uint32_t bits = BN_Bits(num);
    if (*signLen < 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_DSA_BUFF_LEN_NOT_ENOUGH;
    }
    if (bits == 0) {
        sign[0] = 0;
        *signLen = 1;
        return CRYPT_SUCCESS;
    }

    uint32_t offset = 0;
    // If the first byte is greater than 0x7F, and the bit length is a multiple of 8, 0 is added at the beginning.
    if (bits % 8 == 0) {
        sign[0] = 0;
        offset++;
        (*signLen)--;
    }
    int32_t ret = BN_Bn2Bin(num, sign + offset, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *signLen += offset;
    return ret;
}

// Decode the sign to the num.
static int32_t StringDecode(const uint8_t *sign, uint32_t signLen, BN_BigNum *num)
{
    uint32_t offset = 0;
    // Ignore the first byte 0.
    if (sign[0] == 0) {
        offset++;
    }
    if (signLen == offset) {
        return BN_Zeroize(num);
    }
    if (((sign[offset] & 0x80) != 0) && (offset == 0)) {
        // The most significant bit is 0x80, indicating that the data is a negative number and decoding fails.
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_DECODE_FAIL);
        return CRYPT_DSA_DECODE_FAIL;
    }
    return BN_Bin2Bn(num, sign + offset, signLen - offset);
}

/** Internal function, which is not supported when rLen/sLen is greater than 32764.
 * When r and s exceed 32764, the total length exceeds 65536 (that is, 0xFFFF) 32764 * 2 + 4 * 2 = 65536.
 * Currently the specification of the DSA key is 3072 bits, that is 384 bytes. The code in this case can be implemented.
 * EncodeData: CONS_SEQ_TAG + Len + PRIM_INT_TAG + rLen + r + PRIM_INT_TAG + sLen + s
 * For details about the encoding format, see RFC6979-A.1.3.
 */
int32_t ASN1_SignDataEncode(const DSA_Sign *s, uint8_t *sign, uint32_t *signLen)
{
    uint32_t rLen = ASN1_SignStringLenOfBn(s->r);
    uint32_t sLen = ASN1_SignStringLenOfBn(s->s);
    // Ensure that the data length is sufficient for encoding and decoding.
    if (ASN1_SignEnCodeLen(rLen, sLen) > *signLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_DSA_BUFF_LEN_NOT_ENOUGH;
    }
    uint32_t offset = 0;
    sign[offset] = CONS_SEQ_TAG;
    // CONS_SEQ_TAG + Len
    TagLenEncode(sign, &offset, CONS_SEQ_TAG, rLen + sLen + GetEnCodeLen(rLen) + GetEnCodeLen(sLen));
    // PRIM_INT_TAG + rLen
    TagLenEncode(sign, &offset, PRIM_INT_TAG, rLen);
    uint32_t len = *signLen - offset;
    // r
    int32_t ret = StringEncode(sign + offset, &len, s->r);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += len;
    // PRIM_INT_TAG + sLen
    TagLenEncode(sign, &offset, PRIM_INT_TAG, sLen);
    len = *signLen - offset;
    // s
    ret = StringEncode(sign + offset, &len, s->s);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *signLen = offset + len;
    return ret;
}
// Obtain the size of the next data block and check the validity of the length. If 0 is returned, the parsing fails.
// If other values are returned, that means the parsed data length is obtained.
static uint32_t GetDecodeLen(const uint8_t *sign, uint32_t signLen, uint32_t *off, uint8_t tag)
{
    uint32_t offset = *off;
    uint32_t cnt = 0;
    uint32_t ret = 0;
    // Determine whether out-of-bounds.
    if (offset >= signLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return 0;
    }
    // Check whether the tags are consistent.
    if (sign[offset] != tag) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return 0;
    }
    offset++;
    // Determine whether out-of-bounds.
    if (offset >= signLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return 0;
    }
    // Obtain the length of the length identifier.
    if ((sign[offset] & 0x80) != 0) {
        cnt = sign[offset] & 0x7F;
        offset++;
    } else {
        cnt = 1;
    }
    // Check whether the length is meaningful and out of range.
    if (cnt == 0 || (offset + cnt) > signLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return 0;
    }
    uint32_t i;
    // Obtain the length.
    for (i = 0; i < cnt; i++) {
        ret <<= 8;
        ret += sign[offset + i];
    }
    // Check whether the length is meaningful.
    if (ret == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return 0;
    }
    offset += i;
    // Determine whether out-of-bounds.
    if (offset + ret > signLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return 0;
    }
    *off = offset;
    return ret;
}
// For details about the decoding format, see RFC6979-A.1.3.
int32_t ASN1_SignDataDecode(DSA_Sign *s, const uint8_t *sign, uint32_t signLen)
{
    uint32_t len;
    uint32_t offset = 0;

    len = GetDecodeLen(sign, signLen, &offset, CONS_SEQ_TAG);
    if (len == 0 || len != signLen - offset) { // Check whether the total length is correct.
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_DECODE_FAIL);
        return CRYPT_DSA_DECODE_FAIL;
    }
    len = GetDecodeLen(sign, signLen, &offset, PRIM_INT_TAG);
    if (len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_DECODE_FAIL);
        return CRYPT_DSA_DECODE_FAIL;
    }
    int32_t ret = StringDecode(sign + offset, len, s->r);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += len;
    len = GetDecodeLen(sign, signLen, &offset, PRIM_INT_TAG);
    if (len == 0 || len != (signLen - offset)) { // last block
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_DECODE_FAIL);
        return CRYPT_DSA_DECODE_FAIL;
    }
    ret = StringDecode(sign + offset, len, s->s);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#ifdef HITLS_CRYPTO_SM2_CRYPT

#define PRIM_OCT_STRING_TAG 0x04
#define SM2_CURVE_BITS_WIDTH 32
#define SM2_CURVE_BITS_WIDTH_TWICE 64
#define SM3_HASH_LEN 32

uint64_t ASN1_Sm2GetEnCodeLen(uint32_t dataLen)
{
    uint32_t initBytes = 2; // 'tag', 'len' needs 2 bytes.
    uint32_t c1EncodeLen = (SM2_CURVE_BITS_WIDTH + initBytes + 1) * 2; // x, y all needs to be encoded.
    uint32_t c3EncodeLen = SM3_HASH_LEN + initBytes;
    uint32_t c2EncodeLen = GetEnCodeLen(dataLen) + dataLen;
    uint32_t sum = GetEnCodeLen(c1EncodeLen + c3EncodeLen + c2EncodeLen);
    return c1EncodeLen + c3EncodeLen + c2EncodeLen + sum;
}

static int32_t Sm2FetchString(const uint8_t *encode, uint32_t encodeLen, uint8_t *num, uint32_t numLen, uint8_t tag)
{
    if (tag == PRIM_INT_TAG && (encode[0] & 0x80) != 0) {
        // The most significant bit is not 0. Decoding failed.
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_DECODE_FAIL);
        return CRYPT_SM2_DECODE_FAIL;
    }
    uint32_t hasPad = 0;
    uint32_t hasZero = 0;
    if (tag == PRIM_INT_TAG && encodeLen > SM2_CURVE_BITS_WIDTH) {
        hasPad = 1; // There are padding of INT_TAG data during encoding.
    }
    if (tag == PRIM_INT_TAG && encodeLen < SM2_CURVE_BITS_WIDTH) {
        // if encodeLen < 32, add 0 to the front of the data to facilitate transcoding during decryption.
        hasZero = SM2_CURVE_BITS_WIDTH - encodeLen;
    }
    (void)memcpy_s(num + hasZero, numLen - hasZero, encode + hasPad, encodeLen - hasPad);
    return CRYPT_SUCCESS;
}

static void Sm2EnterString(uint8_t *output, uint32_t *outputLen,
    const uint8_t *num, uint32_t numLen, bool pad)
{
    uint32_t len = *outputLen;
    if (numLen == 0) {
        output[0] = 0;
        *outputLen = 1;
        return;
    }

    uint32_t offset = 0;
    if (pad) {
        output[0] = 0;
        offset++;
        len--;
    }
    (void)memcpy_s(output + offset, len, num, numLen);
    *outputLen = numLen + offset;
}

static void GetXYstatus(const uint8_t *input, uint32_t *tmpXLen, uint32_t *tmpYLen, bool *xPad, bool *yPad)
{
    if ((input[0] & 0x80) != 0) {
        *tmpXLen += 1;
        *xPad = true;
    }
    if ((input[SM2_CURVE_BITS_WIDTH] & 0x80) != 0) {
        *tmpYLen += 1;
        *yPad = true;
    }
    return;
}

// Encode the SM2 ciphertext into the ASNI format according to the GM/T 0009-2012.
int32_t ASN1_Sm2EncryptDataEncode(const uint8_t *input, uint32_t inputLen, uint8_t *encode, uint32_t *encodeLen)
{
    uint32_t tmpXLen = SM2_CURVE_BITS_WIDTH;
    uint32_t tmpYLen = SM2_CURVE_BITS_WIDTH;
    uint32_t c2Len = inputLen - SM2_CURVE_BITS_WIDTH_TWICE - SM3_HASH_LEN;
    bool xPad = false;
    bool yPad = false;
    uint32_t len = 0;
    uint32_t offset = 0;

    // CONS_SEQ_TAG + Len
    GetXYstatus(input, &tmpXLen, &tmpYLen, &xPad, &yPad);
    // x, y and hash are all less than 128 bytes long, so only need 2 extra bytes to encode, 2 * 3 = 6
    TagLenEncode(encode, &offset, CONS_SEQ_TAG, tmpXLen + tmpYLen + SM3_HASH_LEN + 6 + c2Len + GetEnCodeLen(c2Len));

    // x
    // PRIM_INT_TAG + tmpXLen
    TagLenEncode(encode, &offset, PRIM_INT_TAG, tmpXLen);
    len = *encodeLen - offset;
    Sm2EnterString(encode + offset, &len, input, SM2_CURVE_BITS_WIDTH, xPad);
    offset += len;

    // y
    // PRIM_INT_TAG + tmpYLen
    TagLenEncode(encode, &offset, PRIM_INT_TAG, tmpYLen);
    len = *encodeLen - offset;
    Sm2EnterString(encode + offset, &len, input + SM2_CURVE_BITS_WIDTH, SM2_CURVE_BITS_WIDTH, yPad);
    offset += len;

    // c3
    // PRIM_INT_TAG + tmpSLen
    TagLenEncode(encode, &offset, PRIM_OCT_STRING_TAG, SM3_HASH_LEN);
    len = *encodeLen - offset;
    Sm2EnterString(encode + offset, &len, input + SM2_CURVE_BITS_WIDTH_TWICE, SM3_HASH_LEN, false);
    offset += len;

    // c2
    // PRIM_INT_TAG + tmpSLen
    TagLenEncode(encode, &offset, PRIM_OCT_STRING_TAG, c2Len);
    len = *encodeLen - offset;
    Sm2EnterString(encode + offset, &len, input + SM2_CURVE_BITS_WIDTH_TWICE + SM3_HASH_LEN, c2Len, false);

    *encodeLen = offset + len;
    return CRYPT_SUCCESS;
}

int32_t ASN1_Sm2EncryptDataDecode(const uint8_t *eData, uint32_t eLen, uint8_t *decode, uint32_t *decodeLen)
{
    uint32_t len;
    uint32_t offset = 0;
    int32_t ret = 0;
    // decode whole len
    len = GetDecodeLen(eData, eLen, &offset, CONS_SEQ_TAG);
    if (len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_DECODE_FAIL);
        return CRYPT_SM2_DECODE_FAIL;
    }

    // get X
    len = GetDecodeLen(eData, eLen, &offset, PRIM_INT_TAG);
    if (len == 0 || len > SM2_CURVE_BITS_WIDTH + 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_DECODE_FAIL);
        return CRYPT_SM2_DECODE_FAIL;
    }

    ret = Sm2FetchString(eData + offset, len, decode, SM2_CURVE_BITS_WIDTH, PRIM_INT_TAG);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += len;

    // get Y
    len = GetDecodeLen(eData, eLen, &offset, PRIM_INT_TAG);
    if (len == 0 || len > SM2_CURVE_BITS_WIDTH + 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_DECODE_FAIL);
        return CRYPT_SM2_DECODE_FAIL;
    }
    ret = Sm2FetchString(eData + offset, len, decode + SM2_CURVE_BITS_WIDTH, SM2_CURVE_BITS_WIDTH, PRIM_INT_TAG);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += len;

    // get c3
    len = GetDecodeLen(eData, eLen, &offset, PRIM_OCT_STRING_TAG);
    if (len != SM3_HASH_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_DECODE_FAIL);
        return CRYPT_SM2_DECODE_FAIL;
    }
    (void)Sm2FetchString(eData + offset, len, decode + SM2_CURVE_BITS_WIDTH_TWICE, SM3_HASH_LEN, PRIM_OCT_STRING_TAG);
    offset += len;

    // get c2
    len = GetDecodeLen(eData, eLen, &offset, PRIM_OCT_STRING_TAG);
    if (len == 0 || (len > (*decodeLen - SM2_CURVE_BITS_WIDTH_TWICE - SM3_HASH_LEN))) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_DECODE_FAIL);
        return CRYPT_SM2_DECODE_FAIL;
    }
    (void)Sm2FetchString(eData + offset, len, decode + SM2_CURVE_BITS_WIDTH_TWICE + SM3_HASH_LEN, len,
        PRIM_OCT_STRING_TAG);
    *decodeLen = SM2_CURVE_BITS_WIDTH_TWICE + SM3_HASH_LEN + len;
    return ret;
}
#endif // HITLS_CRYPTO_SM2_CRYPT

#endif // HITLS_CRYPTO_ENCODE
