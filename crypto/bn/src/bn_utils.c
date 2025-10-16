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
#ifdef HITLS_CRYPTO_BN

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "bn_basic.h"
#include "bn_bincal.h"
#include "bsl_sal.h"

int32_t BN_Bin2Bn(BN_BigNum *r, const uint8_t *bin, uint32_t binLen)
{
    if (r == NULL || bin == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)BN_Zeroize(r);
    uint32_t zeroNum = 0;
    for (; zeroNum < binLen; zeroNum++) {
        if (bin[zeroNum] != 0) {
            break;
        }
    }
    if (zeroNum == binLen) {
        // All data is 0.
        return CRYPT_SUCCESS;
    }
    const uint8_t *base = bin + zeroNum;
    uint32_t left = binLen - zeroNum;
    uint32_t needRooms = (left % sizeof(BN_UINT) == 0) ? left / sizeof(BN_UINT)
                                                    : (left / sizeof(BN_UINT)) + 1;
    int32_t ret = BnExtend(r, needRooms);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t offset = 0;
    while (left > 0) {
        BN_UINT num = 0; // single number
        uint32_t m = (left >= sizeof(BN_UINT)) ? sizeof(BN_UINT) : left;
        uint32_t i;
        for (i = m; i > 0; i--) { // big-endian
            num = (num << 8) | base[left - i]; // 8: indicates the number of bits in a byte.
        }
        r->data[offset++] = num;
        left -= m;
    }
    r->size = BinFixSize(r->data, offset);
    return CRYPT_SUCCESS;
}

/* convert BN_UINT to bin */
static inline void Limb2Bin(uint8_t *bin, BN_UINT num)
{
    // convert BN_UINT to bin: buff[0] is the most significant bit.
    uint32_t i;
    for (i = 0; i < sizeof(BN_UINT); i++) { // big-endian
        bin[sizeof(BN_UINT) - i - 1] = (uint8_t)(num >> (8 * i)); // 8: indicates the number of bits in a byte.
    }
}

int32_t BN_Bn2Bin(const BN_BigNum *a, uint8_t *bin, uint32_t *binLen)
{
    if (a == NULL || bin == NULL || binLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t bytes = BN_Bytes(a);
    bytes = (bytes == 0) ? 1 : bytes; // If bytes is 0, 1 byte 0 data needs to be output.
    if (*binLen < bytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_BN_BUFF_LEN_NOT_ENOUGH;
    }
    int32_t ret = BN_Bn2BinFixZero(a, bin, bytes);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *binLen = bytes;
    return ret;
}

void BN_FixSize(BN_BigNum *a)
{
    if (a == NULL) {
        return;
    }
    a->size = BinFixSize(a->data, a->size);
}

int32_t BN_Extend(BN_BigNum *a, uint32_t words)
{
    return BnExtend(a, words);
}

// Padded 0s before bin to obtain the output data whose length is binLen.
int32_t BN_Bn2BinFixZero(const BN_BigNum *a, uint8_t *bin, uint32_t binLen)
{
    if (a == NULL || bin == NULL || binLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t bytes = BN_Bytes(a);
    if (binLen < bytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_BN_BUFF_LEN_NOT_ENOUGH;
    }
    uint32_t fixLen = binLen - bytes;
    uint8_t *base = bin + fixLen;
    (void)memset_s(bin, binLen, 0, fixLen);
    if (bytes == 0) {
        return CRYPT_SUCCESS;
    }

    uint32_t index = a->size - 1;
    uint32_t left = bytes % sizeof(BN_UINT); // High-order non-integrated data
    uint32_t offset = 0;
    while (left != 0) {
        base[offset] = (uint8_t)((a->data[index] >> (8 * (left - 1))) & 0xFF); // 1byte = 8bit
        left--;
        offset++;
    }
    if (offset != 0) {
        index--;
    }
    uint32_t num = bytes / sizeof(BN_UINT); // High-order non-integrated data

    // Cyclically parse the entire data block.
    for (uint32_t i = 0; i < num; i++) {
        Limb2Bin(base + offset, a->data[index]);
        index--;
        offset += sizeof(BN_UINT);
    }

    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_CURVE_SM2_ASM) ||                                                 \
    ((defined(HITLS_CRYPTO_CURVE_NISTP521) || defined(HITLS_CRYPTO_CURVE_NISTP384_ASM)) && \
        defined(HITLS_CRYPTO_NIST_USE_ACCEL))
/* Convert BigNum to a 64-bit array in little-endian order. */
int32_t BN_Bn2U64Array(const BN_BigNum *a, uint64_t *array, uint32_t *len)
{
    // Number of BN_UINTs that can be accommodated
    const uint64_t capacity = ((uint64_t)(*len)) * (sizeof(uint64_t) / sizeof(BN_UINT));
    if (a->size > capacity || *len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    if (BN_IsZero(a)) {
        *len = 1;
        array[0] = 0;
        return CRYPT_SUCCESS;
    }
    // BN_UINT is 64-bit or 32-bit. Select one during compilation.
    if (sizeof(BN_UINT) == sizeof(uint64_t)) {
        uint32_t i = 0;
        for (; i < a->size; i++) {
            array[i] = a->data[i];
        }
        *len = i;
    }
    if (sizeof(BN_UINT) == sizeof(uint32_t)) {
        uint32_t i = 0;
        uint32_t j = 0;
        for (; i < a->size - 1; i += 2) { // processes 2 BN_UINT each time. Here, a->size >= 1
            array[j] = a->data[i];
            array[j] |= ((uint64_t)a->data[i + 1]) << 32; // in the upper 32 bits
            j++;
        }
        // When a->size is an odd number, process the tail.
        if (i < a->size) {
            array[j++] = a->data[i];
        }
        *len = j;
    }
    return CRYPT_SUCCESS;
}

/* Convert a 64-bit array in little-endian order to a BigNum. */
int32_t BN_U64Array2Bn(BN_BigNum *r, const uint64_t *array, uint32_t len)
{
    const uint64_t needRoom = ((uint64_t)len) * sizeof(uint64_t) / sizeof(BN_UINT);
    if (r == NULL || array == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (needRoom > UINT32_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BITS_TOO_MAX);
        return CRYPT_BN_BITS_TOO_MAX;
    }
    int32_t ret = BnExtend(r, (uint32_t)needRoom);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    (void)BN_Zeroize(r);
    // BN_UINT is 64-bit or 32-bit. Select one during compilation.
    if (sizeof(BN_UINT) == sizeof(uint64_t)) {
        for (uint32_t i = 0; i < needRoom; i++) {
            r->data[i] = array[i];
        }
    }
    if (sizeof(BN_UINT) == sizeof(uint32_t)) {
        for (uint64_t i = 0; i < len; i++) {
            r->data[i * 2] = (BN_UINT)array[i]; // uint64_t is twice the width of uint32_t.
            // obtain the upper 32 bits, uint64_t is twice the width of uint32_t.
            r->data[i * 2 + 1] = (BN_UINT)(array[i] >> 32);
        }
    }
    // can be forcibly converted to 32 bits because needRoom <= r->room
    r->size = BinFixSize(r->data, (uint32_t)needRoom);
    return CRYPT_SUCCESS;
}
#endif

#if defined(HITLS_CRYPTO_CURVE_SM2_ASM) || (defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) && \
    defined(HITLS_CRYPTO_NIST_USE_ACCEL))
int32_t BN_BN2Array(const BN_BigNum *src, BN_UINT *dst, uint32_t size)
{
    if (size < src->size) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_BN_BUFF_LEN_NOT_ENOUGH;
    }

    (void)memset_s(dst, size * sizeof(BN_UINT), 0, size * sizeof(BN_UINT));
    for (uint32_t i = 0; i < src->size; i++) {
        dst[i] = src->data[i];
    }
    return CRYPT_SUCCESS;
}

int32_t BN_Array2BN(BN_BigNum *dst, const BN_UINT *src, const uint32_t size)
{
    int32_t ret = BnExtend(dst, size);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // No error code is returned because the src has been checked NULL.
    (void)BN_Zeroize(dst);
    for (uint32_t i = 0; i < size; i++) {
        dst->data[i] = src[i];
    }
    dst->size = BinFixSize(dst->data, size);
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_BN_STR_CONV

static const char HEX_MAP[] = "0123456789ABCDEF"; // Hexadecimal value corresponding to 0-15

#define BITS_OF_NUM 4
#define BITS_OF_BYTE 8

static bool IsXdigit(const char str, bool isHex)
{
    if ((str >= '0') && (str <= '9')) {
        return true;
    }
    if (isHex) {
        if ((str >= 'A') && (str <= 'F')) {
            return true;
        }
        if ((str >= 'a') && (str <= 'f')) {
            return true;
        }
    }
    return false;
}

static unsigned char StrToHex(char str)
{
    if ((str >= '0') && (str <= '9')) {
        return (unsigned char)(str - '0');
    }
    if ((str >= 'A') && (str <= 'F')) {
        return (unsigned char)(str - 'A' + 10); // Hexadecimal. A~F offset 10
    }
    if ((str >= 'a') && (str <= 'f')) {
        return (unsigned char)(str - 'a' + 10); // Hexadecimal. a~f offset 10
    }
    return 0x00; // Unexpected character string, which is processed as 0.
}

static int32_t CheckInputStr(int32_t *outLen, const char *str, int32_t *negtive, bool isHex)
{
    int32_t len = 0;
    int32_t strMax = BN_MAX_BITS / BITS_OF_NUM; // BigNum storage limit: 2^29 bits
    const char *inputStr = str;

    if (str[0] == '\0') {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_CONVERT_INPUT_INVALID);
        return CRYPT_BN_CONVERT_INPUT_INVALID;
    }
    if (str[0] == '-') {
        *negtive = 1;
        inputStr++;
    }

    int32_t initStrLen = strlen(inputStr);
    if (initStrLen == 0 || initStrLen > strMax) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_CONVERT_INPUT_INVALID);
        return CRYPT_BN_CONVERT_INPUT_INVALID;
    }
    while (len < initStrLen) {
        if (!IsXdigit(inputStr[len++], isHex)) { // requires that the entire content of a character string must be valid
            BSL_ERR_PUSH_ERROR(CRYPT_BN_CONVERT_INPUT_INVALID);
            return CRYPT_BN_CONVERT_INPUT_INVALID;
        }
    }
    *outLen = len;

    return CRYPT_SUCCESS;
}

static int32_t OutputCheck(BN_BigNum **r, int32_t num)
{
    uint32_t needBits = (uint32_t)num * BITS_OF_NUM;
    if (*r == NULL) {
        *r = BN_Create(needBits);
        if (*r == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    } else {
        int32_t ret = BnExtend(*r, BITS_TO_BN_UNIT(needBits));
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        (void)BN_Zeroize(*r);
    }
    return CRYPT_SUCCESS;
}

int32_t BN_Hex2Bn(BN_BigNum **r, const char *str)
{
    int32_t len;
    int32_t negtive = 0;
    if (r == NULL || str == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const char *inputStr = str;
    int32_t ret = CheckInputStr(&len, inputStr, &negtive, true);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = OutputCheck(r, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BN_UINT *p = (*r)->data;
    if (negtive != 0) {
        inputStr++;
    }
    int32_t unitBytes;
    uint32_t tmpval = 0;
    uint32_t size = 0; // Record the size that r will use.
    int32_t bytes = sizeof(BN_UINT);
    BN_UINT unitValue;
    while (len > 0) {
        unitBytes = (bytes * 2 <= len) ? bytes * 2 : len; // Prevents the number of char left being less than bytes *2
        unitValue = 0;
        for (; unitBytes > 0; unitBytes--) {
            // interface ensures that all characters are valid at the begining
            tmpval = StrToHex(inputStr[len - unitBytes]);
            unitValue = (unitValue << 4) | tmpval; // The upper bits are shifted rightwards by 4 bits each time.
        }
        p[size++] = unitValue;
        len -= bytes * 2; // Length of the character stream processed each time = Number of bytes x 2
    }
    (*r)->size = BinFixSize(p, size);
    if (!BN_IsZero(*r)) {
        (*r)->sign = negtive;
    }
    return CRYPT_SUCCESS;
}

char *BN_Bn2Hex(const BN_BigNum *a)
{
    uint32_t bytes = sizeof(BN_UINT);
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    // output character stream = Number of bytes x 2 + minus sign + terminator
    char *ret = (char *)BSL_SAL_Malloc(a->size * bytes * 2 + 2);
    if (ret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    char *p = ret;
    if (BN_IsZero(a)) {
        *p++ = '0';
        *p++ = '\0';
        return ret;
    }
    if (a->sign) {
        *p++ = '-';
    }
    bool leadingZeros = true;
    for (int32_t i = a->size - 1; i >= 0; i--) {
        // processes data in a group of 8 bits
        for (int32_t j = (int32_t)(bytes * BITS_OF_BYTE - BITS_OF_BYTE); j >= 0; j -= 8) {
            uint32_t chars = (uint32_t)((a->data[i] >> (uint32_t)j) & 0xFF); // Take the last eight bits.
            if (leadingZeros && (chars == 0)) {
                continue;
            }
            *p++ = HEX_MAP[chars >> 4]; // Higher 4 bits
            *p++ = HEX_MAP[chars & 0x0F]; // Lower 4 bits
            leadingZeros = false;
        }
    }
    *p = '\0';
    return ret;
}

static int32_t CalBnData(BN_BigNum **r, int32_t num, const char *inputStr)
{
    int32_t ret = CRYPT_INVALID_ARG;
    int32_t optTimes;
    int32_t len = num;
    const char *p = inputStr;
    BN_UINT unitValue = 0;
    /*
     * Processes decimal strings in groups of BN_DEC_LEN.
     * If the length of a string is not a multiple of BN_DEC_LEN, then in the first round of string processing,
       handle according to the actual length of less than BN_DEC_LEN
     */
    optTimes = (len % BN_DEC_LEN == 0) ? 0 : (BN_DEC_LEN - len % BN_DEC_LEN);
    while (len > 0) {
        // keep the upper limit of each round of traversal as BN_DEC_LEN
        for (; optTimes < BN_DEC_LEN; optTimes++, len--) {
            unitValue *= 10; // A decimal number is multiplied by 10 and then added.
            unitValue += *p - '0';
            p++;
        }

        ret = BN_MulLimb(*r, *r, BN_DEC_VAL);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }

        ret = BN_AddLimb(*r, *r, unitValue);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        unitValue = 0;
        optTimes = 0;
    }

ERR:
    return ret;
}

int32_t BN_Dec2Bn(BN_BigNum **r, const char *str)
{
    int32_t num;
    int32_t negtive = 0;
    if (r == NULL || str == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const char *inputStr = str;
    int32_t ret = CheckInputStr(&num, inputStr, &negtive, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = OutputCheck(r, num);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (negtive != 0) {
        inputStr++;
    }
    ret = CalBnData(r, num, inputStr);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (!BN_IsZero(*r)) {
        (*r)->sign = negtive;
    }
    return ret;
}

static int32_t CalDecStr(const BN_BigNum *a, BN_UINT *bnInit, uint32_t unitNum, uint32_t *step)
{
    int32_t ret = CRYPT_INVALID_ARG;
    BN_UINT *valNow = bnInit;
    uint32_t index = 0;
    BN_BigNum *bnDup = BN_Dup(a);
    if (bnDup == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }

    while (!BN_IsZero(bnDup)) {
        BN_UINT rem;
        // index records the amount of BN_UINT offset, cannot exceed the maximum value unitNum
        if (index == unitNum) {
            ret = CRYPT_SECUREC_FAIL;
            goto ERR;
        }
        ret = BN_DivLimb(bnDup, &rem, bnDup, BN_DEC_VAL);
        if (ret != CRYPT_SUCCESS) {
            goto ERR;
        }
        valNow[index++] = rem;
    }
    (*step) = index - 1;
ERR:
    BN_Destroy(bnDup);
    return ret;
}

static int32_t NumToStr(char *output, uint32_t *restLen, BN_UINT valNow, bool isNeedPad, uint32_t *printNum)
{
    BN_UINT num = valNow;
    char *target = output;
    uint32_t len = 0;
    do {
        if (*restLen < len + 1) {
            BSL_ERR_PUSH_ERROR(CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
            return CRYPT_BN_BUFF_LEN_NOT_ENOUGH;
        }
        // The ASCII code of 0 to 9 is [48, 57]
        target[len++] = num % 10 + 48; // Take last num by mod 10, and convet to 'char'.
        num /= 10; // for taken the last digit by dividing 10
    } while (num != 0);

    if (isNeedPad) {
        if (*restLen < BN_DEC_LEN) {
            BSL_ERR_PUSH_ERROR(CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
            return CRYPT_BN_BUFF_LEN_NOT_ENOUGH;
        }
        while (len < BN_DEC_LEN) {
            target[len++] = '0';
        }
    }

    // Symmetrically swapped values at both ends, needs len / 2 times.
    for (uint32_t j = 0; j < len / 2; j++) {
        char t = target[j];
        target[j] = target[len - 1 - j];
        target[len - 1 - j] = t;
    }
    *restLen -= len;
    *printNum = len;
    return CRYPT_SUCCESS;
}

static int32_t FmtDecOutput(char *output, uint32_t outLen, const BN_UINT *bnInit, uint32_t steps)
{
    uint32_t cpyNum = 0;
    char *outputPtr = output;
    uint32_t index = steps;
    uint32_t restLen = outLen - 1; // Reserve the position of the terminator.
    int32_t ret = NumToStr(outputPtr, &restLen, *(bnInit + index), false, &cpyNum);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    outputPtr += cpyNum;
    while (index-- != 0) {
        ret = NumToStr(outputPtr, &restLen, *(bnInit + index), true, &cpyNum);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        outputPtr += cpyNum;
    }
    *outputPtr = '\0';
    return CRYPT_SUCCESS;
}

char *BN_Bn2Dec(const BN_BigNum *a)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    int32_t ret;
    char *p = NULL;
    uint32_t steps = 0;
    /*
     * Estimate the maximum length of a decimal BigNum
     * x <= 10 ^ y < 2 ^ (bit + 1)
     * y < lg_(2) ( 2 ^ (bit + 1))
     * y < (bit + 1) * lg2 -- (lg_2 = 0.30102999566...)
     * y < (bit + 1) * 0.303
     * y < 3 * bit * 0.001 +  3 * bit * 0.100 + 1
     */
    uint32_t numLen = (BN_Bits(a) * 3) / 10 + (BN_Bits(a) * 3) / 1000 + 1;
    uint32_t outLen = numLen + 3; // Add the sign, end symbol, and buffer space.
    uint32_t unitNum = (numLen / BN_DEC_LEN) + 1;
    char *result = BSL_SAL_Malloc(outLen);
    BN_UINT *bnInit = (BN_UINT *)BSL_SAL_Malloc(unitNum * sizeof(BN_UINT));
    if (result == NULL || bnInit == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }

    p = result;
    if (BN_IsZero(a)) {
        *p++ = '0';
        *p++ = '\0';
        ret = CRYPT_SUCCESS;
        goto ERR;
    }

    if (a->sign) {
        *p++ = '-';
        outLen--;
    }
    ret = CalDecStr(a, bnInit, unitNum, &steps);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = FmtDecOutput(p, outLen, bnInit, steps);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

ERR:
    BSL_SAL_FREE(bnInit);
    if (ret == CRYPT_SUCCESS) {
        return result;
    }
    BSL_SAL_FREE(result);
    return NULL;
}
#endif /* HITLS_CRYPTO_BN_STR_CONV */

#endif /* HITLS_CRYPTO_BN */
