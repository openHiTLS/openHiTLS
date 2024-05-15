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

#define BITS_OF_NUM 4
#define BITS_OF_BYTE 8

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
    if (BnExtend(r, needRooms) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t offset = 0;
    while (left > 0) {
        BN_UINT num = 0; // single number
        uint32_t m = (left >= sizeof(BN_UINT)) ? sizeof(BN_UINT) : left;
        uint32_t i;
        for (i = m; i > 0; i--) { // big-endian
            num = (num << 8) | base[left - i];
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
        bin[sizeof(BN_UINT) - i - 1] = (uint8_t)(num >> (8 * i));
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

/* Convert BigNum to a 64-bit array in little-endian order. */
int32_t BN_Bn2U64Array(const BN_BigNum *a, uint64_t *array, uint32_t *len)
{
    if (a == NULL || array == NULL || len == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
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
    if (BnExtend(r, (uint32_t)needRoom) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
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

int32_t BN_BN2Array(const BN_BigNum *src, BN_UINT *dst, uint32_t size)
{
    if (src == NULL || dst == NULL || size == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
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
    if (dst == NULL || src == NULL || size == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BnExtend(dst, size) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // No error code is returned because the src has been checked NULL.
    (void)BN_Zeroize(dst);
    for (uint32_t i = 0; i < size; i++) {
        dst->data[i] = src[i];
    }
    dst->size = BinFixSize(dst->data, size);
    return CRYPT_SUCCESS;
}
#endif /* HITLS_CRYPTO_BN */
