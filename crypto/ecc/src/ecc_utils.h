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

#ifndef ECC_UTILS_H
#define ECC_UTILS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECC

#include "crypt_ecc.h"
#include "ecc_local.h"
#include "crypt_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the window length of common point multiplication */
#define WINDOW_SIZE 5

/*
 * Decoded from a 6-bit signed code to obtain the sign and value. The upper five bits are the complement of the value,
 * and the least significant bit is the carry (positive) of the next group of numbers.
 * Output:
 *      sign = 0 or 1
 *      0 <= value <= 16
 */
inline static void DecodeScalarCode(uint32_t *sign, uint32_t *value, uint32_t code)
{
    uint32_t s, v;
    s = 0 - (code >> WINDOW_SIZE);  // Bit 5 is the sign bit, and the negative number is all 1s.
    // Take its value and add a carry. Because the symbol is obtained and then the carry is added, v may be + 16 or - 0.
    v = (code >> 1) + (code & 1);
    // Find the Take its value and add a carry. If the number is positive, v is the Take its value and add a carry.
    // If the number is negative, v is inverted + 1.
    v = (~s & v) | (s & (~v + 1));

    *sign = s & 1;
    *value = v & ((1 << WINDOW_SIZE) - 1);  // Five bits are intercepted.
}

inline static int32_t CheckParaValid(const ECC_Para *para, CRYPT_PKEY_ParaId id)
{
    if (para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (para->id != id) {
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    return CRYPT_SUCCESS;
}

inline static int32_t CheckPointValid(const ECC_Point *pt, CRYPT_PKEY_ParaId id)
{
    if (pt == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (pt->id != id) {
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    return CRYPT_SUCCESS;
}

inline static int32_t CheckBnValid(const BN_BigNum *k, uint32_t maxBits)
{
    if (k == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (BN_Bits(k) > maxBits) {  // If K is greater than maxBits, it is considered too long.
        return CRYPT_ECC_POINT_MUL_ERR_K_LEN;
    }
    return CRYPT_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ECC

#endif // ECC_UTILS_H
