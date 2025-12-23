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

#ifndef __HEADER_BN_H__
#define __HEADER_BN_H__

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include <stdint.h>

// macro for common bn
#define WordLen                        32
#define ByteLen                        8
#define WordByteLen                    (WordLen/ByteLen)
#define LSBOfWord                    0x00000001
#define MSBOfWord                    0x80000000

// macro for BN in SM9
#define BNBitLen                    256
#define BNByteLen                    (BNBitLen/ByteLen)
#define BNWordLen                    (BNBitLen/WordLen)

#define WORDBITS    32
#define WORDBYTES    (WORDBITS/8)
#define BN_MAX_WORDSIZE    16

#define BN_MSB(x, w)        (((x)[w] >> (WORDBITS - 1)) & 1)
#define BN_LSB(x, w)        ((x)[0] & 1)
#define BN_BIT(x, i)        (((x)[(i) / WORDBITS] >> ((i) % WORDBITS)) & 1)

#ifdef  __cplusplus
extern "C" {
#endif

/*============================Part_1: Basic Functions=========================*/

// x <= 0
void bn_reset(uint32_t *x, int32_t wsize);

// x <= n
void bn_set_int(uint32_t *x, int32_t n, int32_t wsize);

// y <= x
void bn_assign(uint32_t *y, const uint32_t *x, int32_t wsize);

int32_t bn_get_bitlen(const uint32_t *x, int32_t wsize);

int32_t bn_get_wordlen(const uint32_t *x, int32_t wsize);

/*==================    Section: Comparison Operations    ======================
@Brief
==============================================================================*/

int32_t bn_equal(const uint32_t *x, const uint32_t *y, int32_t wsize);

// Big number compare function 1(x > y) 0(x = y) -1(x < y)
int32_t bn_cmp(const uint32_t *x, const uint32_t *y, int32_t wsize);

// if x equal 0 return 1, else return 0
int32_t bn_is_zero(uint32_t *x, int32_t wsize);

int32_t bn_is_nonzero(uint32_t *x, int32_t wsize);

/*==============================================================================
@Section    Logical Operations
@Brief      Logical operations are operations that can be performed either with
            simple shifts or boolean operators such as AND, XOR and OR directly.
==============================================================================*/

// y = x / 2 or y = x >> 1
int32_t bn_div_2(uint32_t *y, const uint32_t *x, int32_t wsize);

// Addition: r = x + y
uint32_t bn_add(uint32_t *r, const uint32_t *x, const uint32_t *y, int32_t wsize);

// Subtraction: r = x - y
uint32_t bn_sub(uint32_t *r, const uint32_t *x, const uint32_t *y, int32_t wsize);

// r = x + n
uint32_t bn_add_int(uint32_t *r, const uint32_t *x, uint32_t n, int32_t wsize);

// r = x - n
uint32_t bn_sub_int(uint32_t *r, const uint32_t *x, uint32_t n, int32_t wsize);

/*============================Part_2: Mod Functions============================*/

// r = x + y mod m
void bn_mod_add(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, int32_t wsize);

// r = x - y mod m
void bn_mod_sub(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, int32_t wsize);

// r = - y mod m
void bn_mod_neg(uint32_t *r, const uint32_t *x, const uint32_t *m, int32_t wsize);

// r = y ^ -1 mod m
void bn_mod_inv(uint32_t *r, uint32_t *x, uint32_t *m, int32_t wsize);

// r = x >> 1 mod m
void bn_mod_div_2(uint32_t *r, const uint32_t *x, const uint32_t *m, int32_t wsize);

// x = x mod m
void bn_get_res(uint32_t *x, const uint32_t *m, int32_t wsize);

/*==================____Section: Montgomery Reduction____========================
@Brief     Montgomery is a specialized reduction algorithm for any odd moduli.
----Before using montgomery reduction, integers should be normalized by multiplying
----it by R, where the pre-computed value R = b ^ n, n is the n number of digits in m
----and b is radix used (default is 2^32).
==============================================================================*/

/* Montgomery multiplication: r = x * y * R^-1 mod m  (HAC 14.36) */
void bn_mont_mul(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, uint32_t mc, int32_t wsize);

/* Montgomery reduction: r = x^2 * R^-1 mod m */
void bn_mont_redc(uint32_t *r, const uint32_t *x, const uint32_t *m, uint32_t mc, int32_t wsize);
/*============================================================================*/

void BN_GetInv_Mont(uint32_t *r, uint32_t *x, uint32_t *m, uint32_t wModuleConst, uint32_t *pwRRModule, int32_t wsize);

int32_t BN_Mod_Basic(uint32_t *rem, int32_t iBNWordLen_r, uint32_t *pwBNX,
                     int32_t iBNWordLen_X, uint32_t *pwBNM, int32_t iBNWordLen_M);

int32_t ByteToBN(const uint8_t *pByteBuf, int32_t bytelen, uint32_t *pwBN, int32_t wsize);
int32_t BNToByte(uint32_t *pwBN, int32_t wsize, uint8_t *pByteBuf, int32_t *bytelen);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9

#endif /* __HEADER_BN_H__ */

