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
#define    WORDBYTES    (WORDBITS/8)
#define BN_MAX_WORDSIZE                16

#define BN_MSB(x, w)        (((x)[w] >> (WORDBITS - 1)) & 1)

#define BN_LSB(x, w)        ((x)[0] & 1)

#define BN_BIT(x, i)        (((x)[(i) / WORDBITS] >> ((i) % WORDBITS)) & 1)

#ifdef  __cplusplus
extern "C" {
#endif

/*============================Part_1: Basic Functions=========================*/

// x <= 0
void bn_reset(uint32_t *x, int wsize);

// x <= n
void bn_set_int(uint32_t *x, int n, int wsize);

// y <= x
void bn_assign(uint32_t *y, const uint32_t *x, int wsize);

int bn_get_bytes(uint32_t *pWord, int wordlen, unsigned char *pByte, int bytelen);

int bn_put_bytes(unsigned char *pByte, int bytelen, uint32_t *pWord, int wordlen);

int bn_get_bitlen(const uint32_t *x, int wsize);

int bn_get_wordlen(const uint32_t *x, int wsize);

/*==================    Section: Comparison Operations    ======================
@Brief
==============================================================================*/

int bn_equal(const uint32_t *x, const uint32_t *y, int wsize);

// Big number compare function 1(x > y) 0(x = y) -1(x < y)
int bn_cmp(const uint32_t *x, const uint32_t *y, int wsize);

int bn_cmp_int(const uint32_t *x, unsigned int n, int wsize);

// if x equal 0 return 1, else return 0
int bn_is_zero(uint32_t *x, int wsize);

int bn_is_nonzero(uint32_t *x, int wsize);

// if x equal 1 return 1, else return 0
int bn_is_one(uint32_t *x, int wsize);

int bn_is_even(uint32_t *x);

int bn_is_odd(uint32_t *x);

/*==============================================================================
@Section    Logical Operations
@Brief      Logical operations are operations that can be performed either with
            simple shifts or boolean operators such as AND, XOR and OR directly.
==============================================================================*/

// y = x * 2 or y = x << 1
int bn_mul_2(uint32_t *y, const uint32_t *x, int wsize);

// y = x / 2 or y = x >> 1
int bn_div_2(uint32_t *y, const uint32_t *x, int wsize);

// Addition: r = x + y
uint32_t bn_add(uint32_t *r, const uint32_t *x, const uint32_t *y, int wsize);

// Subtraction: r = x - y
uint32_t bn_sub(uint32_t *r, const uint32_t *x, const uint32_t *y, int wsize);

// r = x + n
uint32_t bn_add_int(uint32_t *r, const uint32_t *x, unsigned int n, int wsize);

// r = x - n
uint32_t bn_sub_int(uint32_t *r, const uint32_t *x, unsigned int n, int wsize);

/*============================Part_2: Mod Functions============================*/

// r = x + y mod m
void bn_mod_add(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, int wsize);

// r = x - y mod m
void bn_mod_sub(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, int wsize);

// r = - y mod m
void bn_mod_neg(uint32_t *r, const uint32_t *x, const uint32_t *m, int wsize);

// r = y ^ -1 mod m
void bn_mod_inv(uint32_t *r, uint32_t *x, uint32_t *m, int wsize);

// r = x >> 1 mod m
void bn_mod_div_2(uint32_t *r, const uint32_t *x, const uint32_t *m, int wsize);

// x = x mod m
void bn_get_res(uint32_t *x, const uint32_t *m, int wsize);

/*==================____Section: Montgomery Reduction____========================
@Brief     Montgomery is a specialized reduction algorithm for any odd moduli.
----Before using montgomery reduction, integers should be normalized by multiplying
----it by R, where the pre-computed value R = b ^ n, n is the n number of digits in m
----and b is radix used (default is 2^32).
==============================================================================*/

/* Fast Montgomery initialization to get montgomery const(mc)*/
int bn_mont_init(uint32_t *mc, const uint32_t *m);

/* Montgomery multiplication: r = x * y * R^-1 mod m  (HAC 14.36) */
void bn_mont_mul(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, uint32_t mc, int wsize);

/* Montgomery reduction: r = x^2 * R^-1 mod m */
void bn_mont_redc(uint32_t *r, const uint32_t *x, const uint32_t *m, uint32_t mc, int wsize);

/* r = x^2 * R^-1 mod m */
void bn_mont_squ(uint32_t *r, const uint32_t *x, const uint32_t *m, uint32_t mc, int wsize);

// r = x ^ e mod m ( e is normal mode )
void bn_mont_exp(uint32_t *r, const uint32_t *x, const uint32_t *e, const uint32_t *m, uint32_t mc, int wsize);

// r = x ^ 1/2 mod m (sometime not exist square root, return -1)
int bn_mont_sqrt(uint32_t* r, const uint32_t *x, const uint32_t *m, uint32_t mc, int wsize);

// Get parity of integer x (If x is odd, return 1, else return 0)
int bn_mont_parity(uint32_t *x, const uint32_t *m, uint32_t mc, int wsize);

/*============================================================================*/

void BN_Print(uint32_t *pwBN, int32_t wsize);

void BN_GetLen(int32_t *pBitLen, int32_t *pWordLen, uint32_t *pwBN, int32_t wsize);

void BN_GetInv_Mont(uint32_t *r, uint32_t *x, uint32_t *m, uint32_t wModuleConst, uint32_t *pwRRModule, int wsize);

void BN_Random(uint32_t *pwBN, int32_t wsize);

int32_t BN_Mod_Basic(uint32_t *rem, int32_t iBNWordLen_r, uint32_t *pwBNX, int32_t iBNWordLen_X, uint32_t *pwBNM, int32_t iBNWordLen_M);

int32_t ByteToBN(const uint8_t *pByteBuf, int32_t bytelen, uint32_t *pwBN, int32_t wsize);
int32_t BNToByte(uint32_t *pwBN, int32_t wsize, uint8_t *pByteBuf, int32_t *bytelen);

int BN_WriteBytes(unsigned char *pbDst, int iWords, uint32_t *pwSrc);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9

#endif /* __HEADER_BN_H__ */

