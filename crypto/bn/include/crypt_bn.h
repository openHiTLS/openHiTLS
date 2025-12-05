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

#ifndef CRYPT_BN_H
#define CRYPT_BN_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(HITLS_SIXTY_FOUR_BITS)
#define BN_UINT uint64_t
#define BN_MASK (0xffffffffffffffffL)
#define BN_DEC_VAL (10000000000000000000ULL)
#define BN_DEC_LEN 19
#define BN_UNIT_BITS 64
#elif defined(HITLS_THIRTY_TWO_BITS)
#define BN_UINT uint32_t
#define BN_MASK (0xffffffffL)
#define BN_DEC_VAL (1000000000L)
#define BN_DEC_LEN 9
#define BN_UNIT_BITS 32
#else
#error BN_UINT MUST be defined first.
#endif

#define BN_MAX_BITS         (1u << 29) /* @note: BN_BigNum bits limitation 2^29 bits */
#define BN_BITS_TO_BYTES(n) (((n) + 7) >> 3) /* @note: Calcute bytes form bits, bytes = (bits + 7) >> 3 */
#define BN_BYTES_TO_BITS(n) ((n) << 3) /* bits = bytes * 8 = bytes << 3 */
#define BN_UINT_BITS ((uint32_t)sizeof(BN_UINT) << 3)
#define BITS_TO_BN_UNIT(bits) (((bits) + BN_UINT_BITS - 1) / BN_UINT_BITS)
/* Flag of BigNum. If a new number is added, the value increases by 0x01 0x02 0x04... */
typedef enum {
    CRYPT_BN_FLAG_OPTIMIZER = 0x01,      /**< Flag of BigNum, indicating the BigNum obtained from the optimizer */
    CRYPT_BN_FLAG_STATIC = 0x02,      /**< Flag of BigNum, indicating the BN memory management belongs to the user. */
    CRYPT_BN_FLAG_CONSTTIME = 0x04,      /**< Flag of BigNum, indicating the constant time execution. */
} CRYPT_BN_FLAG;

typedef struct BigNum {
    bool sign; /* *< bignum sign: negtive(true) or not(false) */
    uint32_t size; /* *< bignum size (count of BN_UINT) */
    uint32_t room; /* *< bignum max size (count of BN_UINT) */
    uint32_t flag; /* *< bignum flag */
    BN_UINT *data; /* *< bignum data chunk(most significant limb at the largest) */
} BN_BigNum;

typedef struct BnMont BN_Mont;

typedef struct BnOptimizer BN_Optimizer;

typedef struct BnCbCtx BN_CbCtx;
 
typedef int32_t (*BN_CallBack)(BN_CbCtx *, int32_t, int32_t);

/* If a is 0, all Fs are returned. If a is not 0, 0 is returned. */
static inline BN_UINT BN_IsZeroUintConsttime(BN_UINT a)
{
    BN_UINT t = ~a & (a - 1); // The most significant bit of t is 1 only when a == 0.
    // Shifting 3 bits to the left is equivalent to multiplying 8, convert the number of bytes into the number of bits.
    return (BN_UINT)0 - (t >> (((uint32_t)sizeof(BN_UINT) << 3) - 1));
}

#ifdef HITLS_CRYPTO_EAL_BN
/* Check whether the BN entered externally is valid. */
bool BnVaild(const BN_BigNum *a);
#endif

/**
 * @ingroup bn
 * @brief   BigNum creation
 *
 * @param   bits [IN] Number of bits
 *
 * @retval not-NULL Success
 * @retval NULL fail
 */
BN_BigNum *BN_Create(uint32_t bits);

/**
 * @ingroup bn
 * @brief   BigNum Destruction
 *
 * @param   a [IN] BigNum
 *
 * @retval none
 */
void BN_Destroy(BN_BigNum *a);

/**
 * @ingroup bn
 * @brief   BN initialization
 * @attention This interface is used to create the BN structure between modules. The BN does not manage the memory of
              the external BN structure and internal data space. the interface only the fixed attributes such as data,
              room, and flag. The size attribute is defined by the caller.
 *
 * @param   bn [IN/OUT] BN, which is created by users and is not managed by the BN.
 * @param   data [IN] BN data, the memory is allocated by the user and is not managed by the BN.
 * @param   number [IN] number of BN that need to be initialized.
 *
 * @retval void
 */
void BN_Init(BN_BigNum *bn, BN_UINT *data, uint32_t room, int32_t number);

#ifdef HITLS_CRYPTO_BN_CB

/**
 * @ingroup bn
 * @brief   BigNum callback creation
 *
 * @param   none
 *
 * @retval not-NULL Success
 * @retval NULL fail
 */
BN_CbCtx *BN_CbCtxCreate(void);

/**
 * @ingroup bn
 * @brief   BigNum callback configuration
 *
 * @param   gencb [out] Callback
 * @param   callBack [in] Callback API
 * @param   arg [in] Callback parameters
 *
 * @retval none
 */
void BN_CbCtxSet(BN_CbCtx *gencb, BN_CallBack callBack, void *arg);

/**
 * @ingroup bn
 * @brief   Invoke the callback.
 *
 * @param   callBack [out] Callback
 * @param   process [in] Parameter
 * @param   target [in] Parameter

 * @retval CRYPT_SUCCESS    succeeded
 * @retval other            determined by the callback function
 */
int32_t BN_CbCtxCall(BN_CbCtx *callBack, int32_t process, int32_t target);

/**
 * @ingroup bn
 * @brief Obtain the arg parameter in the callback.
 *
 * @param callBack [in] Callback
 * @retval void* NULL or callback parameter.
 */
void *BN_CbCtxGetArg(BN_CbCtx *callBack);

/**
 * @ingroup bn
 * @brief   Callback release
 *
 * @param   cb [in] Callback
 *
 * @retval none
 */
void BN_CbCtxDestroy(BN_CbCtx *cb);
#endif

/**
 * @ingroup bn
 * @brief Set the symbol.
 *
 * @param a    [IN] BigNum
 * @param sign [IN] symbol. The value true indicates a negative number and the value false indicates a positive number.
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT         Invalid null pointer
 * @retval CRYPT_BN_NO_NEGATOR_ZERO 0 cannot be set to a negative sign.
 */
int32_t BN_SetSign(BN_BigNum *a, bool sign);

/**
 * @ingroup bn
 * @brief Set the flag.
 *
 * @param a    [IN] BigNum
 * @param flag [IN] flag, for example, BN_MARK_CONSTTIME indicates that the constant interface is used.
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT         Invalid null pointer
 * @retval CRYPT_BN_FLAG_INVALID    Invalid BigNum flag.
 */
int32_t BN_SetFlag(BN_BigNum *a, uint32_t flag);

/**
 * @ingroup bn
 * @brief BigNum copy
 *
 * @param r [OUT] BigNum
 * @param a [IN] BigNum
 *
 * @retval CRYPT_SUCCESS            succeeded.
 * @retval CRYPT_NULL_INPUT         Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 */
int32_t BN_Copy(BN_BigNum *r, const BN_BigNum *a);

/**
 * @ingroup bn
 * @brief Generate a BigNum with the same content.
 *
 * @param a [IN] BigNum
 *
 * @retval Not NULL  Success
 * @retval NULL      failure
 */
BN_BigNum *BN_Dup(const BN_BigNum *a);

/**
 * @ingroup bn
 * @brief Check whether the value of a BigNum is 0.
 *
 * @attention The input parameter cannot be null.
 * @param a [IN] BigNum
 *
 * @retval true. The value of a BigNum is 0.
 * @retval false. The value of a BigNum is not 0.
 * @retval other: indicates that the input parameter is abnormal.
 *
 */
bool BN_IsZero(const BN_BigNum *a);

/**
 * @ingroup bn
 * @brief Check whether the value of a BigNum is 1.
 *
 * @attention The input parameter cannot be null.
 * @param a [IN] BigNum
 *
 * @retval true. The value of a BigNum is 1.
 * @retval false. The value of a BigNum is not 1.
 * @retval other: indicates that the input parameter is abnormal.
 *
 */
bool BN_IsOne(const BN_BigNum *a);

/**
 * @ingroup bn
 * @brief Check whether a BigNum is a negative number.
 *
 * @attention The input parameter cannot be null.
 * @param a [IN] BigNum
 *
 * @retval true. The value of a BigNum is a negative number.
 * @retval false. The value of a BigNum is not a negative number.
 *
 */
bool BN_IsNegative(const BN_BigNum *a);

/**
 * @ingroup bn
 * @brief Check whether the value of a BigNum is an odd number.
 *
 * @attention The input parameter cannot be null.
 * @param a [IN] BigNum
 *
 * @retval true. The value of a BigNum is an odd number.
 * @retval false. The value of a BigNum is not an odd number.
 * @retval other: indicates that the input parameter is abnormal.
 *
 */
bool BN_IsOdd(const BN_BigNum *a);

/**
 * @ingroup bn
 * @brief Check whether the flag of a BigNum meets the expected flag.
 *
 * @param a    [IN] BigNum
 * @param flag [IN] Flag. For example, BN_MARK_CONSTTIME indicates that the constant interface is used.
 *
 * @retval true, invalid null pointer
 * @retval false, 0 cannot be set to a negative number.
 * @retval other: indicates that the input parameter is abnormal.
 */
bool BN_IsFlag(const BN_BigNum *a, uint32_t flag);

/**
 * @ingroup bn
 * @brief Set the value of a BigNum to 0.
 *
 * @param a [IN] BigNum
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT Invalid null pointer
 * @retval other: indicates that the input parameter is abnormal.
 */
int32_t BN_Zeroize(BN_BigNum *a);

/**
 * @ingroup bn
 * @brief Compare whether the value of BigNum a is the target limb w.
 *
 * @attention The input parameter cannot be null.
 * @param a [IN] BigNum
 * @param w [IN] Limb
 *
 * @retval true: equal
 * @retval false, not equal
 * @retval other: indicates that the input parameter is abnormal.
 */
bool BN_IsLimb(const BN_BigNum *a, const BN_UINT w);

/**
 * @ingroup bn
 * @brief Set a limb to the BigNum.
 *
 * @param a [IN] BigNum
 * @param w [IN] Limb
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 */
int32_t BN_SetLimb(BN_BigNum *r, BN_UINT w);

/**
 * @ingroup bn
 * @brief Obtain the limb from the BigNum.
 *
 * @param a [IN] BigNum
 *
 * @retval 0        Get 0
 * @retval BN_MASK  Obtain the mask.
 * @retval others   The limb is obtained successfully.
 */
BN_UINT BN_GetLimb(const BN_BigNum *a);

/**
 * @ingroup bn
 * @brief Obtain the value of the bit corresponding to a BigNum. The value is 1 or 0.
 *
 * @attention The input parameter of a BigNum cannot be null.
 * @param a [IN] BigNum
 * @param n [IN] Number of bits
 *
 * @retval true. The corresponding bit is 1.
 * @retval false. The corresponding bit is 0.
 *
 */
bool BN_GetBit(const BN_BigNum *a, uint32_t n);

/**
 * @ingroup bn
 * @brief Set the bit corresponding to the BigNum to 1.
 *
 * @param a [IN] BigNum
 * @param n [IN] Number of bits
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_BN_SPACE_NOT_ENOUGH    The space is insufficient.
 */
int32_t BN_SetBit(BN_BigNum *a, uint32_t n);

/**
 * @ingroup bn
 * @brief Clear the bit corresponding to the BigNum to 0.
 *
 * @param a [IN] BigNum
 * @param n [IN] Number of bits
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_BN_SPACE_NOT_ENOUGH    The space is insufficient.
 */
int32_t BN_ClrBit(BN_BigNum *a, uint32_t n);

/**
 * @ingroup bn
 * @brief Truncate a BigNum from the corresponding bit.
 *
 * @param a [IN] BigNum
 * @param n [IN] Number of bits
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_BN_SPACE_NOT_ENOUGH    The space is insufficient.
 */
int32_t BN_MaskBit(BN_BigNum *a, uint32_t n);

/**
 * @ingroup bn
 * @brief Obtain the valid bit length of a BigNum.
 *
 * @attention The input parameter of a BigNum cannot be null.
 * @param a [IN] BigNum
 *
 * @retval uint32_t, valid bit length
 */
uint32_t BN_Bits(const BN_BigNum *a);

/**
 * @ingroup bn
 * @brief Obtain the valid byte length of a BigNum.
 *
 * @attention The large input parameter cannot be a null pointer.
 * @param a [IN] BigNum
 *
 * @retval uint32_t, valid byte length of a BigNum
 */
uint32_t BN_Bytes(const BN_BigNum *a);

/**
 * @ingroup bn
 * @brief BigNum Calculate the greatest common divisor
 * @par Description: gcd(a, b) (a, b!=0)
 *
 * @param r     [OUT] greatest common divisor
 * @param a     [IN] BigNum
 * @param b     [IN] BigNum
 * @param opt   [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL  Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_ERR_GCD_NO_ZERO     The greatest common divisor cannot be 0.
 */
int32_t BN_Gcd(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief BigNum modulo inverse
 *
 * @param r   [OUT] Result
 * @param x   [IN] BigNum
 * @param m   [IN] mod
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL  Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_ERR_NO_INVERSE      Cannot calculate the module inverse.
 */
int32_t BN_ModInv(BN_BigNum *r, const BN_BigNum *x, const BN_BigNum *m, BN_Optimizer *opt);
/**
 * @ingroup bn
 * @brief BigNum comparison
 *
 * @attention The input parameter of a BigNum cannot be null.
 * @param a [IN] BigNum
 * @param b [IN] BigNum
 *
 * @retval  0,a == b
 * @retval  1,a > b
 * @retval  -1,a < b
 */
int32_t BN_Cmp(const BN_BigNum *a, const BN_BigNum *b);

/**
 * @ingroup bn
 * @brief BigNum Addition
 *
 * @param r [OUT] and
 * @param a [IN] Addendum
 * @param b [IN] Addendum
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT         Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 */
int32_t BN_Add(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b);

/**
 * @ingroup bn
 * @brief BigNum plus limb
 *
 * @param r [OUT] and
 * @param a [IN] Addendum
 * @param w [IN] Addendum
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT         Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 */
int32_t BN_AddLimb(BN_BigNum *r, const BN_BigNum *a, BN_UINT w);

/**
 * @ingroup bn
 * @brief subtraction of large numbers
 *
 * @param r [OUT] difference
 * @param a [IN] minuend
 * @param b [IN] subtrahend
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 */
int32_t BN_Sub(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b);

/**
 * @ingroup bn
 * @brief BigNum minus limb
 *
 * @param   r [OUT] difference
 * @param   a [IN] minuend
 * @param   w [IN] subtrahend
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT         Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 */
int32_t BN_SubLimb(BN_BigNum *r, const BN_BigNum *a, BN_UINT w);

/**
 * @ingroup bn
 * @brief BigNum Multiplication
 *
 * @param r   [OUT] product
 * @param a   [IN] multiplier
 * @param b   [IN] multiplier
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL  Failed to apply for space from the optimizer.
 */
int32_t BN_Mul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief Multiplication of BigNum by Limb
 *
 * @param   r [OUT] product
 * @param   a [IN] multiplicand
 * @param   w [IN] multiplier (limb)
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 */
int32_t BN_MulLimb(BN_BigNum *r, const BN_BigNum *a, const BN_UINT w);

/**
 * @ingroup bn
 * @brief BigNum square. r must not be a.
 *
 * @param r   [OUT] product
 * @param a   [IN] multiplier
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL  Failed to apply for space from the optimizer.
 */
int32_t BN_Sqr(BN_BigNum *r, const BN_BigNum *a, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief BigNum Division
 *
 * @param q   [OUT] quotient
 * @param r   [OUT] remainder
 * @param x   [IN] dividend
 * @param y   [IN] divisor
 * @param opt [IN] optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_INVALID_ARG            The addresses of q, r are identical, or both of them are null.
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL  Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_ERR_DIVISOR_ZERO    divisor cannot be 0.
 */
int32_t BN_Div(BN_BigNum *q, BN_BigNum *r, const BN_BigNum *x, const BN_BigNum *y, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief BigNum divided by limb
 *
 * @param q [OUT] quotient
 * @param r [OUT] remainder
 * @param x [IN] dividend
 * @param y [IN] Divisor (limb)
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_ERR_DIVISOR_ZERO    divisor cannot be 0.
 */
int32_t BN_DivLimb(BN_BigNum *q, BN_UINT *r, const BN_BigNum *x, const BN_UINT y);

/**
 * @ingroup bn
 * @brief BigNum Modular addition
 * @par Description: r = (a + b) mod (mod)
 *
 * @param r   [OUT] Modulus result
 * @param a   [IN] BigNum
 * @param b   [IN] BigNum
 * @param mod [IN] mod
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL  Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_ERR_DIVISOR_ZERO    module cannot be 0.
 */
int32_t BN_ModAdd(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, BN_Optimizer *opt);
/**
 * @ingroup bn
 * @brief BigNum Modular subtraction
 * @par Description: r = (a - b) mod (mod)
 *
 * @param r   [OUT] Modulo result
 * @param a   [IN] minuend
 * @param b   [IN] subtrahend
 * @param mod [IN] mod
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL  Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_ERR_DIVISOR_ZERO    module cannot be 0.
 */
int32_t BN_ModSub(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief BigNum Modular multiplication
 * @par Description: r = (a * b) mod (mod)
 *
 * @param r   [OUT] Modulus result
 * @param a   [IN] BigNum
 * @param b   [IN] BigNum
 * @param mod [IN] mod
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL  Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_ERR_DIVISOR_ZERO    module cannot be 0.
 */
int32_t BN_ModMul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief BigNum Modular squared
 * @par Description: r = (a ^ 2) mod (mod)
 *
 * @param r   [OUT] Modulus result
 * @param a   [IN] BigNum
 * @param mod [IN] mod
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL  Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_ERR_DIVISOR_ZERO    module cannot be 0.
 */
int32_t BN_ModSqr(
    BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *mod, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief BigNum Modular power
 * @par Description: r = (a ^ e) mod (mod)
 *
 * @param r   [OUT] Modulus result
 * @param a   [IN] BigNum
 * @param mod [IN] mod
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT               Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL           Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL    Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_ERR_DIVISOR_ZERO      module cannot be 0.
 * @retval CRYPT_BN_ERR_EXP_NO_NEGATIVE   exponent cannot be a negative number
 */
int32_t BN_ModExp(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e,
    const BN_BigNum *m, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief BigNum modulo
 * @par Description: r = a mod m
 *
 * @param r   [OUT] Modulus result
 * @param a   [IN] BigNum
 * @param m   [IN] mod
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL  Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_ERR_DIVISOR_ZERO    module cannot be 0.
 */
int32_t BN_Mod(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *m, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief BigNum modulo limb
 * @par Description: r = a mod m
 *
 * @param r [OUT] Modulus result
 * @param a [IN] BigNum
 * @param m [IN] Modulus (limb)
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_BN_ERR_DIVISOR_ZERO    module cannot be 0.
 */
int32_t BN_ModLimb(BN_UINT *r, const BN_BigNum *a, const BN_UINT m);

#ifdef HITLS_CRYPTO_BN_PRIME
/**
 * @ingroup bn
 * @brief generate BN prime
 *
 * @param r    [OUT] Generate a prime number.
 * @param e    [OUT] A helper prime to reduce the number of Miller-Rabin primes check.
 * @param bits [IN] Length of the generated prime number
 * @param half [IN] Whether to generate a prime number greater than the maximum value of this prime number by 1/2:
 *                  Yes: True, No: false
 * @param opt  [IN] Optimizer
 * @param cb   [IN] BigNum callback
 * @retval CRYPT_SUCCESS                    The prime number is successfully generated.
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer.
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_STACK_FULL    The optimizer stack is full.
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL      Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_NOR_GEN_PRIME           Failed to generate prime numbers.
 * @retval CRYPT_NO_REGIST_RAND             No random number is registered.
 * @retval CRYPT_BN_RAND_GEN_FAIL           Failed to generate a random number.
 */
int32_t BN_GenPrime(BN_BigNum *r, BN_BigNum *e, uint32_t bits, bool half, BN_Optimizer *opt, BN_CbCtx *cb);

/**
 * @ingroup bn
 * @brief check prime number
 *
 * @param bn  [IN] Prime number to be checked
 * @param checkTimes  [IN] the user can set the check times of miller-rabin testing.
 *                         if checkTimes == 0, it will use the default detection times of miller-rabin.
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS                    The check result is a prime number.
 * @retval CRYPT_BN_NOR_CHECK_PRIME         The check result is a non-prime number.
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer
 * @retval CRYPT_BN_OPTIMIZER_STACK_FULL    The optimizer stack is full.
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL      Failed to apply for space from the optimizer.
 * @retval CRYPT_NO_REGIST_RAND             No random number is registered.
 * @retval CRYPT_BN_RAND_GEN_FAIL           Failed to generate a random number.
 */
int32_t BN_PrimeCheck(const BN_BigNum *bn, uint32_t checkTimes, BN_Optimizer *opt, BN_CbCtx *cb);
#endif // HITLS_CRYPTO_BN_PRIME

#ifdef HITLS_CRYPTO_BN_RAND
#define BN_RAND_TOP_NOBIT      0 /* Not set bits */
#define BN_RAND_TOP_ONEBIT     1 /* Set the most significant bit to 1. */
#define BN_RAND_TOP_TWOBIT     2 /* Set the highest two bits to 1 */

#define BN_RAND_BOTTOM_NOBIT   0 /* Not set bits */
#define BN_RAND_BOTTOM_ONEBIT  1 /* Set the least significant bit to 1. */
#define BN_RAND_BOTTOM_TWOBIT  2 /* Set the least significant two bits to 1. */

/**
 * @ingroup bn
 * @brief generate random BigNum
 *
 * @param r      [OUT] Generate a random number.
 * @param bits   [IN] Length of the generated prime number
 * @param top    [IN] Generating the flag indicating whether to set the most significant bit of a random number
 * @param bottom [IN] Generate the flag indicating whether to set the least significant bit of the random number.
 *
 * @retval CRYPT_SUCCESS                        A random number is generated successfully.
 * @retval CRYPT_NULL_INPUT                     Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL                 Memory allocation failure
 * @retval CRYPT_BN_ERR_RAND_TOP_BOTTOM         The top or bottom is invalid during random number generation.
 * @retval CRYPT_NO_REGIST_RAND                 No random number is registered.
 * @retval CRYPT_BN_RAND_GEN_FAIL               Failed to generate a random number.
 * @retval CRYPT_BN_ERR_RAND_BITS_NOT_ENOUGH    The bit is too small during random number generation.
 */
int32_t BN_Rand(BN_BigNum *r, uint32_t bits, uint32_t top, uint32_t bottom);

/**
 * @ingroup bn
 * @brief generate random BigNum
 *
 * @param libCtx [IN] provider libCtx
 * @param r      [OUT] Generate a random number.
 * @param bits   [IN] Length of the generated prime number
 * @param top    [IN] Generating the flag indicating whether to set the most significant bit of a random number
 * @param bottom [IN] Generate the flag indicating whether to set the least significant bit of the random number.
 *
 * @retval CRYPT_SUCCESS                        A random number is generated successfully.
 * @retval CRYPT_NULL_INPUT                     Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL                 Memory allocation failure
 * @retval CRYPT_BN_ERR_RAND_TOP_BOTTOM         The top or bottom is invalid during random number generation.
 * @retval CRYPT_BN_RAND_GEN_FAIL               Failed to generate a random number.
 * @retval CRYPT_BN_ERR_RAND_BITS_NOT_ENOUGH    The bit is too small during random number generation.
 */
int32_t BN_RandEx(void *libCtx, BN_BigNum *r, uint32_t bits, uint32_t top, uint32_t bottom);

/**
 * @ingroup bn
 * @brief generate random BigNum
 *
 * @param r [OUT] Generate a random number.
 * @param p [IN] Compare data so that the generated r < p
 *
 * @retval CRYPT_SUCCESS            A random number is successfully generated.
 * @retval CRYPT_NULL_INPUT         Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_NO_REGIST_RAND     No random number is registered.
 * @retval CRYPT_BN_RAND_GEN_FAIL   Failed to generate a random number.
 * @retval CRYPT_BN_ERR_RAND_ZERO   Generate a random number smaller than 0.
 * @retval CRYPT_BN_ERR_RAND_NEGATE Generate a negative random number.
 */
int32_t BN_RandRange(BN_BigNum *r, const BN_BigNum *p);

/**
 * @ingroup bn
 * @brief generate random BigNum
 *
 * @param libCtx [IN] provider libCtx
 * @param r [OUT] Generate a random number.
 * @param p [IN] Compare data so that the generated r < p
 *
 * @retval CRYPT_SUCCESS            A random number is successfully generated.
 * @retval CRYPT_NULL_INPUT         Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_BN_RAND_GEN_FAIL   Failed to generate a random number.
 * @retval CRYPT_BN_ERR_RAND_ZERO   Generate a random number smaller than 0.
 * @retval CRYPT_BN_ERR_RAND_NEGATE Generate a negative random number.
 */
int32_t BN_RandRangeEx(void *libCtx, BN_BigNum *r, const BN_BigNum *p);
#endif
/**
 * @ingroup bn
 * @brief Binary to BigNum
 *
 * @param r      [OUT] BigNum
 * @param bin    [IN] Data stream to be converted
 * @param binLen [IN] Data stream length
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 */
int32_t BN_Bin2Bn(BN_BigNum *r, const uint8_t *bin, uint32_t binLen);

/**
 * @ingroup bn
 * @brief Convert BigNum to a big-endian binary
 *
 * @param a      [IN] BigNum
 * @param bin    [IN/OUT] Data stream to be converted -- The input pointer cannot be null.
 * @param binLen [IN/OUT] Data stream length -- When input, binLen is also the length of the bin buffer.
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval CRYPT_SECUREC_FAIL   An error occurred during the copy.
 */
int32_t BN_Bn2Bin(const BN_BigNum *a, uint8_t *bin, uint32_t *binLen);

/**
 * @ingroup bn
 * @brief fix size of BigNum
 *
 * @param a      [IN] BigNum
 *
 * @retval void
 */
void BN_FixSize(BN_BigNum *a);

/**
 * @ingroup bn
 * @brief
 *
 * @param a      [IN/OUT] BigNum
 * @param words  [IN] the bn room that the caller wanted.
 *
 * @retval CRYPT_SUCCESS
 * @retval others, see crypt_errno.h
 */
int32_t BN_Extend(BN_BigNum *a, uint32_t words);

/**
 * @ingroup bn
 * @brief Convert BigNum to binary to obtain big-endian data with the length of binLen.
 *        The most significant bits are filled with 0.
 *
 * @param a      [IN] BigNum
 * @param bin    [OUT] Data stream to be converted -- The input pointer cannot be null.
 * @param binLen [IN] Data stream length -- When input, binLen is also the length of the bin buffer.
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_BN_BUFF_LEN_NOT_ENOUGH The space is insufficient.
 */
int32_t BN_Bn2BinFixZero(const BN_BigNum *a, uint8_t *bin, uint32_t binLen);

#ifdef HITLS_CRYPTO_BN_STR_CONV
/**
 * @ingroup bn
 * @brief Hexadecimal to a BigNum
 *
 * @param r [OUT] BigNum
 * @param r [IN] Data stream to be converted
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_BN_CONVERT_INPUT_INVALID   Invalid string
 */
int32_t BN_Hex2Bn(BN_BigNum **r, const char *str);

/**
 * @ingroup bn
 * @brief Convert BigNum to hexadecimal number
 *
 * @param a    [IN] BigNum
 * @param char [OUT] Converts a hexadecimal string.
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 */
char *BN_Bn2Hex(const BN_BigNum *a);

/**
 * @ingroup bn
 * @brief Decimal to BigNum
 *
 * @param r   [OUT] BigNum
 * @param str [IN] A decimal string to be converted
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_BN_CONVERT_INPUT_INVALID   Invalid string
 */
int32_t BN_Dec2Bn(BN_BigNum **r, const char *str);

/**
 * @ingroup bn
 * @brief Convert BigNum to decimal number
 *
 * @param r   [IN] BigNum
 *
 * @retval A decimal string after conversion or push error.
 */
char *BN_Bn2Dec(const BN_BigNum *a);
#endif

#if defined(HITLS_CRYPTO_CURVE_SM2_ASM) ||                                             \
    ((defined(HITLS_CRYPTO_CURVE_NISTP521) || defined(HITLS_CRYPTO_CURVE_NISTP384_ASM)) && \
        defined(HITLS_CRYPTO_NIST_USE_ACCEL))
/**
 * @ingroup bn
 * @brief Converting a 64-bit unsigned number array to a BigNum
 *
 * @param r     [OUT] BigNum
 * @param array [IN] Array to be converted
 * @param len   [IN] Number of elements in the array
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 */
int32_t BN_U64Array2Bn(BN_BigNum *r, const uint64_t *array, uint32_t len);

/**
 * @ingroup bn
 * @brief BigNum to 64-bit unsigned number array
 *
 * @param a     [IN] BigNum
 * @param array [IN/OUT] Array for storing results -- The input pointer cannot be null.
 * @param len   [IN/OUT] Length of the written array -- Number of writable elements when input
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval CRYPT_SECUREC_FAIL   A copy error occurs.
 */
int32_t BN_Bn2U64Array(const BN_BigNum *a, uint64_t *array, uint32_t *len);
#endif

/**
 * @ingroup bn
 * @brief BigNum optimizer creation
 *
 * @param None
 *
 * @retval Not NULL Success
 * @retval NULL failure
 */
BN_Optimizer *BN_OptimizerCreate(void);

/**
 * @ingroup bn
 * @brief Destroy the BigNum optimizer.
 *
 * @param opt [IN] BigNum optimizer
 *
 * @retval none
 */
void BN_OptimizerDestroy(BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief set library context
 *
 * @param libCtx [IN] Library context
 * @param opt [OUT] BigNum optimizer
 *
 * @retval none
 */
void BN_OptimizerSetLibCtx(void *libCtx, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief get library context
 *
 * @param opt [In] BigNum optimizer
 *
 * @retval library context
 */
void *BN_OptimizerGetLibCtx(BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief BigNum Montgomery context creation and setting
 *
 * @param m [IN] Modulus m, which must be positive and odd
 *
 * @retval Not NULL Success
 * @retval NULL failure
 */
BN_Mont *BN_MontCreate(const BN_BigNum *m);

/**
 * @ingroup bn
 * @brief BigNum Montgomery modular exponentiation.
 *        Whether to use the constant API depends on the property of the BigNum.
 *
 * @param r    [OUT] Modular exponentiation result
 * @param a    [IN] base
 * @param e    [IN] Index
 * @param mont [IN] Montgomery context
 * @param opt  [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS                    calculated successfully.
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL      Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_MONT_BASE_TOO_MAX       Montgomery modulus exponentiation base is too large
 * @retval CRYPT_BN_OPTIMIZER_STACK_FULL    The optimizer stack is full.
 * @retval CRYPT_BN_ERR_EXP_NO_NEGATE       exponent cannot be a negative number
 */
int32_t BN_MontExp(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e, BN_Mont *mont,
    BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief Constant time BigNum Montgomery modular exponentiation
 *
 * @param r    [OUT] Modular exponentiation result
 * @param a    [IN] base
 * @param e    [IN] exponent
 * @param mont [IN] Montgomery context
 * @param opt  [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS                    calculated successfully.
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_BN_OPTIMIZER_GET_FAIL      Failed to apply for space from the optimizer.
 * @retval CRYPT_BN_MONT_BASE_TOO_MAX       Montgomery Modular exponentiation base is too large
 * @retval CRYPT_BN_OPTIMIZER_STACK_FULL    The optimizer stack is full.
 * @retval CRYPT_BN_ERR_EXP_NO_NEGATE       exponent cannot be a negative number
 */
int32_t BN_MontExpConsttime(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e,
    BN_Mont *mont, BN_Optimizer *opt);

/**
 * @ingroup mont
 * @brief BigNum Montgomery Context Destruction
 *
 * @param mont [IN] BigNum Montgomery context
 *
 * @retval none
 */
void BN_MontDestroy(BN_Mont *mont);

/**
 * @ingroup bn
 * @brief shift a BigNum to the right
 *
 * @param r [OUT] Shift result
 * @param a [IN] Source data
 * @param n [IN] Shift bit num
 *
 * @retval CRYPT_SUCCESS            succeeded.
 * @retval CRYPT_NULL_INPUT         Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_SECUREC_FAIL       The security function returns an error.
 */
int32_t BN_Rshift(BN_BigNum *r, const BN_BigNum *a, uint32_t n);

/**
 * @ingroup bn
 * @brief shift a BigNum to the left
 *
 * @param r [OUT] Shift result
 * @param a [IN] Source data
 * @param n [IN] Shift bit num
 *
 * @retval CRYPT_SUCCESS            succeeded.
 * @retval CRYPT_NULL_INPUT         Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 */
int32_t BN_Lshift(BN_BigNum *r, const BN_BigNum *a, uint32_t n);

#ifdef HITLS_CRYPTO_DSA
int32_t BN_MontExpMul(BN_BigNum *r, const BN_BigNum *a1, const BN_BigNum *e1,
    const BN_BigNum *a2, const BN_BigNum *e2, BN_Mont *mont, BN_Optimizer *opt);
#endif

#ifdef HITLS_CRYPTO_ECC
/**
 * @ingroup bn
 * @brief Mould opening root
 * @par Description: r^2 = a mod p; p-1=q*2^s.
 *      In the current implementation s=1 will take a special branch, and the calculation speed is faster.
 *      The fast calculation branch with s=2 is not implemented currently.
 *      Currently, the s corresponding to the mod p of the EC nist224, 256, 384, and 521 is 96, 1, 1, and 1 respectively
 *      The branch with s=2 is not used.
 *      The root number is provided for the EC.
 * @param r   [OUT] Modular root result
 * @param a   [IN] Source data, 0 <= a <= p-1
 * @param p   [IN] module, odd prime number
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS                calculated successfully.
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_BN_ERR_SQRT_PARA       The input parameter is incorrect.
 * @retval CRYPT_BN_ERR_LEGENDE_DATA:
 * Failed to find the specific number of the Legendre sign (z|p) of z to p equal to -1 when calculating the square root.
 * @retval CRYPT_BN_ERR_NO_SQUARE_ROOT  The square root cannot be found.
 */
int32_t BN_ModSqrt(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *p, BN_Optimizer *opt);
#endif

#if defined(HITLS_CRYPTO_CURVE_SM2_ASM) || (defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) && \
    defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE))
/**
 * @ingroup bn
 * @brief BigNum to BN_UINT array
 *
 * @param src  [IN] BigNum
 * @param dst  [OUT] BN_UINT array for receiving the conversion result
 * @param size [IN] Length of the dst buffer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval CRYPT_SECUREC_FAIL   The security function returns an error.
 */
int32_t BN_BN2Array(const BN_BigNum *src, BN_UINT *dst, uint32_t size);

/**
 * @ingroup bn
 * @brief BN_UINT array to BigNum
 *
 * @param dst [OUT] BigNum
 * @param src [IN] BN_UINT array to be converted
 * @param size [IN] Length of the src buffer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT     Invalid null pointer.
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 */
int32_t BN_Array2BN(BN_BigNum *dst, const BN_UINT *src, const uint32_t size);
#endif

#ifdef HITLS_CRYPTO_ECC
/**
 * @ingroup bn
 * @brief Copy with the mask. When the mask is set to (0), r = a; when the mask is set to (-1), r = b.
 *
 * @attention Data r, a, and b must have the same room.
 *
 * @param r    [OUT] Output result
 * @param a    [IN] Source data
 * @param b    [IN] Source data
 * @param mask [IN] Mask data
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t BN_CopyWithMask(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_UINT mask);

/**
 * @ingroup bn
 * @brief Calculate r = (a - b) % mod
 *
 * @attention This API is invoked in the area where ECC point computing is intensive and is performance-sensitive.
 * The user must ensure that a < mod, b < mod
 * In addition, a->room and b->room are not less than mod->size.
 * All data are non-negative
 * The mod information cannot be 0.
 * Otherwise, the interface may not be functional.
 *
 * @param r   [OUT] Output result
 * @param a   [IN] Source data
 * @param b   [IN] Source data
 * @param mod [IN] Modular data
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t BN_ModSubQuick(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, const BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief Calculate r = (a + b) % mod
 *
 * @attention This API is invoked in the area where ECC point computing is intensive and is performance-sensitive.
 * The user must ensure that a < mod, b < mod
 * In addition, a->room and b->room are not less than mod->size.
 * All data are non-negative
 * The mod information cannot be 0.
 * Otherwise, the interface may not be functional.
 *
 * @param r   [OUT] Output result
 * @param a   [IN] Source data
 * @param b   [IN] Source data
 * @param mod [IN] Modular data
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t BN_ModAddQuick(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, const BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief Calculate r = (a * b) % mod
 *
 * @attention This API is invoked in the area where ECC point computing is intensive and is performance sensitive.
 * The user must ensure that a < mod, b < mod
 * In addition, a->room and b->room are not less than mod->size.
 * All data are non-negative
 * The mod information can only be the parameter p of the curve of nistP224, nistP256, nistP384, and nistP521.
 * Otherwise, the interface may not be functional.
 *
 * @param r   [OUT] Output result
 * @param a   [IN] Source data
 * @param b   [IN] Source data
 * @param mod [IN] Modular data
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For other errors, see crypt_errno.h.
 */
int32_t BN_ModNistEccMul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    void *data, BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief Calculate r = (a ^ 2) % mod
 *
 * @attention This API is invoked in the area where ECC point computing is intensive and is performance sensitive.
 * The user must guarantee a < mod
 * In addition, a->room are not less than mod->size.
 * All data are non-negative
 * The mod information can only be the parameter p of the curve of nistP224, nistP256, nistP384, and nistP521.
 * Otherwise, the interface may not be functional.
 *
 * @param r   [OUT] Output result
 * @param a   [IN] Source data
 * @param mod [IN] Modular data
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t BN_ModNistEccSqr(BN_BigNum *r, const BN_BigNum *a, void *data, BN_Optimizer *opt);
#endif

#ifdef HITLS_CRYPTO_CURVE_SM2
/**
 * @ingroup ecc
 * @brief   sm2 curve: calculate r = (a*b)% mod
 *
 * @attention This API is invoked in the area where ECC point computing is intensive and is performance sensitive.
 * The user must guarantee a < mod、b < mod
 * In addition, a->room and b->room are not less than mod->size.
 * All data are non-negative
 * The mod information can only be the parameter p of the curve of sm2.
 * Otherwise, the interface may not be functional.
 *
 * @param r   [OUT] Output result
 * @param a   [IN] Source data
 * @param b   [IN] Source data
 * @param mod [IN] Modular data
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t BN_ModSm2EccMul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, void *data, BN_Optimizer *opt);

/**
 * @ingroup ecc
 * @brief   sm2 curve: calculate r = (a ^ 2) % mod
 *
 * @attention This API is invoked in the area where ECC point computing is intensive and is performance sensitive.
 * The user must guarantee a < mod
 * In addition, a->room are not less than mod->size.
 * All data are non-negative
 * The mod information can only be the parameter p of the curve of sm2.
 * Otherwise, the interface may not be functional.
 *
 * @param r   [OUT] Output result
 * @param a   [IN] Source data
 * @param mod [IN] Modular data
 * @param opt [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t BN_ModSm2EccSqr(BN_BigNum *r, const BN_BigNum *a, void *data, BN_Optimizer *opt);
#endif

#ifdef HITLS_CRYPTO_BN_RFC_PRIME
/**
 * @ingroup bn
 * @brief Return the corresponding length of modulo exponent of the BigNum.
 *
 * @param r   [OUT] Output result
 * @param len [IN] Length
 *
 * @retval Not NULL     Success
 * @retval NULL         failure
 */
BN_BigNum *BN_GetRfcConstPrime(BN_BigNum *r, int32_t paraId);
#endif

/**
 * @ingroup bn
 * @brief Return the number of security bits provided by a specific algorithm and specific key size.
 *
 * @param [OUT] Output the result.
 * @param pubLen [IN] Size of the public key
 * @param prvLen [IN] Size of the private key.
 *
 * @retval Number of security bits
 */
int32_t BN_SecBits(int32_t pubLen, int32_t prvLen);

#if defined(HITLS_CRYPTO_RSA)

/**
 * @ingroup bn
 * @brief   Montgomery modulus calculation process, need a < m, b < m, All is positive numbers, The large number
     optimizer must be enabled before this function is used.
 *
 * @param   r [OUT] Output results
 * @param   a [IN] Input data
 * @param   b [IN] Input data
 * @param   mont [IN] Montgomery context
 * @param   opt [IN] Large number optimizer
 *
 * @retval  CRYPT_SUCCESS
 * @retval  For details about other errors, see crypt_errno.h.
 */
int32_t MontMulCore(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_Mont *mont, BN_Optimizer *opt);

#endif // HITLS_CRYPTO_RSA

#if defined(HITLS_CRYPTO_BN_PRIME)
/**
 * @ingroup bn
 * @brief   Montgomery modulus calculation process, need a < m, unlimited symbols.
 *
 * @param   r [OUT] Output results
 * @param   a [IN] Input data
 * @param   mont [IN] Montgomery context
 * @param   opt [IN] Large number optimizer
 *
 * @retval  CRYPT_SUCCESS
 * @retval  For details about other errors, see crypt_errno.h.
 */
int32_t MontSqrCore(BN_BigNum *r, const BN_BigNum *a, BN_Mont *mont, BN_Optimizer *opt);

#endif // HITLS_CRYPTO_BN_PRIME

/**
 * @ingroup bn
 * @brief   Enabling the big data optimizer
 *
 * @param   opt [IN] Large number optimizer
 *
 * @retval  CRYPT_SUCCESS
 * @retval  For details about other errors, see crypt_errno.h.
 */
int32_t OptimizerStart(BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief   Disabling the Large Number Optimizer
 *
 * @param   opt [IN] Large number optimizer
 *
 * @retval  CRYPT_SUCCESS
 * @retval  For details about other errors, see crypt_errno.h.
 */
void OptimizerEnd(BN_Optimizer *opt);

/**
 * @ingroup bn
 * @brief   Get Bn from the large number optimizer.
 *
 * @param   opt [IN] Large number optimizer
 * @param   room [IN] Length of the big number.
 *
 * @retval  BN_BigNum if success
 * @retval  NULL if failed
 */
BN_BigNum *OptimizerGetBn(BN_Optimizer *opt, uint32_t room);

#ifdef HITLS_CRYPTO_CURVE_MONT

/**
 * a, b is mont form.
 * r = a * b
 */
int32_t BN_EcPrimeMontMul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, void *data, BN_Optimizer *opt);

/**
 * a is mont form.
 * r = a ^ 2
 */
int32_t BN_EcPrimeMontSqr(BN_BigNum *r, const BN_BigNum *a, void *data, BN_Optimizer *opt);

/**
 * r = Reduce(r * RR)
 */
int32_t BnMontEnc(BN_BigNum *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime);

/**
 * r = Reduce(r)
 */
void BnMontDec(BN_BigNum *r, BN_Mont *mont);

/**
 * This interface is a constant time.
 * if mask = BN_MASK. swap a and b.
 * if mask = 0, a and b remain as they are.
 */
int32_t BN_SwapWithMask(BN_BigNum *a, BN_BigNum *b, BN_UINT mask);

#endif // HITLS_CRYPTO_CURVE_MONT

#if defined(HITLS_CRYPTO_PAILLIER) || defined(HITLS_CRYPTO_RSA_CHECK)
/**
 * @ingroup bn
 * @brief BigNum Calculate the least common multiple
 * @par Description: lcm(a, b) (a, b!=0)
 *
 * @param r     [OUT] least common multiple
 * @param a     [IN] BigNum
 * @param b     [IN] BigNum
 * @param opt   [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 */
int32_t BN_Lcm(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_Optimizer *opt);

#endif // HITLS_CRYPTO_PAILLIER || HITLS_CRYPTO_RSA_CHECK

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_BN */

#endif
