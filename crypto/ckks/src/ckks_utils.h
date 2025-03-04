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

#ifndef CKKS_UTILS_H
#define CKKS_UTILS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CKKS

#include <immintrin.h>
#include <math.h>
#include "crypt_ckks.h"
#include "ckks_local.h"
#include "crypt_bn.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
  * @ingroup ckks
  * @brief Standard complex multiplication
  * 
  * @param c1 [IN] Multiplier
  * @param c2 [IN] Multiplier
  * 
  * @retval product
  */
CKKS_Complex CKKS_Complex_Mul(CKKS_Complex c1, CKKS_Complex c2);

/**
   * @ingroup ckks
   * @brief Calculate the product of the conjugate of one complex number and another complex number.
   * 
   * @param c1 [IN] Multiplier
   * @param c2 [IN] Multiplier
   * 
   * @retval product
   */
CKKS_Complex CKKS_Complex_Conj_Mul(CKKS_Complex c1, CKKS_Complex c2);

#if defined(PD4_START)

static __m256d PD4_Init_Four_Doubles(double d0, double d1, double d2, double d3)
{
    return _mm256_set_pd(d3, d2, d1, d0);
}

static __m256d PD4_Load(const double *p)
{
    return _mm256_load_pd(p);
}

static void PD4_Store(double *p, __m256d a)
{
    _mm256_store_pd(p, a); // Store to aligned memory
}

static __m256d PD4_Swap(__m256d a)
{
    return _mm256_permute_pd(a, 0x5);
}

static __m256d PD4_Dup2even(__m256d a)
{
    return _mm256_permute_pd(a, 0);
}

static __m256d PD4_Dup2odd(__m256d a)
{
    return _mm256_permute_pd(a, 0xf);
}

static __m256d PD4_Blend_Even(__m256d a, __m256d b)
{
    return _mm256_unpacklo_pd(a, b);
}

static __m256d PD4_Blend_Odd(__m256d a, __m256d b)
{
    return _mm256_unpackhi_pd(a, b);
}

static void PD4_Clear(__m256d *x)
{
    *x = _mm256_setzero_pd();
}

static __m256d PD4_Add(const __m256d a, const __m256d b)
{
    return _mm256_add_pd(a, b);
}
static __m256d PD4_Sub(const __m256d a, const __m256d b)
{
    return _mm256_sub_pd(a, b);
}

static __m256d PD4_Mul(const __m256d a, const __m256d b)
{
    return _mm256_mul_pd(a, b);
}

static __m256d PD4_div(__m256d a, __m256d b)
{
    return _mm256_div_pd(a, b);
}

static inline void PD4_Complex_MUL(__m256d *x0, __m256d *x1, __m256d a0, __m256d a1, __m256d b0, __m256d b1)
{
    __m256d a_real = PD4_Blend_Even(a0, a1);
    __m256d a_imag = PD4_Blend_Odd(a0, a1);
    __m256d b_real = PD4_Blend_Even(b0, b1);
    __m256d b_imag = PD4_Blend_Odd(b0, b1);
    __m256d x_real = PD4_Sub(PD4_Mul(a_real, b_real), PD4_Mul(a_imag, b_imag));
    __m256d x_imag = PD4_Add(PD4_Mul(a_real, b_imag), PD4_Mul(a_imag, b_real));
    *x0 = PD4_Blend_Even(x_real, x_imag);
    *x1 = PD4_Blend_Odd(x_real, x_imag);
}

static inline void PD4_Complex_Conj_MUL(__m256d *x0, __m256d *x1, __m256d a0, __m256d a1, __m256d b0, __m256d b1)
{
    __m256d a_real = PD4_Blend_Even(a0, a1);
    __m256d a_imag = PD4_Blend_Odd(a0, a1);
    __m256d b_real = PD4_Blend_Even(b0, b1);
    __m256d b_imag = PD4_Blend_Odd(b0, b1);
    __m256d x_real = PD4_Add(PD4_Mul(a_real, b_real), PD4_Mul(a_imag, b_imag));
    __m256d x_imag = PD4_Sub(PD4_Mul(a_real, b_imag), PD4_Mul(a_imag, b_real));
    *x0 = PD4_Blend_Even(x_real, x_imag);
    *x1 = PD4_Blend_Odd(x_real, x_imag);
}

static inline void CKKS_Complex_Mul_Loop(uint32_t size, CKKS_Complex *xp, const CKKS_Complex *yp)
{
    uint32_t j;
    double *d_xp = (double *)xp;
    const double *d_yp = (const double *)yp;
    for (j = 0; j < size; j += 4) {
        __m256d x0 = PD4_Load(d_xp + 2 * (j + 0));
        __m256d x1 = PD4_Load(d_xp + 2 * (j + 2));
        __m256d y0 = PD4_Load(d_yp + 2 * (j + 0));
        __m256d y1 = PD4_Load(d_yp + 2 * (j + 2));
        __m256d z0, z1;
        PD4_Complex_MUL(&z0, &z1, x0, x1, y0, y1);
        PD4_Store(d_xp + 2 * (j + 0), z0);
        PD4_Store(d_xp + 2 * (j + 2), z1);
    }
}

#else
static inline void CKKS_Complex_Mul_Loop(uint32_t size, CKKS_Complex *xp, const CKKS_Complex *yp)
{
    for (uint32_t j = 0; j < size; j++) {
        xp[j] = CKKS_Complex_Mul(xp[j], yp[j]);
    }
}
#endif //PD4_START

uint32_t Gcd(uint32_t a, uint32_t b);
uint32_t Get_ZMStar_Gens(uint32_t *gens, uint32_t m);
uint32_t PowerMod(uint32_t base, uint32_t exp, uint32_t mod);
uint32_t *Get_ZMStar(uint32_t m);
bool Lexico_Order(uint32_t *buffer, const uint32_t *ZMStar, uint32_t buffer_sz, uint32_t ZMStar_sz);
uint32_t Get_T_Ele(const uint32_t *exps, uint32_t exps_sz, const uint32_t *gens, uint32_t gens_sz, uint32_t m);
bool Check_I_In_ZMStar(const int32_t *Tidx, uint32_t t, uint32_t m);
double Coordinate_Wise_Random_Rounding(double coord);
uint64_t htonll(uint64_t host);
uint64_t ntohll(uint64_t net);
CKKS_Complex CKKS_Complex_Conj(CKKS_Complex c);
CKKS_Complex CKKS_Complex_Add(CKKS_Complex c1, CKKS_Complex c2);
CKKS_Complex CKKS_Complex_Int_Add(CKKS_Complex c, uint32_t w);
CKKS_Complex CKKS_Complex_Sub(CKKS_Complex c1, CKKS_Complex c2);
CKKS_Complex CKKS_Complex_Int_Sub(CKKS_Complex c, uint32_t w);

CKKS_Complex CKKS_Complex_ADouble_Mul(CKKS_Complex c, double w);
CKKS_Complex CKKS_Complex_Int_Div(CKKS_Complex c, uint32_t w);
double CKKS_Complex_Cabs(CKKS_Complex c);
void CKKS_Complex_Copy(CKKS_Complex *new_c, const CKKS_Complex c);
CKKS_Complex CKKS_ADouble2Complex(double d1);
CKKS_Complex CKKS_U32t2Complex(uint32_t u1);
int32_t CKKS_BN2Double(const BN_BigNum *a, double *val);
/**
* @ingroup ckks
* @brief Initializes aligned memory for CKKS
* 
* @param mem [IN/OUT] Pointer to CKKS aligned memory structure
* @param initial_capacity [IN] Initial capacity for memory allocation
* 
* @retval CRYPT_SUCCESS succeeded.
* @retval For details about other errors, see crypt_errno.h.
*/
int32_t CKKS_Complex_Array_Init(CKKS_Complex_Array *mem, size_t initial_size);
int32_t Set_Complex_Array_Data(CKKS_Complex_Array *mem, CKKS_Complex *complex_arr);
/**
* @ingroup ckks
* @brief Pushes an element into aligned memory
* 
* @param mem [IN/OUT] Pointer to CKKS aligned memory structure
* @param ele [IN] Pointer to element to be added
* 
* @retval CRYPT_SUCCESS succeeded.
* @retval For details about other errors, see crypt_errno.h.
*/
int32_t Push_Complex_Array_Ele(CKKS_Complex_Array *mem, void *ele);
int32_t CKKS_Complex_Array_Copy(CKKS_Complex_Array *dst, const CKKS_Complex_Array *src);
/**
* @ingroup ckks
* @brief Frees aligned memory
* 
* @param mem [IN/OUT] Pointer to CKKS aligned memory structure
* 
* @retval NULL
*/
void CKKS_Complex_Array_Destroy(CKKS_Complex_Array *mem);
int32_t CKKS_Doubles2Complex(CKKS_Complex_Array *complex_arr, double *doublearr, uint32_t doublearr_sz);
int32_t CKKS_Complex2Doubles(double *doublearr, const CKKS_Complex_Array *complex_arr);
int32_t CKKS_ComplexArray2Bin(const CKKS_Complex_Array *arr, uint8_t *bin, uint32_t *binLen);
int32_t CKKS_Bin2ComplexArray(CKKS_Complex_Array *arr, const uint8_t *bin, uint32_t binLen);
int32_t CKKS_Poly_Init(CKKS_Poly *poly, uint32_t bits, uint32_t m);
void CKKS_Poly_Destroy(CKKS_Poly *poly);
int32_t CKKS_Poly_Copy(CKKS_Poly *dst, const CKKS_Poly *src);
CKKS_Poly *CKKS_Poly_Dup(const CKKS_Poly *src);
int32_t CKKS_Poly_Set_Coeff(CKKS_Poly *poly, uint32_t index, BN_BigNum *coeff);
int32_t CKKS_Poly_Get_Coeff(BN_BigNum *coeff, const CKKS_Poly *poly, uint32_t index);
int32_t CKKS_Poly_ZeroizeCoeffs(CKKS_Poly *poly);
int32_t CKKS_PolyCtx_Set(CKKS_PolyCtx *poly_ctx, uint32_t bits, uint32_t m);
int32_t CKKS_PolyCtx_Copy(CKKS_PolyCtx *dst, const CKKS_PolyCtx *src);
bool CKKS_PolyCtx_Cmp(const CKKS_PolyCtx *Pctx1, const CKKS_PolyCtx *Pctx2);
int32_t CKKS_Poly_Normalized(CKKS_Poly *poly);
int32_t CKKS_Poly_Add(CKKS_Poly *res, const CKKS_Poly *p1, const CKKS_Poly *p2);
int32_t CKKS_Poly_Mul(CKKS_Poly *res, const CKKS_Poly *p1, const CKKS_Poly *p2, BN_Optimizer *opt);
int32_t CKKS_Poly_Int_Mul(CKKS_Poly *res, const CKKS_Poly *p, const uint32_t w, BN_Optimizer *opt);
bool Check_Prime_In_Chain(const CKKS_Moduli *moduli, const BN_BigNum *q);
BN_BigNum *Get_ModularQ(const CKKS_Moduli *moduli, uint32_t nbits, BN_Optimizer *opt);
uint32_t CKKS_Get_Prime_Size(uint32_t nBits);
BN_BigNum *CKKS_Gen_Ctx_Prime(uint32_t len, const BN_BigNum *q_lowerB, const BN_BigNum *q_upperB,
                              const BN_BigNum *m_lshift_k, const uint32_t m, uint32_t k, BN_Optimizer *opt);
int32_t CKKS_Add_Ctx_Prime(CKKS_Moduli *moduli, const BN_BigNum *q);
int32_t CKKS_Gen_Ctx_Primes(CKKS_Moduli *moduli, uint32_t m, uint32_t nBits, uint32_t len, BN_Optimizer *opt);
int32_t Build_Ctx_Primes(CKKS_Moduli *moduli, CRYPT_CKKS_Para *para, BN_Optimizer *opt);
int32_t CKKS_Moduli_Copy(CKKS_Moduli *dst, CKKS_Moduli *src);
CKKS_Moduli *CKKS_Moduli_Dup(const CKKS_Moduli *src);
bool CKKS_Moduli_Cmp(const CKKS_Moduli *m1, const CKKS_Moduli *m2);
void CKKS_Moduli_Destroy(CKKS_Moduli *moduli);
int32_t CKKS_DoubleCRT_Init(CKKS_DoubleCRT *doubleCRT, uint32_t bits, uint32_t m, const CKKS_Moduli *moduli);
int32_t Randomize_Map(BN_BigNum **map, const CKKS_Moduli *moduli, uint32_t phiM);
int32_t CKKS_Map_Copy(BN_BigNum **dst, BN_BigNum **src, uint32_t row, uint32_t column);
bool CKKS_Map_Cmp(BN_BigNum **m1, BN_BigNum **m2, uint32_t row, uint32_t column);
void CKKS_Map_Destroy(BN_BigNum **map, uint32_t row, uint32_t column);
int32_t CKKS_Poly2DoubleCRT(CKKS_DoubleCRT *doubleCRT, const CKKS_Poly *poly, const CKKS_Moduli *moduli,
                            BN_Optimizer *optimizer);
int32_t CKKS_DoubleCRT_AddSubMul(CKKS_DoubleCRT *res, const CKKS_DoubleCRT *d1, const CKKS_DoubleCRT *d2,
                                 CKKS_Moduli *moduli, BN_Optimizer *opt, int32_t flag);
int32_t CKKS_DoubleCRT_Copy(CKKS_DoubleCRT *dst, const CKKS_DoubleCRT *src);
CKKS_DoubleCRT *CKKS_DoubleCRT_Dup(const CKKS_DoubleCRT *src);
void CKKS_DoubleCRT_Destroy(CKKS_DoubleCRT *doubleCRT);
int32_t CKKS_DoubleCRT2Bin(const CKKS_DoubleCRT *doubleCRT, uint8_t *bin, uint32_t *binLen);
int32_t CKKS_Bin2DoubleCRT(CKKS_DoubleCRT *doubleCRT, const uint8_t *bin, uint32_t binLen);
int32_t CKKS_DoubleCRT_Cipher2Bin(CKKS_DoubleCRT *crt1, CKKS_DoubleCRT *crt2, uint8_t *bin, uint32_t *binLen);
int32_t CKKS_DoubleCRT_Bin2Cipher(const uint8_t *bin, uint32_t binLen, CKKS_DoubleCRT *crt1, CKKS_DoubleCRT *crt2);

#ifdef __cplusplus
}
#endif
#endif // HITLS_CRYPTO_CKKS

#endif // CKKS_UTILS_H