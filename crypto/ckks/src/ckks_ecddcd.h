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

#ifndef CKKS_ECDDCD_H
#define CKKS_ECDDCD_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CKKS

#include <math.h>
#include "crypt_ckks.h"
#include "ckks_local.h"
#include "ckks_utils.h"
#include "crypt_bn.h"
#include "crypt_types.h"
#include "crypt_local_types.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
  * @ingroup ckks
  * @brief Check whether SIMD is available
  * 
  * @retval true     SIMD is available
  * @retval false    SIMD is unavailable
  */
int32_t CKKS_FFT_SIMD_Enabled();

/**
  * @ingroup ckks
  * @brief Allocate aligned memory. If SIMD is available, Some extra space is allocated to ensure memory alignment.
  * 
  * @param n [IN] input length
  * @param n_size [IN] The size of each element in bytes
  * 
  * @retval NULL
  */
void *CKKS_Aligned_Allocate(size_t n, size_t n_size);

/**
  * @ingroup ckks
  * @brief Free Allocated aligned memory. 
  * 
  * @param ptr [IN] Memory pointer to be deallocated. If SIMD is available, it will perform additional offset processing.
  * 
  * @retval NULL
  */
void CKKS_Aligned_Deallocate(void *ptr);

/**
  * @ingroup ckks
  * @brief When n is not a power of 2, an appropriate round up is performed
  * 
  * @param in_size [IN] input size
  * @param k [IN] target size
  * 
  * @retval Appropriate length value
  */
uint32_t Adjust_To_Tar_size(uint32_t in_size, uint32_t tar_scale);

/**
  * @ingroup ckks
  * @brief Calculate the power of the unit root
  * 
  * @param corr_factor [IN] Stores the power of the unit root, corr_factor->data[i] = 2^{2*pi*I*(i/m)}
  * @param n [IN] input length
  * 
  * @retval selected strategy
  */
int32_t Corr_Factor_Cal(CKKS_Complex_Array *corr_factor, const uint32_t n);

/**
  * @ingroup ckks
  * @brief Initializes the FFT structure
  * 
  * @param fft [IN] Stores fast Fourier transform related data
  * @param n [IN] input length
  * 
  * @retval selected strategy
  */
int32_t CKKS_FFT_Init(CKKS_FFT *fft, uint32_t n);

/**
  * @ingroup ckks
  * @brief Apply FFT on n points.
  * 
  * @param fft [IN] Stores fast Fourier transform related data
  * @param src [IN] Input complex array
  * @param dst [IN] Output complex array
  * @param n [IN] input length
  * 
  * @retval The value of n-point after FFT.
  */
int32_t CKKS_FFT_Apply(CKKS_FFT *fft, CKKS_Complex *src, CKKS_Complex *dst, uint32_t n);

/**
  * @ingroup ckks
  * @brief Destory CKKS_FFT
  * 
  * @param fft [IN] The CKKS_FFT to be destoryed
  * 
  * @retval NULL
  */
void CKKS_FFT_Destroy(CKKS_FFT *fft);

double Embedding_Largest_Coeff(CKKS_Poly *poly);
int32_t CKKS_Pi_Inverse(CKKS_Complex_Array *slot_vec, CKKS_Poly *Eptxt, const uint32_t m,
                        const CKKS_Complex_Array *complex_arr);
int32_t CKKS_Pi(CKKS_Complex_Array *out, const uint32_t ratfactor, const uint32_t m, const uint32_t *T);
int32_t Diagonal_Factor_Correction(CKKS_FFT *fft, CKKS_Complex_Array *mem, CKKS_Poly *Eptxt, double scaling);
int32_t CRYPT_CKKS_Encode(const CRYPT_CKKS_Ctx *ctx, CKKS_Poly *Eptxt, CKKS_Complex_Array *data);
int32_t CRYPT_CKKS_Decode(const CRYPT_CKKS_Ctx *ctx, const CKKS_Poly *Dptxt, CKKS_Complex_Array *out);

#ifdef __cplusplus
}
#endif
#endif // HITLS_CRYPTO_CKKS

#endif // CKKS_ECDDCD_H
