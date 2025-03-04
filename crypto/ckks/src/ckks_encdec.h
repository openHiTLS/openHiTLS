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

#ifndef CKKS_ENCDEC_H
#define CKKS_ENCDEC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CKKS

#include <math.h>
#include "crypt_ckks.h"
#include "ckks_local.h"
#include "ckks_ecddcd.h"
#include "crypt_utils.h"
#include "crypt_bn.h"
#include "crypt_types.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
  * @ingroup ckks
  * @brief Noise boundary for L-infinite norm with high probability
  * 
  * @param magBound [IN] Uniform distribution range of polynomial coefficients, All coefficients satisfied [-magBound,magBound]
  * @param degBound [IN] The number of the coefficients
  * @param scale [IN] The defalut is 10. The scale satisfy: Pr(|X|>scale\cdot \delta)=erfc(?scale/\sqrt(2)). The total failure probability is: \epsilon=\phi(m)\cdot erfc(?scale/\sqrt(2)?)
  * 
  * @retval Noise bound
  */
double Default_Err(double magBound, uint32_t degBound);

/**
  * @ingroup ckks
  * @brief Calculate the default scaling factor
  * 
  * @param err [IN] Noise bound
  * @param prec [IN] Precision bit number,the default is 20.
  * 
  * @retval Scaling factor
  */
double Default_Scale(double err, int32_t prec);
int32_t Sample_Gaussian_Bound(double *bound, CKKS_Poly *poly, double stdev);
double RLWE(CRYPT_CKKS_Ctx *ctx, CKKS_DoubleCRT *p0, CKKS_DoubleCRT *p1, CKKS_DoubleCRT *s, BN_Optimizer *opt);

#ifdef __cplusplus
}
#endif
#endif // HITLS_CRYPTO_CKKS

#endif // CKKS_ENCDEC_H