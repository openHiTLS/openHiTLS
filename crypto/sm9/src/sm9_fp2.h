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

#ifndef _SM9_FP2_H_
#define _SM9_FP2_H_

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include "sm9_fp.h"
#include "sm9_curve.h"

#ifdef  __cplusplus
extern "C" {
#endif

void SM9_Fp2_Reset(SM9_Fp2 *pElement);
void SM9_Fp2_Assign(SM9_Fp2 *pFp2_D, SM9_Fp2 *pFp2_S);
void SM9_Fp2_SetOne(SM9_Fp2 *pFp2_E);
int32_t SM9_Fp2_IsZero(SM9_Fp2 *pElement);

// pFp2_R = pFp2_A + pFp2_B
void SM9_Fp2_Add(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A, SM9_Fp2 *pFp2_B);
// pFp2_R = pFp2_A - pFp2_B
void SM9_Fp2_Sub(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A, SM9_Fp2 *pFp2_B);
// pFp2_R = - pFp2_A
void SM9_Fp2_Neg(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A);

// pFp2_R = pFp2_A * pFp2_B
void SM9_Fp2_Mul(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A, SM9_Fp2 *pFp2_B);
// pFp2_R = pFp2_A ^ 2
void SM9_Fp2_Squ(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A);
// pFp2_R = pFp2_A ^ -1
void SM9_Fp2_Inv(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A);

// r = a * b = (a0 + a1*u) * (b0 + 0*u)
void SM9_Fp2_Mul_Coef0(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A, uint32_t *pFp_B);
// r = a * u = (a0 + a1*u) * u
void SM9_Fp2_Mul_U(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A);
// r = a * v^q = (a0 + a1*u) * v^q
void SM9_Fp2_Mul_Vq(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A);
// r = a * w^q = (a0 + a1*u) * w^q
void SM9_Fp2_Mul_Wq(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A);

void SM9_Fp2_FrobMap(SM9_Fp2 *pwRes, SM9_Fp2 *pwA);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9

#endif // !_SM9_FP2_H_

