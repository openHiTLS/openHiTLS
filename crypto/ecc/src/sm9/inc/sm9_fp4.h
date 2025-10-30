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

#ifndef __HEADER_SM9_Fp4_H__
#define __HEADER_SM9_Fp4_H__

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include "sm9_fp2.h"

#ifdef  __cplusplus
extern "C" {
#endif

void SM9_Fp4_Print( SM9_Fp4 *pElement, int32_t  wsize);
void SM9_Fp4_Reset(SM9_Fp4 *pFp4_X);
void SM9_Fp4_Assign(SM9_Fp4 *pFp4_Y, SM9_Fp4 *pFp4_X);
void SM9_Fp4_SetOne(SM9_Fp4 *pFp4_X);
int  SM9_Fp4_IsZero(SM9_Fp4 *pElement);

int32_t  SM9_Fp4_JE(SM9_Fp4 *pElement1, SM9_Fp4 *pElement2, int32_t  wsize);

void SM9_Fp4_Add(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp4 *pFp4_B);
void SM9_Fp4_Sub(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp4 *pFp4_B);
void SM9_Fp4_Neg(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A);
void SM9_Fp4_Res(SM9_Fp4 *pFp4_A);
void SM9_Fp4_GetConj(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A);

void SM9_Fp4_Mul(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp4 *pFp4_B);
void SM9_Fp4_Squ(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A);
void SM9_Fp4_Inv(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A);

void SM9_Fp4_Exp(SM9_Fp4 *pwResult, SM9_Fp4 *pwX, uint32_t *pwE, uint32_t *pwM, uint32_t wModuleConst, int32_t wsize);
void SM9_Fp4_Random(SM9_Fp4 *pwA, int32_t wsize);

void SM9_Fp4_FrobMap(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A);

void SM9_Fp4_Mul_Coef0(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp2 *pFp2_B);
void SM9_Fp4_Mul_Coef1(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp2 *pFp2_B);
void SM9_Fp4_Mul_Coef0BN(SM9_Fp4 *pFp4_R, SM9_Fp4 *pElementA, uint32_t *pwBN);
void SM9_Fp4_Mul_V(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A);
void SM9_Fp4_Mul_V2(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A);

void SM9_Fp4_MulWq(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A);
void SM9_Fp4_MulW2q(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9

#endif

