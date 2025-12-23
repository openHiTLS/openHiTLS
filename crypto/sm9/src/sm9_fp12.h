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

#ifndef _SM9_FP12_H_
#define _SM9_FP12_H_

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include "sm9_fp4.h"

#ifdef  __cplusplus
extern "C" {
#endif

void SM9_Fp12_ReadBytes(SM9_Fp12 *dst, const uint8_t *src);

void SM9_Fp12_WriteBytes(uint8_t *dst, SM9_Fp12 *src);

void SM9_Fp12_Reset(SM9_Fp12 *pFp12_E);
void SM9_Fp12_Assign(SM9_Fp12 *pDest, SM9_Fp12 *pSource);
void SM9_Fp12_SetOne(SM9_Fp12 *pFp12_E);

// pFp12_Prod = pFp12_A * pFp12_B mod pBN_M
void SM9_Fp12_Mul(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A, SM9_Fp12 *pFp12_B);
// pFp12_Prod = pFp12_A ^ 2 mod pBN_M
void SM9_Fp12_Squ(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A);
// pFp12_Res = pFp12_A ^ -1 mod pBN_M
void SM9_Fp12_Inv(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A);
// pFp12_Res = pFp12_X ^ pBN_E mod pBN_M
void SM9_Fp12_Exp(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A, uint32_t *pBn_E);

void SM9_Fp12_FrobMap(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A);

void SM9_Fp12_Mul_For_MillerLoop(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A, SM9_Fp12 *pFp12_B);

void SM9_Fp12_Mul_For_FrobMap(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A, SM9_Fp12 *pFp12_B);

void SM9_Fp12_GetConj(SM9_Fp12 *pwRes, SM9_Fp12 *pwA);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9

#endif // !_SM9_FP12_H_

