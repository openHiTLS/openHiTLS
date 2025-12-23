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

#ifndef __HEADER_SM9_Fp2_ECP_H__
#define __HEADER_SM9_Fp2_ECP_H__

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include "sm9_fp2.h"

#include "sm9_curve.h"

#ifdef  __cplusplus
extern "C" {
#endif

void SM9_Ecp2_A_ReadBytes(SM9_ECP2_A *dst, const uint8_t *src);
void SM9_Ecp2_A_WriteBytes(uint8_t *dst, SM9_ECP2_A *src);

void SM9_Ecp2_A_Reset(SM9_ECP2_A *pEcp2_A);
void SM9_Ecp2_J_Reset(SM9_ECP2_J *pEcp2_J);

void SM9_Ecp2_A_Assign(SM9_ECP2_A *pPointA, SM9_ECP2_A *pPointB);
void SM9_Ecp2_J_Assign(SM9_ECP2_J *pPointA, SM9_ECP2_J *pPointB);

void SM9_Ecp2_A_ToJ(SM9_ECP2_J *pJ_Point, SM9_ECP2_A *pA_Point);
void SM9_Ecp2_J_ToA(SM9_ECP2_A *pA_Point, SM9_ECP2_J *pJ_Point);

void SM9_Ecp2_J_AddA(SM9_ECP2_J *pJ_Sum, SM9_ECP2_J *pJp, SM9_ECP2_A *pAp);
void SM9_Ecp2_J_DoubleJ(SM9_ECP2_J *pJp_Result, SM9_ECP2_J *pJp);

void SM9_Ecp2_KP(SM9_ECP2_A *pKP, SM9_ECP2_A *pAp, uint32_t *pwK);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9

#endif

