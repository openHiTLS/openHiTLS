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

#ifndef _SM9_ECP_H_
#define _SM9_ECP_H_

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include "sm9_fp.h"

#ifdef  __cplusplus
extern "C" {
#endif

void SM9_Fp_ECP_A_Print(SM9_ECP_A *pECP_A, SM9_Sys_Para *pSysPara);
void SM9_Fp_ECP_J_Print(SM9_ECP_J *pECP_A, SM9_Sys_Para *pSysPara);

void SM9_Ecp_A_Reset(SM9_ECP_A *pECP_A);
void SM9_Ecp_J_Reset(SM9_ECP_J *pECP_J);

void SM9_Ecp_A_Assign(SM9_ECP_A *pPointA, SM9_ECP_A *pPointB);
void SM9_Ecp_J_Assign(SM9_ECP_J *pPointA, SM9_ECP_J *pPointB);

int32_t SM9_Fp_ECP_A_JE(SM9_ECP_A *pPointA, SM9_ECP_A *pPointB, SM9_Sys_Para *pSysPara);

void SM9_Ecp_A_ToJ(SM9_ECP_J *pJ_Point, SM9_ECP_A *pA_Point);
void SM9_Ecp_J_ToA(SM9_ECP_A *pAp, SM9_ECP_J *pJp);

void SM9_Ecp_J_AddA(SM9_ECP_J *pJ_Sum, SM9_ECP_J *pJp, SM9_ECP_A *pAp);
void SM9_Ecp_J_DoubleJ(SM9_ECP_J *pJp_Result, SM9_ECP_J *pJp);
void SM9_Ecp_KP(SM9_ECP_A *pKP, SM9_ECP_A *pAp, uint32_t *pwK);

void SM9_Fp_ECP_KPAddAToA(SM9_ECP_A *pKP, SM9_ECP_A *pAp, uint32_t *pwK, SM9_ECP_A *pBp, SM9_Sys_Para *pSysPara);

// Read ECP point from byte string and convert to MontMode
void SM9_Ecp_A_ReadBytes(SM9_ECP_A *dst, const unsigned char *src);

int SM9_Fp_ECP_A_ReadBytesWithPC(SM9_ECP_A *dst, unsigned char PC, const unsigned char *src);

// Convert to NormMode and write to byte string
void SM9_Ecp_A_WriteBytes(unsigned char *dst, SM9_ECP_A *src);

int SM9_Fp_ECP_A_WriteBytesWithPC(unsigned char *dst, unsigned char PC, SM9_ECP_A *src);

int  SM9_Ecp_A_Check(SM9_ECP_A *pAp);

void SM9_Ecp_A_DoubleKP(SM9_CTX *ctx, int nPr, int nBk, int nPk, int nBh, int nPh);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9

#endif // !_SM9_ECP_H_

