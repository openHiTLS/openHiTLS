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

#ifndef __HEADER_SM9_R_ATE_PAIRING_H__
#define __HEADER_SM9_R_ATE_PAIRING_H__

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include "sm9_fp2.h"
#include "sm9_fp4.h"
#include "sm9_fp12.h"
#include "sm9_ecp.h"
#include "sm9_ecp2.h"

#ifdef  __cplusplus
extern "C" {
#endif

void SM9_Pairing_MulQuaRoot(SM9_Fp2 *pElementProd, SM9_Fp2 *pElementA);
void SM9_Pairing_MulCubRoot(SM9_Fp2 *pElementProd, SM9_Fp2 *pElementA);
void SM9_Pairing_MulQuaRoot_FrobMap(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A);
void SM9_Pairing_MulCubRoot_FrobMap(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_E);

void SM9_Pairing_EncDL(SM9_Fp12 *pLineEva, SM9_ECP2_J *pJSum, SM9_ECP2_J *pJT, SM9_ECP_A *pAP);
void SM9_Pairing_EncAL(SM9_Fp12 *pLineEva, SM9_ECP2_J *pJSum, SM9_ECP2_J *pJT, SM9_ECP2_A *pAQ, SM9_ECP_A *pAP);

void SM9_Pairing_EncAL_R_Ate_Q1(SM9_Fp12 *pLineEva, SM9_ECP2_J *pJSum, SM9_ECP2_J *pJT,
                                SM9_ECP2_A *pAQ, SM9_ECP_A *pAP);
void SM9_Pairing_EncAL_R_Ate_Q2(SM9_Fp12 *pLineEva, SM9_ECP2_J *pJT, SM9_ECP2_A *pAQ, SM9_ECP_A *pAP);

void SM9_Pairing_Miller_R_Tate(SM9_Fp12 *pFp12_R, SM9_ECP_A *pEcp_P1, SM9_ECP2_A *pEcp2_P2, uint32_t *pBn_T);

void SM9_Pairing_Exp_Q2(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_E);
void SM9_Pairing_Exp_Q4(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_E);
void SM9_Pairing_Exp_Q6(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_E);
void SM9_Pairing_FinExp(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_E);

void SM9_Pairing_R_Ate(SM9_Fp12 *pFp12_R, SM9_ECP_A *pEcp_P1, SM9_ECP2_A *pEcp2_P2);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9

#endif

