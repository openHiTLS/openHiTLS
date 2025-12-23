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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include "sm9_fp2.h"
#include "sm9_curve.h"
#include "sm9_fp.h"

void SM9_Fp2_Reset(SM9_Fp2 *pElement)
{
    memset(pElement, 0, sizeof(SM9_Fp2));
}

void SM9_Fp2_Assign(SM9_Fp2 *pFp2_D, SM9_Fp2 *pFp2_S)
{
    memcpy(pFp2_D, pFp2_S, sizeof(SM9_Fp2));
}

void SM9_Fp2_SetOne(SM9_Fp2 *pFp2_E)
{
    bn_assign(pFp2_E->Coef_0, sm9_sys_para.Q_R1, sm9_sys_para.wsize);
    memset(pFp2_E->Coef_1, 0, 4 * sm9_sys_para.wsize);
}

int32_t SM9_Fp2_IsZero(SM9_Fp2 *pFp2_E)
{
    if (SM9_Fq_IsZero(pFp2_E->Coef_0) == 0)
        return 0;
    if (SM9_Fq_IsZero(pFp2_E->Coef_1) == 0)
        return 0;
    return 1;
}

void SM9_Fp2_Add(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A, SM9_Fp2 *pFp2_B)
{
    SM9_Fp_Add(pFp2_R->Coef_0, pFp2_A->Coef_0, pFp2_B->Coef_0);
    SM9_Fp_Add(pFp2_R->Coef_1, pFp2_A->Coef_1, pFp2_B->Coef_1);
}

void SM9_Fp2_Sub(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A, SM9_Fp2 *pFp2_B)
{
    SM9_Fp_Sub(pFp2_R->Coef_0, pFp2_A->Coef_0, pFp2_B->Coef_0);
    SM9_Fp_Sub(pFp2_R->Coef_1, pFp2_A->Coef_1, pFp2_B->Coef_1);
}

void SM9_Fp2_Neg(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    SM9_Fp_Neg(pFp2_R->Coef_0, pFp2_A->Coef_0);
    SM9_Fp_Neg(pFp2_R->Coef_1, pFp2_A->Coef_1);
}

void SM9_Fp2_Mul(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A, SM9_Fp2 *pFp2_B)
{
    uint32_t Fp_T0[BNWordLen];
    uint32_t Fp_T1[BNWordLen];
    uint32_t Fp_T2[BNWordLen];

    SM9_Fp_Add(Fp_T0, pFp2_A->Coef_0, pFp2_A->Coef_1);    // T0 = a0 + a1
    SM9_Fp_Add(Fp_T1, pFp2_B->Coef_0, pFp2_B->Coef_1);    // T1 = b0 + b1
    SM9_Fp_Mul(Fp_T0, Fp_T0, Fp_T1);                    // T0 = T0 * T1 = (a0+a1)*(b0+b1)
    SM9_Fp_Mul(Fp_T1, pFp2_A->Coef_0, pFp2_B->Coef_0);    // T1 = a0 * b0
    SM9_Fp_Sub(Fp_T0, Fp_T0, Fp_T1);                    // T0 = T0 - T1 = (a0+a1)*(b0+b1)-a0*b0
    SM9_Fp_Mul(Fp_T2, pFp2_A->Coef_1, pFp2_B->Coef_1);    // T2 = a1 * b1
    SM9_Fp_Sub(Fp_T1, Fp_T1, Fp_T2);                    // T1 = T1 - T2 = a0*b0 - a1*b1
    SM9_Fp_Sub(pFp2_R->Coef_0, Fp_T1, Fp_T2);            // c0 = T1 - T2 = a0*b0 - 2*a1*b1
    SM9_Fp_Sub(pFp2_R->Coef_1, Fp_T0, Fp_T2);            // c1 = T0 - T2 = (a0+a1)*(b0+b1)-a0*b0-a1*b1
}

void SM9_Fp2_Squ(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    uint32_t Fp_T0[BNWordLen];
    uint32_t Fp_T1[BNWordLen];

    SM9_Fp_Sub(Fp_T0, pFp2_A->Coef_0, pFp2_A->Coef_1);    // v0=a0-a1
    SM9_Fp_Add(Fp_T1, pFp2_A->Coef_0, pFp2_A->Coef_1);    // v1=a0+a1
    SM9_Fp_Add(Fp_T1, Fp_T1, pFp2_A->Coef_1);            // v1=a0+2*a1
    SM9_Fp_Mul(Fp_T0, Fp_T0, Fp_T1);                    // v0=v0*v1 = (a0-a1)*(a0+2*a1)
    SM9_Fp_Mul(Fp_T1, pFp2_A->Coef_0, pFp2_A->Coef_1);    // v1=a0*a1
    SM9_Fp_Sub(pFp2_R->Coef_0, Fp_T0, Fp_T1);            // c0=v0-v1
    SM9_Fp_Add(pFp2_R->Coef_1, Fp_T1, Fp_T1);            // c1=v1+v1
}

void SM9_Fp2_Inv(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    uint32_t Fp_T0[BNWordLen];
    uint32_t Fp_T1[BNWordLen];

    SM9_Fp_Squ(Fp_T0, pFp2_A->Coef_0);            // a0 ^ 2
    SM9_Fp_Squ(Fp_T1, pFp2_A->Coef_1);            // a1 ^ 2
    SM9_Fp_Add(Fp_T0, Fp_T0, Fp_T1);
    SM9_Fp_Add(Fp_T0, Fp_T0, Fp_T1); // a0 ^ 2 + 2*a1 ^ 2
    SM9_Fp_Inv(Fp_T0, Fp_T0);            // 1 / (a0 ^ 2 + 2*a1 ^ 2)
    SM9_Fp_Mul(pFp2_R->Coef_0, pFp2_A->Coef_0, Fp_T0); // a0 / (a0 ^ 2 + 2*a1 ^ 2)
    SM9_Fp_Neg(Fp_T1, pFp2_A->Coef_1);            // -a1
    SM9_Fp_Mul(pFp2_R->Coef_1, Fp_T1, Fp_T0); // -a1 / (a0 ^ 2 + 2*a1 ^ 2)
}

void SM9_Fp2_Mul_Coef0(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A, uint32_t *pFp_B)
{
    SM9_Fp_Mul(pFp2_R->Coef_0, pFp2_A->Coef_0, pFp_B);
    SM9_Fp_Mul(pFp2_R->Coef_1, pFp2_A->Coef_1, pFp_B);
}

void SM9_Fp2_Mul_Vq(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    SM9_Fp_Mul(pFp2_R->Coef_0, pFp2_A->Coef_0, sm9_sys_para.EC_Vq_Mont);
    SM9_Fp_Mul(pFp2_R->Coef_1, pFp2_A->Coef_1, sm9_sys_para.EC_Vq_Mont);
}

void SM9_Fp2_Mul_Wq(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    SM9_Fp_Mul(pFp2_R->Coef_0, pFp2_A->Coef_0, sm9_sys_para.EC_Wq_Mont);
    SM9_Fp_Mul(pFp2_R->Coef_1, pFp2_A->Coef_1, sm9_sys_para.EC_Wq_Mont);
}

void SM9_Fp2_Mul_U(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    uint32_t Fp_T0[BNWordLen];

    SM9_Fp_Neg(Fp_T0, pFp2_A->Coef_1);
    SM9_Fp_Assign(pFp2_R->Coef_1, pFp2_A->Coef_0);
    SM9_Fp_Add(pFp2_R->Coef_0, Fp_T0, Fp_T0);
}

void SM9_Fp2_FrobMap(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    SM9_Fp_Assign(pFp2_R->Coef_0, pFp2_A->Coef_0);
    SM9_Fp_Neg(pFp2_R->Coef_1, pFp2_A->Coef_1);
}

#endif // HITLS_CRYPTO_SM9
