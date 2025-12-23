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

#include "sm9_fp4.h"
#include "sm9_curve.h"
#include "sm9_fp.h"

void SM9_Fp4_Add(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp4 *pFp4_B)
{
    SM9_Fp2_Add(&pFp4_R->Coef_0, &pFp4_A->Coef_0, &pFp4_B->Coef_0);
    SM9_Fp2_Add(&pFp4_R->Coef_1, &pFp4_A->Coef_1, &pFp4_B->Coef_1);
}

void SM9_Fp4_Sub(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp4 *pFp4_B)
{
    SM9_Fp2_Sub(&pFp4_R->Coef_0, &pFp4_A->Coef_0, &pFp4_B->Coef_0);
    SM9_Fp2_Sub(&pFp4_R->Coef_1, &pFp4_A->Coef_1, &pFp4_B->Coef_1);
}

void SM9_Fp4_Neg(SM9_Fp4 *pElementRes, SM9_Fp4 *pElementA)
{
    SM9_Fp2_Neg(&pElementRes->Coef_0, &pElementA->Coef_0);
    SM9_Fp2_Neg(&pElementRes->Coef_1, &pElementA->Coef_1);
}

void SM9_Fp4_Mul(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp4 *pFp4_B)
{
    SM9_Fp2 Fp2_V0;
    SM9_Fp2 Fp2_V1;
    SM9_Fp2 Fp2_V2;

    SM9_Fp2_Add(&Fp2_V0, &pFp4_A->Coef_0, &pFp4_A->Coef_1);    // V0 = a0 + a1
    SM9_Fp2_Add(&Fp2_V1, &pFp4_B->Coef_0, &pFp4_B->Coef_1);    // V1 = b0 + b1
    SM9_Fp2_Mul(&Fp2_V0, &Fp2_V0, &Fp2_V1);                    // V0 = V0 * V1 = (a0+a1)*(b0+b1)
    SM9_Fp2_Mul(&Fp2_V1, &pFp4_A->Coef_1, &pFp4_B->Coef_1);    // V1 = a1 * b1
    SM9_Fp2_Sub(&Fp2_V0, &Fp2_V0, &Fp2_V1);                    // V0 = V0 - V1 = (a0+a1)*(b0+b1)-a1*b1
    SM9_Fp2_Mul_U(&Fp2_V1, &Fp2_V1);                        // V1 = V1 *  u = a1*b1*u
    SM9_Fp2_Mul(&Fp2_V2, &pFp4_A->Coef_0, &pFp4_B->Coef_0);    // V2 = a0 * b0
    SM9_Fp2_Add(&pFp4_R->Coef_0, &Fp2_V1, &Fp2_V2);            // c0 = V1 + V2 = a0 *b0+a1*b1*u
    SM9_Fp2_Sub(&pFp4_R->Coef_1, &Fp2_V0, &Fp2_V2);            // c1 = V0 - V2 = v2*v3-v0-v1
}

void SM9_Fp4_Squ(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    SM9_Fp2 V0;
    SM9_Fp2 V2;
    SM9_Fp2 V3;

    SM9_Fp2_Sub(&V0, &pFp4_A->Coef_0, &pFp4_A->Coef_1); // V0= a0 - a1
    SM9_Fp2_Mul_U(&V3, &pFp4_A->Coef_1); // V3= u*a1
    SM9_Fp2_Sub(&V3, &pFp4_A->Coef_0, &V3); // V3= a0 - u*a1

    SM9_Fp2_Mul(&V2, &pFp4_A->Coef_0, &pFp4_A->Coef_1); // V2 = a0 * a1

    SM9_Fp2_Mul(&V0, &V0, &V3); // V0=V0*V3
    SM9_Fp2_Add(&V0, &V0, &V2); // V0=V0*V3+V2

    SM9_Fp2_Add(&pFp4_R->Coef_1, &V2, &V2); // c1 = V2 + V2

    SM9_Fp2_Mul_U(&pFp4_R->Coef_0, &V2); // c0 = u*V2
    SM9_Fp2_Add(&pFp4_R->Coef_0, &pFp4_R->Coef_0, &V0); // c0 = V0 + u*V2
}

void SM9_Fp4_Mul_Coef0(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp2 *pFp2_B)
{
    SM9_Fp2_Mul(&pFp4_R->Coef_0, &pFp4_A->Coef_0, pFp2_B);
    SM9_Fp2_Mul(&pFp4_R->Coef_1, &pFp4_A->Coef_1, pFp2_B);
}

void SM9_Fp4_MulWq(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    SM9_Fp2_Mul_Coef0(&pFp4_R->Coef_0, &pFp4_A->Coef_0, sm9_sys_para.EC_Wq_Mont);
    SM9_Fp2_Mul_Coef0(&pFp4_R->Coef_1, &pFp4_A->Coef_1, sm9_sys_para.EC_Wq_Mont);
}

void SM9_Fp4_MulW2q(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    SM9_Fp2_Mul_Coef0(&pFp4_R->Coef_0, &pFp4_A->Coef_0, sm9_sys_para.EC_W2q_Mont);
    SM9_Fp2_Mul_Coef0(&pFp4_R->Coef_1, &pFp4_A->Coef_1, sm9_sys_para.EC_W2q_Mont);
}

void SM9_Fp4_Inv(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    // pFp4_A = a0 + a1 * v, where v ^ 2 = u
    SM9_Fp2 T0;
    SM9_Fp2 T1;

    SM9_Fp2_Squ(&T0, &pFp4_A->Coef_0);    // a0 ^ 2
    SM9_Fp2_Squ(&T1, &pFp4_A->Coef_1);    // a1 ^ 2
    SM9_Fp2_Mul_U(&T1, &T1);            // a1^2 * u
    SM9_Fp2_Sub(&T0, &T0, &T1);            // a0^2 - a1^2 * u
    SM9_Fp2_Inv(&T1, &T0);                // T1=(a0^2 - a1^2 * u) ^ (-1)

    SM9_Fp2_Mul(&pFp4_R->Coef_0, &pFp4_A->Coef_0, &T1); // a0 / (a0^2 - a1^2 * u)
    SM9_Fp2_Neg(&T0, &pFp4_A->Coef_1); // T0=-a1
    SM9_Fp2_Mul(&pFp4_R->Coef_1, &T0, &T1); // -a1 / (a0^2 - a1^2 * u)
}

void SM9_Fp4_FrobMap(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    SM9_Fp2_FrobMap(&pFp4_R->Coef_0, &pFp4_A->Coef_0);
    SM9_Fp2_FrobMap(&pFp4_R->Coef_1, &pFp4_A->Coef_1);
    SM9_Fp2_Mul_Vq(&pFp4_R->Coef_1, &pFp4_R->Coef_1);
}

void SM9_Fp4_Mul_V(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    SM9_Fp2    tmpFp2;

    SM9_Fp2_Assign(&tmpFp2, &pFp4_A->Coef_0);

    // (a0+a1*v) * v=a0 * v + a1 *v ^2
    // = a1*u+a0 * v
    // tmpFp4.Coef_0 = a1* u
    SM9_Fp2_Mul_U(&pFp4_R->Coef_0, &pFp4_A->Coef_1);

    // tmpFp4.Coef_1 = a0
    SM9_Fp2_Assign(&pFp4_R->Coef_1, &tmpFp2);
}

void SM9_Fp4_Mul_Coef1(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp2 *pFp2_B)
{
    SM9_Fp2 Fp2_T0;

    SM9_Fp2_Mul(&Fp2_T0, &pFp4_A->Coef_1, pFp2_B);
    SM9_Fp2_Mul(&pFp4_R->Coef_1, &pFp4_A->Coef_0, pFp2_B);    // c1 = a0 * b1
    SM9_Fp2_Mul_U(&pFp4_R->Coef_0, &Fp2_T0);                // c0 = a1*b1*u
}

void SM9_Fp4_Mul_V2(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    // (a0+a1*v) * v^2=a0 * v^2 + a1 *v ^ 3
    // = a0*u+a1 * u * v
    // tmpFp4.Coef_0 = a0* u
    SM9_Fp2_Mul_U(&pFp4_R->Coef_0, &pFp4_A->Coef_0);

    // tmpFp4.Coef_1 = a1* u
    SM9_Fp2_Mul_U(&pFp4_R->Coef_1, &pFp4_A->Coef_1);
}

void SM9_Fp4_GetConj(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    SM9_Fp2_Assign(&pFp4_R->Coef_0, &pFp4_A->Coef_0);
    SM9_Fp2_Neg(&pFp4_R->Coef_1, &pFp4_A->Coef_1);
}

#endif // HITLS_CRYPTO_SM9
