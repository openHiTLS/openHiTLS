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

#define    FP4_00(p)    (p)
#define FP4_01(p)    ((p) + 1)
#define FP4_10(p)    ((p) + 2)
#define FP4_11(p)    ((p) + 3)

#define FP4_0(p)    ((p))
#define FP4_1(p)    ((p) + 2)

void SM9_Fp4_Print( SM9_Fp4 *pElement, int32_t  wsize)
{
    SM9_Fp2_Print(&pElement->Coef_0, wsize);
    SM9_Fp2_Print(&pElement->Coef_1, wsize);
}

void SM9_Fp4_Reset(SM9_Fp4 *pFp4_X)
{
    memset(pFp4_X, 0, sizeof(SM9_Fp4));
}

void SM9_Fp4_Assign(SM9_Fp4 *pFp4_Y, SM9_Fp4 *pFp4_X)
{
    memcpy(pFp4_Y, pFp4_X, sizeof(SM9_Fp4));
}

void SM9_Fp4_SetOne(SM9_Fp4 *pFp4_X)
{
    memset(pFp4_X, 0, sizeof(SM9_Fp4));
    SM9_Fp_SetOne(pFp4_X->Coef_0.Coef_0);
}

int SM9_Fp4_IsZero(SM9_Fp4 *pFp4_E)
{
    if (SM9_Fp2_IsZero(&pFp4_E->Coef_0) == 0)
        return 0;
    if (SM9_Fp2_IsZero(&pFp4_E->Coef_1) == 0)
        return 0;
    return 1;
}

int32_t SM9_Fp4_JE(SM9_Fp4 *pElement1, SM9_Fp4 *pElement2, int32_t  wsize)
{
    int32_t res = 0;

    res = SM9_Fp2_JE(&pElement1->Coef_0, &pElement2->Coef_0, wsize);
    if ( res == 0)
    {
         return 0;
    }

    res = SM9_Fp2_JE(&pElement1->Coef_1, &pElement2->Coef_1, wsize);
    if ( res == 0)
    {
        return 0;
    }

    return 1;
}

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

    SM9_Fp2_Add(&Fp2_V0, &pFp4_A->Coef_0, &pFp4_A->Coef_1);    //V0 = a0 + a1
    SM9_Fp2_Add(&Fp2_V1, &pFp4_B->Coef_0, &pFp4_B->Coef_1);    //V1 = b0 + b1
    SM9_Fp2_Mul(&Fp2_V0, &Fp2_V0, &Fp2_V1);                    //V0 = V0 * V1 = (a0+a1)*(b0+b1)
    SM9_Fp2_Mul(&Fp2_V1, &pFp4_A->Coef_1, &pFp4_B->Coef_1);    //V1 = a1 * b1
    SM9_Fp2_Sub(&Fp2_V0, &Fp2_V0, &Fp2_V1);                    //V0 = V0 - V1 = (a0+a1)*(b0+b1)-a1*b1
    SM9_Fp2_Mul_U(&Fp2_V1, &Fp2_V1);                        //V1 = V1 *  u = a1*b1*u
    SM9_Fp2_Mul(&Fp2_V2, &pFp4_A->Coef_0, &pFp4_B->Coef_0);    //V2 = a0 * b0
    SM9_Fp2_Add(&pFp4_R->Coef_0, &Fp2_V1, &Fp2_V2);            //c0 = V1 + V2 = a0 *b0+a1*b1*u
    SM9_Fp2_Sub(&pFp4_R->Coef_1, &Fp2_V0, &Fp2_V2);            //c1 = V0 - V2 = v2*v3-v0-v1
}

void SM9_Fp4_Squ(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    SM9_Fp2 V0;
    SM9_Fp2 V2;
    SM9_Fp2 V3;

    SM9_Fp2_Sub(&V0, &pFp4_A->Coef_0, &pFp4_A->Coef_1);//V0= a0 - a1
    SM9_Fp2_Mul_U(&V3, &pFp4_A->Coef_1);//V3= u*a1
    SM9_Fp2_Sub(&V3, &pFp4_A->Coef_0, &V3);//V3= a0 - u*a1

    SM9_Fp2_Mul(&V2, &pFp4_A->Coef_0, &pFp4_A->Coef_1);//V2 = a0 * a1

    SM9_Fp2_Mul(&V0, &V0, &V3);//V0=V0*V3
    SM9_Fp2_Add(&V0, &V0, &V2);//V0=V0*V3+V2

    SM9_Fp2_Add(&pFp4_R->Coef_1, &V2, &V2);//c1 = V2 + V2

    SM9_Fp2_Mul_U(&pFp4_R->Coef_0, &V2);//c0 = u*V2
    SM9_Fp2_Add(&pFp4_R->Coef_0, &pFp4_R->Coef_0, &V0);//c0 = V0 + u*V2
}

void SM9_Fp4_Mul_Coef0(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp2 *pFp2_B)
{
    SM9_Fp2_Mul(&pFp4_R->Coef_0, &pFp4_A->Coef_0, pFp2_B);
    SM9_Fp2_Mul(&pFp4_R->Coef_1, &pFp4_A->Coef_1, pFp2_B);
}

void SM9_Fp4_Mul_Coef0BN(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, uint32_t *pwBN)
{
    SM9_Fp2_Mul_Coef0(&pFp4_R->Coef_0, &pFp4_A->Coef_0, pwBN);
    SM9_Fp2_Mul_Coef0(&pFp4_R->Coef_1, &pFp4_A->Coef_1, pwBN);
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
{//pFp4_A = a0 + a1 * v, where v ^ 2 = u
    SM9_Fp2 T0;
    SM9_Fp2 T1;

    SM9_Fp2_Squ(&T0, &pFp4_A->Coef_0);    // a0 ^ 2
    SM9_Fp2_Squ(&T1, &pFp4_A->Coef_1);    // a1 ^ 2
    SM9_Fp2_Mul_U(&T1, &T1);            // a1^2 * u
    SM9_Fp2_Sub(&T0, &T0, &T1);            // a0^2 - a1^2 * u
    SM9_Fp2_Inv(&T1, &T0);                //T1=(a0^2 - a1^2 * u) ^ (-1)

    SM9_Fp2_Mul(&pFp4_R->Coef_0, &pFp4_A->Coef_0, &T1);//a0 / (a0^2 - a1^2 * u)
    SM9_Fp2_Neg(&T0, &pFp4_A->Coef_1);// T0=-a1
    SM9_Fp2_Mul(&pFp4_R->Coef_1, &T0, &T1);//-a1 / (a0^2 - a1^2 * u)
}

void SM9_Fp4_Exp(SM9_Fp4 *pwResult, SM9_Fp4 *pwX, uint32_t *pwE, uint32_t *pwM, uint32_t wModuleConst, int32_t wsize)
{
    /***********************************/
    int32_t bitlen = 0;
    int32_t i = 0;
    uint32_t flag[32] = {0x00000001,0x00000002,0x00000004,0x00000008,
                   0x00000010,0x00000020,0x00000040,0x00000080,
                   0x00000100,0x00000200,0x00000400,0x00000800,
                   0x00001000,0x00002000,0x00004000,0x00008000,
                   0x00010000,0x00020000,0x00040000,0x00080000,
                   0x00100000,0x00200000,0x00400000,0x00800000,
                   0x01000000,0x02000000,0x04000000,0x08000000,
                   0x10000000,0x20000000,0x40000000,0x80000000};
    SM9_Fp4 Result_T;
    /***********************************/
    (void)pwM;
    (void)wModuleConst;

    // SM9_Fp4_Reset(&Result_T, BNWordLen);

    bitlen = bn_get_bitlen(pwE, wsize);
    if (bitlen == 0)
    {
        SM9_Fp4_SetOne(&Result_T);
    }
    else
    {
        SM9_Fp4_Assign(&Result_T, pwX);
        for (i = bitlen - 2; i >= 0; i--)
        {
            SM9_Fp4_Mul(&Result_T, &Result_T, &Result_T);
            if (pwE[i / WordLen] & flag[i % WordLen])
                SM9_Fp4_Mul(&Result_T, &Result_T, pwX);
        }
    }

    SM9_Fp4_Assign(pwResult, &Result_T);
}

void SM9_Fp4_Random(SM9_Fp4 *pwA, int32_t wsize)
{
    SM9_Fp2_Random(&pwA->Coef_0, wsize);
    SM9_Fp2_Random(&pwA->Coef_1, wsize);
}

void SM9_Fp4_Res(SM9_Fp4 *pFp4_A)
{
    SM9_Fp2_LastRes(&pFp4_A->Coef_0);
    SM9_Fp2_LastRes(&pFp4_A->Coef_1);
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

    //(a0+a1*v) * v=a0 * v + a1 *v ^2
    //=a1*u+a0 * v
    // tmpFp4.Coef_0 = a1* u
    SM9_Fp2_Mul_U(&pFp4_R->Coef_0, &pFp4_A->Coef_1);

    // tmpFp4.Coef_1 = a0
    SM9_Fp2_Assign(&pFp4_R->Coef_1, &tmpFp2);
}

void SM9_Fp4_Mul_Coef1(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A, SM9_Fp2 *pFp2_B)
{
    SM9_Fp2    Fp2_T0;

    SM9_Fp2_Mul(&Fp2_T0, &pFp4_A->Coef_1, pFp2_B);
    SM9_Fp2_Mul(&pFp4_R->Coef_1, &pFp4_A->Coef_0, pFp2_B);    //c1 = a0 * b1
    SM9_Fp2_Mul_U(&pFp4_R->Coef_0, &Fp2_T0);                //c0 = a1*b1*u
}

void SM9_Fp4_Mul_V2(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    ////(a0+a1*v) * v^2=a0 * v^2 + a1 *v ^ 3
    ////=a0*u+a1 * u * v
    ////tmpFp4.Coef_0 = a0* u
    SM9_Fp2_Mul_U(&pFp4_R->Coef_0, &pFp4_A->Coef_0);

    ////tmpFp4.Coef_1 = a1* u
    SM9_Fp2_Mul_U(&pFp4_R->Coef_1, &pFp4_A->Coef_1);
}

void SM9_Fp4_GetConj(SM9_Fp4 *pFp4_R, SM9_Fp4 *pFp4_A)
{
    SM9_Fp2_Assign(&pFp4_R->Coef_0, &pFp4_A->Coef_0);
    SM9_Fp2_Neg(&pFp4_R->Coef_1, &pFp4_A->Coef_1);
}

#endif // HITLS_CRYPTO_SM9
