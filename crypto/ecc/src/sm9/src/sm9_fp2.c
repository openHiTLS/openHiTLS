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

#define    FP2_0(p)    (p)
#define FP2_1(p)    ((p) + 1)

void SM9_Fp2_Print( SM9_Fp2 *pElement, int32_t  wsize)
{
    BN_Print(pElement->Coef_0, wsize);
    BN_Print(pElement->Coef_1, wsize);
}

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

int SM9_Fp2_IsZero(SM9_Fp2 *pFp2_E)
{
    if (SM9_Fq_IsZero(pFp2_E->Coef_0) == 0)
        return 0;
    if (SM9_Fq_IsZero(pFp2_E->Coef_1) == 0)
        return 0;
    return 1;
}

int32_t SM9_Fp2_JE(SM9_Fp2 *pElement1, SM9_Fp2 *pElement2, int32_t  wsize)
{
    int32_t res = 0;

    res = bn_equal(pElement1->Coef_0, pElement2->Coef_0, wsize);
    if ( res == 0)
    {
         return 0;
    }

    res = bn_equal(pElement1->Coef_1, pElement2->Coef_1, wsize);
    if ( res == 0)
    {
        return 0;
    }

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

    SM9_Fp_Add(Fp_T0, pFp2_A->Coef_0, pFp2_A->Coef_1);    //T0 = a0 + a1
    SM9_Fp_Add(Fp_T1, pFp2_B->Coef_0, pFp2_B->Coef_1);    //T1 = b0 + b1
    SM9_Fp_Mul(Fp_T0, Fp_T0, Fp_T1);                    //T0 = T0 * T1 = (a0+a1)*(b0+b1)
    SM9_Fp_Mul(Fp_T1, pFp2_A->Coef_0, pFp2_B->Coef_0);    //T1 = a0 * b0
    SM9_Fp_Sub(Fp_T0, Fp_T0, Fp_T1);                    //T0 = T0 - T1 = (a0+a1)*(b0+b1)-a0*b0
    SM9_Fp_Mul(Fp_T2, pFp2_A->Coef_1, pFp2_B->Coef_1);    //T2 = a1 * b1
    SM9_Fp_Sub(Fp_T1, Fp_T1, Fp_T2);                    //T1 = T1 - T2 = a0*b0 - a1*b1
    SM9_Fp_Sub(pFp2_R->Coef_0, Fp_T1, Fp_T2);            //c0 = T1 - T2 = a0*b0 - 2*a1*b1
    SM9_Fp_Sub(pFp2_R->Coef_1, Fp_T0, Fp_T2);            //c1 = T0 - T2 = (a0+a1)*(b0+b1)-a0*b0-a1*b1
}

void SM9_Fp2_Squ(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    uint32_t Fp_T0[BNWordLen];
    uint32_t Fp_T1[BNWordLen];

    SM9_Fp_Sub(Fp_T0, pFp2_A->Coef_0, pFp2_A->Coef_1);    //v0=a0-a1
    SM9_Fp_Add(Fp_T1, pFp2_A->Coef_0, pFp2_A->Coef_1);    //v1=a0+a1
    SM9_Fp_Add(Fp_T1, Fp_T1, pFp2_A->Coef_1);            //v1=a0+2*a1
    SM9_Fp_Mul(Fp_T0, Fp_T0, Fp_T1);                    //v0=v0*v1 = (a0-a1)*(a0+2*a1)
    SM9_Fp_Mul(Fp_T1, pFp2_A->Coef_0, pFp2_A->Coef_1);    //v1=a0*a1
    SM9_Fp_Sub(pFp2_R->Coef_0, Fp_T0, Fp_T1);            //c0=v0-v1
    SM9_Fp_Add(pFp2_R->Coef_1, Fp_T1, Fp_T1);            //c1=v1+v1
}

void SM9_Fp2_Inv(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    uint32_t Fp_T0[BNWordLen];
    uint32_t Fp_T1[BNWordLen];

    SM9_Fp_Squ(Fp_T0, pFp2_A->Coef_0);            //a0 ^ 2
    SM9_Fp_Squ(Fp_T1, pFp2_A->Coef_1);            //a1 ^ 2
    SM9_Fp_Add(Fp_T0, Fp_T0, Fp_T1);
    SM9_Fp_Add(Fp_T0, Fp_T0, Fp_T1);//a0 ^ 2 + 2*a1 ^ 2
    SM9_Fp_Inv(Fp_T0, Fp_T0);            //1 / (a0 ^ 2 + 2*a1 ^ 2)
    SM9_Fp_Mul(pFp2_R->Coef_0, pFp2_A->Coef_0, Fp_T0);//a0 / (a0 ^ 2 + 2*a1 ^ 2)
    SM9_Fp_Neg(Fp_T1, pFp2_A->Coef_1);            //-a1
    SM9_Fp_Mul(pFp2_R->Coef_1, Fp_T1, Fp_T0);//-a1 / (a0 ^ 2 + 2*a1 ^ 2)
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

void SM9_Fp2_Exp(SM9_Fp2 *pwResult, SM9_Fp2 *pwX, uint32_t *pwE, uint32_t *pwM,  uint32_t wModuleConst, int32_t wsize)
{
    /***********************************/
    int bitlen, i;
    uint32_t flag[32] = {0x00000001,0x00000002,0x00000004,0x00000008,
                   0x00000010,0x00000020,0x00000040,0x00000080,
                   0x00000100,0x00000200,0x00000400,0x00000800,
                   0x00001000,0x00002000,0x00004000,0x00008000,
                   0x00010000,0x00020000,0x00040000,0x00080000,
                   0x00100000,0x00200000,0x00400000,0x00800000,
                   0x01000000,0x02000000,0x04000000,0x08000000,
                   0x10000000,0x20000000,0x40000000,0x80000000};
    SM9_Fp2 Result_T;
    /***********************************/
    (void)pwM;
    (void)wModuleConst;

    SM9_Fp2_Reset(&Result_T);

    bitlen = bn_get_bitlen(pwE, wsize);
    if (bitlen == 0)
    {
        SM9_Fp2_SetOne(&Result_T);
    }
    else
    {
        SM9_Fp2_Assign(&Result_T, pwX);

        for (i = bitlen - 2; i >= 0; i--)
        {
            SM9_Fp2_Squ(&Result_T, &Result_T);
            if (pwE[i / WordLen] & flag[i % WordLen])
                SM9_Fp2_Mul(&Result_T, &Result_T, pwX);
        }
    }

    SM9_Fp2_Assign(pwResult, &Result_T);
}

void SM9_Fp2_Random(SM9_Fp2 *pwA, int32_t wsize)
{
    BN_Random(pwA->Coef_0, wsize);
    BN_Random(pwA->Coef_1, wsize);
}

void SM9_Fp2_LastRes(SM9_Fp2 *pFp2_A)
{
    SM9_Fp_LastRes(pFp2_A->Coef_0);
    SM9_Fp_LastRes(pFp2_A->Coef_1);
}

void SM9_Fp2_FrobMap(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    SM9_Fp_Assign(pFp2_R->Coef_0, pFp2_A->Coef_0);
    SM9_Fp_Neg(pFp2_R->Coef_1, pFp2_A->Coef_1);
}

#endif // HITLS_CRYPTO_SM9
