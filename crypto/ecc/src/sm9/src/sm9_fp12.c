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

#include "sm9_fp12.h"
#include "sm9_fp.h"

// read fp12 element and convert to MontMode
void SM9_Fp12_ReadBytes(SM9_Fp12 *dst, const unsigned char *src)
{
    SM9_Fp_ReadBytes(dst->Coef_0.Coef_0.Coef_0, src + 11 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_0.Coef_0.Coef_1, src + 10 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_0.Coef_1.Coef_0, src + 9 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_0.Coef_1.Coef_1, src + 8 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_1.Coef_0.Coef_0, src + 7 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_1.Coef_0.Coef_1, src + 6 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_1.Coef_1.Coef_0, src + 5 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_1.Coef_1.Coef_1, src + 4 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_2.Coef_0.Coef_0, src + 3 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_2.Coef_0.Coef_1, src + 2 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_2.Coef_1.Coef_0, src + BNByteLen);
    SM9_Fp_ReadBytes(dst->Coef_2.Coef_1.Coef_1, src);
}

// write fp12 element and convert to NormMode
void SM9_Fp12_WriteBytes(unsigned char *dst, SM9_Fp12 *src)
{
    SM9_Fp_WriteBytes(dst + 11 * BNByteLen, src->Coef_0.Coef_0.Coef_0);
    SM9_Fp_WriteBytes(dst + 10 * BNByteLen, src->Coef_0.Coef_0.Coef_1);
    SM9_Fp_WriteBytes(dst +  9 * BNByteLen, src->Coef_0.Coef_1.Coef_0);
    SM9_Fp_WriteBytes(dst +  8 * BNByteLen, src->Coef_0.Coef_1.Coef_1);
    SM9_Fp_WriteBytes(dst +  7 * BNByteLen, src->Coef_1.Coef_0.Coef_0);
    SM9_Fp_WriteBytes(dst +  6 * BNByteLen, src->Coef_1.Coef_0.Coef_1);
    SM9_Fp_WriteBytes(dst +  5 * BNByteLen, src->Coef_1.Coef_1.Coef_0);
    SM9_Fp_WriteBytes(dst +  4 * BNByteLen, src->Coef_1.Coef_1.Coef_1);
    SM9_Fp_WriteBytes(dst +  3 * BNByteLen, src->Coef_2.Coef_0.Coef_0);
    SM9_Fp_WriteBytes(dst +  2 * BNByteLen, src->Coef_2.Coef_0.Coef_1);
    SM9_Fp_WriteBytes(dst +      BNByteLen, src->Coef_2.Coef_1.Coef_0);
    SM9_Fp_WriteBytes(dst, src->Coef_2.Coef_1.Coef_1);
}

void SM9_Fp12_Print( SM9_Fp12 *pElement, int32_t  wsize)
{
    SM9_Fp4_Print(&pElement->Coef_0, wsize);
    SM9_Fp4_Print(&pElement->Coef_1, wsize);
    SM9_Fp4_Print(&pElement->Coef_2, wsize);
}

void SM9_Fp12_Reset(SM9_Fp12 *pFp12_E)
{
    memset(pFp12_E, 0, sizeof(SM9_Fp12));
}

void SM9_Fp12_Assign(SM9_Fp12 *pFp12_D, SM9_Fp12 *pFp12_S)
{
    memcpy(pFp12_D, pFp12_S, sizeof(SM9_Fp12));
}

void SM9_Fp12_SetOne(SM9_Fp12 *pFp12_E)
{
    SM9_Fp12_Reset(pFp12_E);
    SM9_Fp_SetOne(pFp12_E->Coef_0.Coef_0.Coef_0);
}

int SM9_Fp12_IsZero(SM9_Fp12 *pFp12_E)
{
    if (SM9_Fp4_IsZero(&pFp12_E->Coef_0) == 0)
        return 0;
    if (SM9_Fp4_IsZero(&pFp12_E->Coef_1) == 0)
        return 0;
    if (SM9_Fp4_IsZero(&pFp12_E->Coef_2) == 0)
        return 0;
    return 1;
}

int32_t SM9_Fp12_JE(SM9_Fp12 *pElement1, SM9_Fp12 *pElement2, int32_t  wsize)
{
    int32_t res = 0;

    res = SM9_Fp4_JE(&pElement1->Coef_0, &pElement2->Coef_0, wsize);
    if ( res == 0)
    {
         return 0;
    }

    res = SM9_Fp4_JE(&pElement1->Coef_1, &pElement2->Coef_1, wsize);
    if ( res == 0)
    {
        return 0;
    }

    res = SM9_Fp4_JE(&pElement1->Coef_2, &pElement2->Coef_2, wsize);
    if ( res == 0)
    {
        return 0;
    }

    return 1;
}

#define Fp4_a0    (pFp12_A->Coef_0)
#define Fp4_a1    (pFp12_A->Coef_1)
#define Fp4_a2    (pFp12_A->Coef_2)
#define Fp4_b0    (pFp12_B->Coef_0)
#define Fp4_b1    (pFp12_B->Coef_1)
#define Fp4_b2    (pFp12_B->Coef_2)
#define Fp4_c0    (pFp12_R->Coef_0)
#define Fp4_c1    (pFp12_R->Coef_1)
#define Fp4_c2    (pFp12_R->Coef_2)

void SM9_Fp12_Add(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A, SM9_Fp12 *pFp12_B)
{
    SM9_Fp4_Add(&Fp4_c0, &Fp4_a0, &Fp4_b0);
    SM9_Fp4_Add(&Fp4_c1, &Fp4_a1, &Fp4_b1);
    SM9_Fp4_Add(&Fp4_c2, &Fp4_a2, &Fp4_b2);
}

void SM9_Fp12_Sub(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A, SM9_Fp12 *pFp12_B)
{
    SM9_Fp4_Sub(&Fp4_c0, &Fp4_a0, &Fp4_b0);
    SM9_Fp4_Sub(&Fp4_c1, &Fp4_a1, &Fp4_b1);
    SM9_Fp4_Sub(&Fp4_c2, &Fp4_a2, &Fp4_b2);
}

void SM9_Fp12_Neg(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A)
{
    SM9_Fp4_Neg(&pFp12_R->Coef_0, &Fp4_a0);
    SM9_Fp4_Neg(&pFp12_R->Coef_1, &Fp4_a1);
    SM9_Fp4_Neg(&pFp12_R->Coef_2, &Fp4_a2);
}

void SM9_Fp12_Mul(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A, SM9_Fp12 *pFp12_B)
{
    SM9_Fp4 Fp4_V0;
    SM9_Fp4 Fp4_V1;
    SM9_Fp4 Fp4_V2;
    SM9_Fp4 Fp4_V3;
    SM9_Fp4 Fp4_V4;
    SM9_Fp4 Fp4_V5;
    SM9_Fp4 Fp4_V6;

    SM9_Fp4_Mul(&Fp4_V0, &Fp4_a0, &Fp4_b0);    //V0=a0*b0
    SM9_Fp4_Mul(&Fp4_V1, &Fp4_a1, &Fp4_b1);    //V1=a1*b1
    SM9_Fp4_Mul(&Fp4_V2, &Fp4_a2, &Fp4_b2);    //V2=a2*b2

    SM9_Fp4_Add(&Fp4_V3, &Fp4_a1, &Fp4_a2);    //V3= a1 + a2
    SM9_Fp4_Add(&Fp4_V6, &Fp4_b1, &Fp4_b2);    //V6= b1 + b2
    SM9_Fp4_Mul(&Fp4_V3, &Fp4_V3, &Fp4_V6);    //V3=(a1+a2)*(b1+b2)

    SM9_Fp4_Add(&Fp4_V4, &Fp4_a0, &Fp4_a1);    //Fp4_V4= a0 + a1
    SM9_Fp4_Add(&Fp4_V6, &Fp4_b0, &Fp4_b1);    //V6= b0 + b1
    SM9_Fp4_Mul(&Fp4_V4, &Fp4_V4, &Fp4_V6);    //V4=(a0+a1)*(b0+b1)

    SM9_Fp4_Add(&Fp4_V5, &Fp4_a0, &Fp4_a2);    //V5= a0 + a2
    SM9_Fp4_Add(&Fp4_V6, &Fp4_b0, &Fp4_b2);    //V6= b0 + b2
    SM9_Fp4_Mul(&Fp4_V5, &Fp4_V5, &Fp4_V6);    //V5=(a0+a2)*(b0+b2)

    SM9_Fp4_Sub(&Fp4_V3, &Fp4_V3, &Fp4_V1);    //V3=(a1+a2)*(b1+b2)-V1
    SM9_Fp4_Sub(&Fp4_V3, &Fp4_V3, &Fp4_V2);    //V3=(a1+a2)*(b1+b2)-V1-V2
    SM9_Fp4_Mul_V(&Fp4_V3, &Fp4_V3);    //V3=((a1+a2)*(b1+b2)-V1-V2)*v
    SM9_Fp4_Add(&Fp4_c0, &Fp4_V3, &Fp4_V0);    //c0=((a1+a2)*(b1+b2)-V1-V2)*v+V0

    SM9_Fp4_Sub(&Fp4_V4, &Fp4_V4, &Fp4_V0);    //V4=(a0+a1)*(b0+b1)-V0
    SM9_Fp4_Sub(&Fp4_V4, &Fp4_V4, &Fp4_V1);    //V4=(a0+a1)*(b0+b1)-V0-V1
    SM9_Fp4_Mul_V(&Fp4_V6, &Fp4_V2);    //V6=V2 * v
    SM9_Fp4_Add(&Fp4_c1, &Fp4_V4, &Fp4_V6);    //c1=(a0+a1)*(b0+b1)-V0-V1+V2*v

    SM9_Fp4_Sub(&Fp4_V5, &Fp4_V5, &Fp4_V0);    //V5=(a0+a2)*(b0+b2)-V0
    SM9_Fp4_Sub(&Fp4_V5, &Fp4_V5, &Fp4_V2);    //V5=(a0+a2)*(b0+b2)-V0-V2
    SM9_Fp4_Add(&Fp4_c2, &Fp4_V5, &Fp4_V1);    //c2=(a0+a2)*(b0+b2)-V0-V2+V1
}

void SM9_Fp12_Squ(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A)
{
    SM9_Fp4 Fp4_V0;
    SM9_Fp4 Fp4_V1;
    SM9_Fp4 Fp4_V2;
    SM9_Fp4 Fp4_V3;
    SM9_Fp4 Fp4_V4;

    SM9_Fp4_Mul(&Fp4_V0, &Fp4_a1, &Fp4_a2);
    SM9_Fp4_Add(&Fp4_V0, &Fp4_V0, &Fp4_V0);        //V0 = 2*a1*a2
    SM9_Fp4_Mul(&Fp4_V1, &Fp4_a0, &Fp4_a1);
    SM9_Fp4_Add(&Fp4_V1, &Fp4_V1, &Fp4_V1);        //V1 = 2*a0*a1
    SM9_Fp4_Add(&Fp4_V2, &Fp4_a0, &Fp4_a1);
    SM9_Fp4_Add(&Fp4_V2, &Fp4_V2, &Fp4_a2);
    SM9_Fp4_Squ(&Fp4_V2, &Fp4_V2);                //V2 = (a0+a1+a2) ^ 2
    SM9_Fp4_Squ(&Fp4_V3, &Fp4_a0);                //V3 = a0^2
    SM9_Fp4_Squ(&Fp4_V4, &Fp4_a2);                //V4 = a2^2
    SM9_Fp4_Sub(&Fp4_V2, &Fp4_V2, &Fp4_V1);
    SM9_Fp4_Sub(&Fp4_V2, &Fp4_V2, &Fp4_V0);
    SM9_Fp4_Sub(&Fp4_V2, &Fp4_V2, &Fp4_V3);
    SM9_Fp4_Sub(&Fp4_c2, &Fp4_V2, &Fp4_V4);        //c3 = V2-V1-V0-V3-V4
    SM9_Fp4_Mul_V(&Fp4_V0, &Fp4_V0);
    SM9_Fp4_Add(&Fp4_c0, &Fp4_V3, &Fp4_V0);        //c0 = V0*u + V3
    SM9_Fp4_Mul_V(&Fp4_V4, &Fp4_V4);
    SM9_Fp4_Add(&Fp4_c1, &Fp4_V4, &Fp4_V1);        //c1 = V4*u + V1
}

void SM9_Fp12_Inv(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A)
{
    //(a0*b0 + (a2*b1 + a1*b2) * v) + (a1*b0 + a0*b1 + a2*b2 *v)*w + (a2*b0 + a1*b1 + a0*b2) w ^ 2
    //    Delta = a0 ^ 3 + a1 ^ 3 * v - 3 * a0*a1*a2*v + a2 ^ 3 * v ^ 2
    //    Delta0 = a0 ^ 2 - a1*a2*v
    //    Delta1 = -a0*a1 + a2 ^ 2 * v
    //    Delta2 = a1 ^ 2 - a0*a2
    SM9_Fp4 Fp4_V0;
    SM9_Fp4 Fp4_V1;
    SM9_Fp4 Fp4_V2;
    SM9_Fp4 Fp4_V3;
    SM9_Fp4 Fp4_V4;

    SM9_Fp4_Squ(&Fp4_V0, &Fp4_a0);                //V0=a0^2
    SM9_Fp4_Squ(&Fp4_V1, &Fp4_a2);                //V1=a2^2
    SM9_Fp4_Squ(&Fp4_V2, &Fp4_a1);                //V2=a1^2

    SM9_Fp4_Mul(&Fp4_V3, &Fp4_V0, &Fp4_a0);        //V3=a0^3
    SM9_Fp4_Mul(&Fp4_V4, &Fp4_V2, &Fp4_a1);        //V4=a1^3
    SM9_Fp4_Mul_V(&Fp4_V4, &Fp4_V4);        //V4=a1^3 * v
    SM9_Fp4_Add(&Fp4_V3, &Fp4_V3, &Fp4_V4);        //V3=a0^3 + a1^3 * v
    SM9_Fp4_Mul(&Fp4_V4, &Fp4_V1, &Fp4_a2);        //V4=a2^3
    SM9_Fp4_Mul_V2(&Fp4_V4, &Fp4_V4);        //V4=a2^3* v^2
    SM9_Fp4_Add(&Fp4_V3, &Fp4_V3, &Fp4_V4);        //V3=a0^3 + a1^3 * v+a2^3*v^2

    SM9_Fp4_Mul(&Fp4_V4, &Fp4_a0, &Fp4_a2);        //V4=a0*a2
    SM9_Fp4_Sub(&Fp4_V2, &Fp4_V2, &Fp4_V4);        //V2=a1^2 - a0*a2

    SM9_Fp4_Mul(&Fp4_V4, &Fp4_a0, &Fp4_a1);        //V4=a0*a1
    SM9_Fp4_Mul_V(&Fp4_V1, &Fp4_V1);        //V1=a2^2*v
    SM9_Fp4_Sub(&Fp4_V1, &Fp4_V1, &Fp4_V4);        //V1=-a0*a1 + a2^2*v

    SM9_Fp4_Mul(&Fp4_V4, &Fp4_a1, &Fp4_a2);        //V4=a1*a2
    SM9_Fp4_Mul_V(&Fp4_V4, &Fp4_V4);        //V4=a1*a2*v
    SM9_Fp4_Sub(&Fp4_V0, &Fp4_V0, &Fp4_V4);        //V0=a0^2 - a1*a2*v

    SM9_Fp4_Mul(&Fp4_V4, &Fp4_V4, &Fp4_a0);        //T3=a0*a1*a2*v
    SM9_Fp4_Sub(&Fp4_V3, &Fp4_V3, &Fp4_V4);
    SM9_Fp4_Sub(&Fp4_V3, &Fp4_V3, &Fp4_V4);
    SM9_Fp4_Sub(&Fp4_V3, &Fp4_V3, &Fp4_V4);        //V3=a0^3 + a1^3 * v + a2^3*v^2 - 3*a0*a1*a2*v
    SM9_Fp4_Inv(&Fp4_V3, &Fp4_V3);                //V3=(a0^3 + a1^3 * Zeta - 3*a0*a1*a2*Zeta + a2^3*Zeta^2) ^ (-1)
    SM9_Fp4_Mul(&Fp4_c1, &Fp4_V1, &Fp4_V3);        //c1=(-a0*a1 + a2^2*v)/(a0^3 + a1^3 * v - 3*a0*a1*a2*v + a2^3*v^2)
    SM9_Fp4_Mul(&Fp4_c0, &Fp4_V0, &Fp4_V3);        //c0=(a0^2 - a1*a2*Zeta)/(a0^3 + a1^3 * Zeta - 3*a0*a1*a2*Zeta + a2^3*Zeta^2)
    SM9_Fp4_Mul(&Fp4_c2, &Fp4_V2, &Fp4_V3);        //c2=(a1^2 - a0*a2)/(a0^3 + a1^3 * Zeta - 3*a0*a1*a2*Zeta + a2^3*Zeta^2)
}

void SM9_Fp12_FrobMap(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A)
{
    // TODO: �����Ż����ٳ˷�
    SM9_Fp4_FrobMap(&Fp4_c0, &Fp4_a0);
    SM9_Fp4_FrobMap(&Fp4_c1, &Fp4_a1);
    SM9_Fp4_MulWq(&Fp4_c1, &Fp4_c1);
    SM9_Fp4_FrobMap(&Fp4_c2, &Fp4_a2);
    SM9_Fp4_MulW2q(&Fp4_c2, &Fp4_c2);
}

void SM9_Fp12_Mul_For_MillerLoop(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A, SM9_Fp12 *pFp12_B)
{
    SM9_Fp4 Fp4_V0;
    SM9_Fp4 Fp4_V1;
    SM9_Fp4 Fp4_V2;
    SM9_Fp4 Fp4_V3;
    SM9_Fp4 Fp4_V4;
    SM9_Fp4 Fp4_V5;

    SM9_Fp4_Mul(&Fp4_V0, &Fp4_a0, &Fp4_b0);                    //V0 = A0 * B0
    SM9_Fp4_Mul_Coef1(&Fp4_V1, &Fp4_a1, &Fp4_b2.Coef_0);    //V1 = A1 * C0 * v
    SM9_Fp4_Mul(&Fp4_V2, &Fp4_a1, &Fp4_b0);                    //V2 = A1 * B0
    SM9_Fp4_Mul_Coef1(&Fp4_V3, &Fp4_a2, &Fp4_b2.Coef_0);    //V3 = A2 * C0 * v
    SM9_Fp4_Mul(&Fp4_V4, &Fp4_a2, &Fp4_b0);                    //V4 = A2 * B0
    SM9_Fp4_Mul_Coef0(&Fp4_V5, &Fp4_a0, &Fp4_b2.Coef_0);    //V5 = A0 * C0

    SM9_Fp4_Add(&pFp12_R->Coef_0, &Fp4_V0, &Fp4_V1);        //c0=A0 * B0 + A1 * C0 * v
    SM9_Fp4_Add(&pFp12_R->Coef_1, &Fp4_V2, &Fp4_V3);        //c1=A1 * B0 + A2 * C0 * v
    SM9_Fp4_Add(&pFp12_R->Coef_2, &Fp4_V4, &Fp4_V5);        //c2=A1 * B0 + A2 * C0
}

void SM9_Fp12_Mul_For_FrobMap(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A, SM9_Fp12 *pFp12_B)
{
    SM9_Fp4 Fp4_V0;
    SM9_Fp4 Fp4_V1;
    SM9_Fp4 Fp4_V2;
    SM9_Fp4 Fp4_V3;
    SM9_Fp4 Fp4_V4;
    SM9_Fp4 Fp4_V5;

    SM9_Fp4_Mul_Coef1(&Fp4_V0, &Fp4_a0, &Fp4_b0.Coef_1);    //V0=A0*b01
    SM9_Fp4_Mul(&Fp4_V1, &Fp4_a2, &Fp4_b1);                    //V1=A2*B1
    SM9_Fp4_Mul_V(&Fp4_V1, &Fp4_V1);                    //V1=A2*B1*v
    SM9_Fp4_Mul_Coef1(&Fp4_V2, &Fp4_a1, &Fp4_b0.Coef_1);    //V2=A1*b01
    SM9_Fp4_Mul(&Fp4_V3, &Fp4_a0, &Fp4_b1);                    //V3=A0*B1
    SM9_Fp4_Mul_Coef1(&Fp4_V4, &Fp4_a2, &Fp4_b0.Coef_1);    //V4=A2*b01
    SM9_Fp4_Mul(&Fp4_V5, &Fp4_a1, &Fp4_b1);                    //V5=A1*B1
    SM9_Fp4_Add(&Fp4_c0, &Fp4_V0, &Fp4_V1);        //c0=A0*b01+A2*B1*v
    SM9_Fp4_Add(&Fp4_c1, &Fp4_V2, &Fp4_V3);        //c1=A1*b01+A0*B1
    SM9_Fp4_Add(&Fp4_c2, &Fp4_V4, &Fp4_V5);        //c2=A2*b01+A1*B1
}

void SM9_Fp12_GetConj(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_A)
{
    SM9_Fp4_GetConj(&Fp4_c0, &Fp4_a0);
    SM9_Fp4_GetConj(&Fp4_c1, &Fp4_a1);
    SM9_Fp4_Neg(&Fp4_c1, &Fp4_c1);
    SM9_Fp4_GetConj(&Fp4_c2, &Fp4_a2);
}

void SM9_Fp12_Res(SM9_Fp12 *pFp12_A)
{
    SM9_Fp4_Res(&Fp4_a0);
    SM9_Fp4_Res(&Fp4_a1);
    SM9_Fp4_Res(&Fp4_a2);
}

void SM9_Fp12_Exp(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_X, uint32_t *pBn_E)
{
    /***********************************/
    int bitlen, i;
    SM9_Fp12 Fp12_T0;
    /***********************************/

    bitlen = bn_get_bitlen(pBn_E, BNWordLen);
    if (bitlen == 0)
    {
        SM9_Fp12_SetOne(pFp12_R);
        return;
    }
    SM9_Fp12_Assign(pFp12_R, pFp12_X);
    if (bitlen == 1)
        return;
    SM9_Fp12_Assign(&Fp12_T0, pFp12_X);
    for (i = bitlen - 2; i >= 0; i--)
    {
        SM9_Fp12_Squ(pFp12_R, pFp12_R);
        if (BN_BIT(pBn_E, i))
            SM9_Fp12_Mul(pFp12_R, pFp12_R, &Fp12_T0);
    }
}

#undef Fp4_a0
#undef Fp4_a1
#undef Fp4_a2
#undef Fp4_b0
#undef Fp4_b1
#undef Fp4_b2
#undef Fp4_c0
#undef Fp4_c1
#undef Fp4_c2

#endif // HITLS_CRYPTO_SM9
