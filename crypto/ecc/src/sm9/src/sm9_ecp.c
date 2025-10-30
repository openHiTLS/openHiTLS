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

#include "sm9_ecp.h"
#include "sm9_fp.h"

void SM9_Fp_ECP_A_Print(SM9_ECP_A *pECP_A, SM9_Sys_Para *pSysPara)
{
    // int32_t wsize = sm9_sys_para.wsize;
    (void)pSysPara;

    BN_Print(pECP_A->X, sm9_sys_para.wsize);
    BN_Print(pECP_A->Y, sm9_sys_para.wsize);
}

void SM9_Fp_ECP_J_Print(SM9_ECP_J *pECP_A, SM9_Sys_Para *pSysPara)
{
    // int32_t wsize = sm9_sys_para.wsize;
    (void)pSysPara;

    BN_Print(pECP_A->X, sm9_sys_para.wsize);
    BN_Print(pECP_A->Y, sm9_sys_para.wsize);
    BN_Print(pECP_A->Z, sm9_sys_para.wsize);
}

void SM9_Ecp_A_Reset(SM9_ECP_A *pECP_A)
{
    memset(pECP_A, 0, sizeof(SM9_ECP_A));
}

void SM9_Ecp_J_Reset(SM9_ECP_J *pECP_J)
{
    memset(pECP_J, 0, sizeof(SM9_ECP_J));
}

int32_t SM9_Fp_ECP_A_JE(SM9_ECP_A *pPointA, SM9_ECP_A *pPointB, SM9_Sys_Para *pSysPara)
{
    if (bn_equal(pPointA->X, pPointB->X, pSysPara->wsize) != 1)
    {
        return 0;
    }

    if (bn_equal(pPointA->Y, pPointB->Y, pSysPara->wsize) != 1)
    {
        return 0;
    }

    return 1;
}

void SM9_Ecp_A_Assign(SM9_ECP_A *pPointA, SM9_ECP_A *pPointB)
{
    memcpy(pPointA, pPointB, sizeof(SM9_ECP_A));
}

void SM9_Ecp_J_Assign(SM9_ECP_J *pPointA, SM9_ECP_J *pPointB)
{
    memcpy(pPointA, pPointB, sizeof(SM9_ECP_J));
}

void SM9_Ecp_A_ToJ(SM9_ECP_J *pJ_Point, SM9_ECP_A *pA_Point)
{
    SM9_Fp_Assign(pJ_Point->X, pA_Point->X);
    SM9_Fp_Assign(pJ_Point->Y, pA_Point->Y);
    SM9_Fp_SetOne(pJ_Point->Z);
}

void SM9_Ecp_J_ToA(SM9_ECP_A *pAp, SM9_ECP_J *pJp)
{
    /***************************/
    uint32_t Fp_T0[BNWordLen];
    uint32_t Fp_T1[BNWordLen];
    /***************************/

    if (SM9_Bn_IsZero(pJp->Z))
    {
        SM9_Ecp_A_Reset(pAp);
        return;
    }

    SM9_Fp_Inv(Fp_T0, pJp->Z);            //T0 = Z^-1
    SM9_Fp_Squ(Fp_T1, Fp_T0);            //T1 = Z^-2
    SM9_Fp_Mul(Fp_T0, Fp_T1, Fp_T0);    //T0 = Z^-3
    SM9_Fp_Mul(pAp->X, pJp->X, Fp_T1);    //X2 = X1 * Z^-3
    SM9_Fp_Mul(pAp->Y, pJp->Y, Fp_T0);    //Y2 = Y1 * Z^-3
}

void SM9_Ecp_J_AddA(SM9_ECP_J *pJ_Sum, SM9_ECP_J *pJp, SM9_ECP_A *pAp)
{
#define FP_x1    (pJp->X)
#define FP_y1    (pJp->Y)
#define FP_z1    (pJp->Z)
#define FP_x2    (pAp->X)
#define FP_y2    (pAp->Y)
#define FP_x3    (pJ_Sum->X)
#define FP_y3    (pJ_Sum->Y)
#define FP_z3    (pJ_Sum->Z)
    /************************/
    uint32_t Fp_T1[BNWordLen];
    uint32_t Fp_T2[BNWordLen];
    uint32_t Fp_T3[BNWordLen];
    /************************/

    SM9_Fp_Mul(Fp_T3, FP_z1, FP_z1);    //T3 = Z1^2
    SM9_Fp_Mul(Fp_T2, Fp_T3, FP_z1);    //T2 = T3 * Z1 = Z1^3
    SM9_Fp_Mul(Fp_T3, Fp_T3, FP_x2);    //T3 = T3 * X2 = X2 * Z1^2 = A
    SM9_Fp_Sub(Fp_T3, Fp_T3, FP_x1);    //T3 = T3 - X1 = C
    SM9_Fp_Mul(FP_z3, FP_z1, Fp_T3);    //Z3 = Z1 * T3 = Z1 * C
    SM9_Fp_Mul(Fp_T2, Fp_T2, FP_y2);    //T2 = Y2 * T2 = Y2 * Z1^3 = B
    SM9_Fp_Sub(Fp_T2, Fp_T2, FP_y1);    //T2 = T2 - Y1 = B - Y1 = D
    SM9_Fp_Mul(Fp_T1, Fp_T3, Fp_T3);    //T1 = T3^2 = C^2
    SM9_Fp_Mul(Fp_T3, Fp_T3, Fp_T1);    //T3 = T3 * T1 = C^3
    SM9_Fp_Mul(Fp_T1, Fp_T1, FP_x1);    //T1 = T1 * X1 = X1 * C^2
    SM9_Fp_Add(FP_x3, Fp_T1, Fp_T1);    //X3 = T1 + T1 = 2 * X1 * C^2
    SM9_Fp_Add(FP_x3, FP_x3, Fp_T3);    //X3 = X3 + T3 = C^3 + 2*X1 * C^2
    SM9_Fp_Mul(FP_y3, FP_y1, Fp_T3);    //Y3 = Y1 * T3 = Y1 * C^3
    SM9_Fp_Mul(Fp_T3, Fp_T2, Fp_T2);    //T3 = T2^2 = D^2
    SM9_Fp_Sub(FP_x3, Fp_T3, FP_x3);    //X3 = T3 - X3 = D ^ 2 - ( C ^ 3 + 2 X1 * C^2)
    SM9_Fp_Sub(Fp_T1, Fp_T1, FP_x3);    //T1 = T1 - X3 = X1 * C^2 - X3
    SM9_Fp_Mul(Fp_T1, Fp_T1, Fp_T2);    //T1 = T1 * T2 = D * (X1 * C ^ 2 - X3)
    SM9_Fp_Sub(FP_y3, Fp_T1, FP_y3);    //Y3 = T1 - Y3 = D * (X1 * C ^ 2 - X3) - Y1 * C ^ 3

#undef FP_x1
#undef FP_y1
#undef FP_z1
#undef FP_x2
#undef FP_y2
#undef FP_x3
#undef FP_y3
#undef FP_z3
}

void SM9_Ecp_J_DoubleJ(SM9_ECP_J *pJp_Result, SM9_ECP_J *pJp)
{//Cost : 3M+4S+10A (a=0) or 3M+6S+1a+11A (otherwise)    [Change by pengcong 2017-09-27]
#define FP_x1    (pJp->X)
#define FP_y1    (pJp->Y)
#define FP_z1    (pJp->Z)
#define FP_x3    (pJp_Result->X)
#define FP_y3    (pJp_Result->Y)
#define FP_z3    (pJp_Result->Z)
    /************************/
    uint32_t FP_T1[BNWordLen];
    uint32_t FP_T2[BNWordLen];
    uint32_t FP_T3[BNWordLen];
    /************************/

    SM9_Fp_Mul(FP_T1, FP_y1, FP_y1);    //T1 = Y1 ^ 2
    SM9_Fp_Add(FP_T1, FP_T1, FP_T1);    //T1 = T1 + T1 = 2 * Y1 ^ 2
    SM9_Fp_Mul(FP_T2, FP_T1, FP_T1);    //T2 = T1 * T1 = 4 * Y1 ^ 4
    SM9_Fp_Add(FP_T2, FP_T2, FP_T2);    //T2 = T2 + T2 = 8 * Y1 ^ 4 = B
    SM9_Fp_Mul(FP_T1, FP_T1, FP_x1);    //T1 = T1 * X1 = 2 * X1 * Y1 ^ 2
    SM9_Fp_Add(FP_T1, FP_T1, FP_T1);    //T1 = T1 + T1 = 4 X1 * Y1 ^ 2 = A
    SM9_Fp_Mul(FP_T3, FP_x1, FP_x1);    //T3 = X1 ^ 2
    SM9_Fp_Add(FP_x3, FP_T3, FP_T3);    //X3 = T3 + T3 = 2 * X1^2
    SM9_Fp_Add(FP_T3, FP_T3, FP_x3);    //T3 = T3 + X3 = 3 * X1^2 = C
    SM9_Fp_Mul(FP_z3, FP_y1, FP_z1);    //Z3 = Y1 * Z1
    SM9_Fp_Add(FP_z3, FP_z3, FP_z3);    //Z3 = Z3 + Z3 = 2 * Y1 * Z1
    SM9_Fp_Mul(FP_x3, FP_T3, FP_T3);    //X3 = T3 ^ 2 = C ^ 2
    SM9_Fp_Sub(FP_x3, FP_x3, FP_T1);    //X3 = X3 - T1 = C ^ 2 - A
    SM9_Fp_Sub(FP_x3, FP_x3, FP_T1);    //X3 = X3 - T1 = C ^ 2 - 2 * A
    SM9_Fp_Sub(FP_y3, FP_T1, FP_x3);    //Y3 = T1 - X3 = A - X3
    SM9_Fp_Mul(FP_y3, FP_y3, FP_T3);    //Y3 = Y3 * T3 = C * (A - X3)
    SM9_Fp_Sub(FP_y3, FP_y3, FP_T2);    //Y3 = Y3 - T2 = C * (A - X3) - B

#undef FP_x1
#undef FP_y1
#undef FP_z1
#undef FP_x3
#undef FP_y3
#undef FP_z3
}

void SM9_Ecp_KP(SM9_ECP_A *pKP, SM9_ECP_A *pAp, uint32_t *pwK)
{
    /***********************************/
    int bitlen, i;
    SM9_ECP_J Ecp_T0;
    /***********************************/

    bitlen = bn_get_bitlen(pwK, sm9_sys_para.wsize);
    if (bitlen == 0)
    {
        SM9_Ecp_A_Reset(pKP);
        return;
    }
    if (bitlen == 1)
    {
        SM9_Ecp_A_Assign(pKP, pAp);
        return;
    }

    SM9_Ecp_A_ToJ(&Ecp_T0, pAp);
    for (i = bitlen - 2; i >= 0; i--)
    {
        SM9_Ecp_J_DoubleJ(&Ecp_T0, &Ecp_T0);
        if (pwK[i / WordLen] & (1 << (i % WordLen)))
            SM9_Ecp_J_AddA(&Ecp_T0, &Ecp_T0, pAp);
    }
    SM9_Ecp_J_ToA(pKP, &Ecp_T0);
    return;
}

void SM9_Fp_ECP_KPAddAToA(SM9_ECP_A *pKP, SM9_ECP_A *pAp, uint32_t *pwK, SM9_ECP_A *pBp, SM9_Sys_Para *pSysPara)
{
    /***********************************/
    int32_t bitlen = 0;
    int32_t i = 0;
    SM9_ECP_J Jp_tmp;
    /***********************************/
    (void)pSysPara;

    bitlen = bn_get_bitlen(pwK, sm9_sys_para.wsize);
    if (bitlen == 0)
    {
        SM9_Ecp_A_Reset(pKP);
        // return;
    }
    else
    {
        // SM9_Ecp_J_Reset(&Jp_tmp, pSysPara);
        SM9_Ecp_A_ToJ(&Jp_tmp, pAp);
        for (i = bitlen - 2; i >= 0; i--)
        {
            SM9_Ecp_J_DoubleJ(&Jp_tmp, &Jp_tmp);

            if (BN_BIT(pwK, i))
                SM9_Ecp_J_AddA(&Jp_tmp, &Jp_tmp, pAp);
        }
        // SM9_Ecp_J_ToA(pKP, &Jp_tmp, pSysPara);
        // return;
    }
    SM9_Ecp_J_AddA(&Jp_tmp, &Jp_tmp, pBp);
    SM9_Ecp_J_ToA(pKP, &Jp_tmp);
}

void SM9_Ecp_A_ReadBytes(SM9_ECP_A *dst, const unsigned char *src)
{
    ByteToBN(src, BNByteLen, dst->X, BNWordLen);
    ByteToBN(src + BNByteLen, BNByteLen, dst->Y, BNWordLen);
    bn_mont_mul(dst->X, dst->X, sm9_sys_para.Q_R2, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
    bn_mont_mul(dst->Y, dst->Y, sm9_sys_para.Q_R2, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
}

int SM9_Fp_ECP_A_ReadBytesWithPC(SM9_ECP_A *dst, unsigned char PC, const unsigned char *src)
{
    switch (PC)
    {
    case 0x00:
        ByteToBN(src, BNByteLen, dst->X, BNWordLen);
        ByteToBN(src + BNByteLen, BNByteLen, dst->Y, BNWordLen);
        bn_mont_mul(dst->X, dst->X, sm9_sys_para.Q_R2, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
        bn_mont_mul(dst->Y, dst->Y, sm9_sys_para.Q_R2, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
        return 0;
    case 0x02:
    case 0x03:
        ByteToBN(src + 1, BNByteLen, dst->X, BNWordLen);
        bn_mont_mul(dst->X, dst->X, sm9_sys_para.Q_R2, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
        bn_mont_squ(dst->Y, dst->X, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);//tmp = x^2
        bn_mod_add(dst->Y, dst->Y, sm9_sys_para.EC_Fp_A_Mont, sm9_sys_para.EC_Q, sm9_sys_para.wsize);//tmp = x^2 + a
        bn_mont_mul(dst->Y, dst->Y, dst->X, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);//tmp = x^3 + a*x
        bn_mod_add(dst->Y, dst->Y, sm9_sys_para.EC_Fp_B_Mont, sm9_sys_para.EC_Q, sm9_sys_para.wsize);//tmp = x^3 + a*x + b
        bn_mont_sqrt(dst->Y, dst->Y, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);//tmp = (x^3 + a*x + b) ^ 1/2
        bn_mont_mul(dst->Y, dst->Y, sm9_sys_para.EC_One, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
        bn_get_res(dst->Y, sm9_sys_para.EC_Q, sm9_sys_para.wsize);
        if (((src[0] == 0x02) && ((dst->Y[0] & 1) == 1)) || ((src[0] == 0x03) && ((dst->Y[0] & 1) == 0)))
        {
            bn_mod_sub(dst->Y, sm9_sys_para.EC_Q, dst->Y, sm9_sys_para.EC_Q, sm9_sys_para.wsize);
        }
        bn_mont_mul(dst->Y, dst->Y, sm9_sys_para.Q_R2, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
        return 0;
    case 0x04:
    case 0x06:
    case 0x07:
        ByteToBN(src + 1, BNByteLen, dst->X, BNWordLen);
        ByteToBN(src + BNByteLen + 1, BNByteLen, dst->Y, BNWordLen);
        bn_mont_mul(dst->X, dst->X, sm9_sys_para.Q_R2, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
        bn_mont_mul(dst->Y, dst->Y, sm9_sys_para.Q_R2, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
        if (PC & 0x02)
        {
            if ((src[0] ^ src[2 * BNByteLen]) & 1)    return -1;
        }
        else
        {
            if (PC != 0x04)    return -1;
        }
        return 0;
    default:
        return -1;
    }
}

void SM9_Ecp_A_WriteBytes(unsigned char *dst, SM9_ECP_A *src)
{
    SM9_Fp_WriteBytes(dst, src->X);
    SM9_Fp_WriteBytes(dst + BNByteLen, src->Y);
}

int SM9_Fp_ECP_A_WriteBytesWithPC(unsigned char *dst, unsigned char PC, SM9_ECP_A *src)
{
    SM9_ECP_A buf;
    int32_t    bytelen;

    bn_mont_redc(buf.X, src->X, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
    bn_mont_redc(buf.Y, src->Y, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
    bn_get_res(buf.X, sm9_sys_para.EC_Q, sm9_sys_para.wsize);
    bn_get_res(buf.Y, sm9_sys_para.EC_Q, sm9_sys_para.wsize);

    if (PC == 0x00)
    {
        BNToByte(buf.X, BNWordLen, dst, &bytelen);
        BNToByte(buf.Y, BNWordLen, dst + BNByteLen, &bytelen);
        return (2 * BNByteLen);
    }
    else if (PC == 0x04)
    {
        dst[0] = 0x04;
        BNToByte(buf.X, BNWordLen, dst + 1, &bytelen);
        BNToByte(buf.Y, BNWordLen, dst + BNByteLen + 1, &bytelen);
        return (2 * BNByteLen + 1);
    }
    else if ((PC == 0x06) || (PC == 0x07))
    {
        dst[0] = 0x06;
        BNToByte(buf.X, BNWordLen, dst + 1, &bytelen);
        BNToByte(buf.Y, BNWordLen, dst + BNByteLen + 1, &bytelen);
        if (buf.Y[0] & 0x01)    dst[0] |= 0x01;
        return (2 * BNByteLen + 1);
    }
    else if ((PC == 0x02) || (PC == 0x03))
    {
        dst[0] = 0x02;
        BNToByte(buf.X, BNWordLen, dst + 1, &bytelen);
        if (buf.Y[0] & 0x01)    dst[0] |= 0x01;
        return (BNByteLen + 1);
    }
    else
        return -1;
}

int  SM9_Ecp_A_Check(SM9_ECP_A *pAp)
{
    /************************/
    uint32_t bn_tmp1[BNWordLen];
    uint32_t bn_tmp2[BNWordLen];
    /************************/

    SM9_Fp_Squ(bn_tmp1, pAp->Y);
    SM9_Fp_LastRes(bn_tmp1);

    SM9_Fp_Squ(bn_tmp2, pAp->X);
    SM9_Fp_Mul(bn_tmp2, bn_tmp2, pAp->X);
    SM9_Fp_Add(bn_tmp2, bn_tmp2, sm9_sys_para.EC_Fp_B_Mont);
    SM9_Fp_LastRes(bn_tmp2);

    if (bn_equal(bn_tmp1, bn_tmp2, sm9_sys_para.wsize))
        return 0;
    else
        return -1;
}

#endif // HITLS_CRYPTO_SM9
