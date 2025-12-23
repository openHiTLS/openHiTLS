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

#include "sm9_ecp2.h"
#include "sm9_fp.h"

void SM9_Ecp2_A_ReadBytes(SM9_ECP2_A *dst, const uint8_t *src)
{
    SM9_Fp_ReadBytes(dst->X.Coef_1, src);
    SM9_Fp_ReadBytes(dst->X.Coef_0, src + BNByteLen);
    SM9_Fp_ReadBytes(dst->Y.Coef_1, src + 2 * BNByteLen);
    SM9_Fp_ReadBytes(dst->Y.Coef_0, src + 3 * BNByteLen);
}

void SM9_Ecp2_A_WriteBytes(uint8_t *dst, SM9_ECP2_A *src)
{
    SM9_Fp_WriteBytes(dst, src->X.Coef_1);
    SM9_Fp_WriteBytes(dst + BNByteLen, src->X.Coef_0);
    SM9_Fp_WriteBytes(dst + 2 * BNByteLen, src->Y.Coef_1);
    SM9_Fp_WriteBytes(dst + 3 * BNByteLen, src->Y.Coef_0);
}

void SM9_Ecp2_A_Reset(SM9_ECP2_A *pECP_A)
{
    memset(pECP_A, 0, sizeof(SM9_ECP2_A));
}

void SM9_Ecp2_J_Reset(SM9_ECP2_J *pEcp2_J)
{
    memset(pEcp2_J, 0, sizeof(SM9_ECP2_J));
}

void SM9_Ecp2_A_Assign(SM9_ECP2_A *pPointA, SM9_ECP2_A *pPointB)
{
    memcpy(pPointA, pPointB, sizeof(SM9_ECP2_A));
}

void SM9_Ecp2_J_Assign(SM9_ECP2_J *pPointA, SM9_ECP2_J *pPointB)
{
    memcpy(pPointA, pPointB, sizeof(SM9_ECP2_J));
}

void SM9_Ecp2_A_ToJ(SM9_ECP2_J *pJ_Point, SM9_ECP2_A *pA_Point)
{
    SM9_Fp2_Assign(&pJ_Point->X, &pA_Point->X);
    SM9_Fp2_Assign(&pJ_Point->Y, &pA_Point->Y);
    SM9_Fp2_SetOne(&pJ_Point->Z);
}

void SM9_Ecp2_J_ToA(SM9_ECP2_A *pAp, SM9_ECP2_J *pJp)
{
    /***************************/
    SM9_Fp2 Fp2_T0;
    SM9_Fp2 Fp2_T1;
    /***************************/

    if (SM9_Fp2_IsZero(&pJp->Z)) {
        SM9_Ecp2_A_Reset(pAp);
        return;
    }

    SM9_Fp2_Inv(&Fp2_T0, &pJp->Z);
    SM9_Fp2_Squ(&Fp2_T1, &Fp2_T0);
    SM9_Fp2_Mul(&Fp2_T0, &Fp2_T0, &Fp2_T1);
    SM9_Fp2_Mul(&pAp->Y, &pJp->Y, &Fp2_T0); // Y1 = Y * Z^-3
    SM9_Fp2_Mul(&pAp->X, &pJp->X, &Fp2_T1); // X1 = X * Z ^ -2
}

void SM9_Ecp2_J_AddA(SM9_ECP2_J *pJs, SM9_ECP2_J *pJp, SM9_ECP2_A *pAp)
{
    // Cost : 8M+3S+7A
    /************************/
    SM9_Fp2 Fp2_T1;
    SM9_Fp2 Fp2_T2;
    SM9_Fp2 Fp2_T3;
    /************************/

    SM9_Fp2_Squ(&Fp2_T3, &pJp->Z);            // T3 = Z1^2
    SM9_Fp2_Mul(&Fp2_T2, &Fp2_T3, &pJp->Z);    // T2 = Z1^3
    SM9_Fp2_Mul(&Fp2_T3, &Fp2_T3, &pAp->X);    // T3 = X2 * Z1^2 = A
    SM9_Fp2_Sub(&Fp2_T3, &Fp2_T3, &pJp->X);    // T3 = A - X1 = C
    SM9_Fp2_Mul(&pJs->Z, &pJp->Z, &Fp2_T3);    // Z3 = Z1 * C
    SM9_Fp2_Mul(&Fp2_T2, &Fp2_T2, &pAp->Y);    // T2 = Y2 * Z1 ^ 3 = B
    SM9_Fp2_Sub(&Fp2_T2, &Fp2_T2, &pJp->Y);    // T2 = B - Y1 = D

    SM9_Fp2_Squ(&Fp2_T1, &Fp2_T3);            // T1 = C ^ 2
    SM9_Fp2_Mul(&Fp2_T3, &Fp2_T3, &Fp2_T1);    // T3 = C ^ 3
    SM9_Fp2_Mul(&Fp2_T1, &Fp2_T1, &pJp->X);    // T1 = X1 * C^2
    SM9_Fp2_Add(&pJs->X, &Fp2_T1, &Fp2_T1);    // X3 = 2 * X1 * C^2
    SM9_Fp2_Add(&pJs->X, &pJs->X, &Fp2_T3);    // X3 = C ^ 3 + 2 X1 * C^2
    SM9_Fp2_Mul(&pJs->Y, &pJp->Y, &Fp2_T3);    // Y3 = Y1 * C^3

    SM9_Fp2_Squ(&Fp2_T3, &Fp2_T2);            // T3 =  D^2
    SM9_Fp2_Sub(&pJs->X, &Fp2_T3, &pJs->X);    // X3 = D ^ 2 - ( C ^ 3 + 2 X1 * C^2)
    SM9_Fp2_Sub(&Fp2_T1, &Fp2_T1, &pJs->X);    // T1 = X1 * C ^ 2 - X3
    SM9_Fp2_Mul(&Fp2_T1, &Fp2_T1, &Fp2_T2);    // T1 = D * (X1 * C ^ 2 - X3)
    SM9_Fp2_Sub(&pJs->Y, &Fp2_T1, &pJs->Y);    // Y3 = D * (X1 * C ^ 2 - X3) - Y1 * C ^ 3
}

void SM9_Ecp2_J_DoubleJ(SM9_ECP2_J *pJr, SM9_ECP2_J *pJp)
{
    // Cost : 3M+4S+10A (a=0) or 3M+6S+1a+11A (otherwise)    [Change by pengcong 2017-09-27]
    /************************/
    SM9_Fp2 Fp2_T1;
    SM9_Fp2 Fp2_T2;
    SM9_Fp2 Fp2_T3;
    /************************/

    // A = 4 * X1 * Y1 ^ 2;    B = 8 * Y1 ^ 4;    Cost: 1M+2S+3A
    SM9_Fp2_Squ(&Fp2_T1, &pJp->Y);                // T1 = Y1 ^ 2
    SM9_Fp2_Add(&Fp2_T1, &Fp2_T1, &Fp2_T1);        // T1 = 2 * Y1 ^ 2
    SM9_Fp2_Squ(&Fp2_T2, &Fp2_T1);                // T2 = 4 * Y1 ^ 4
    SM9_Fp2_Add(&Fp2_T2, &Fp2_T2, &Fp2_T2);        // T2 = 8 * Y1 ^ 4 = B
    SM9_Fp2_Mul(&Fp2_T1, &Fp2_T1, &pJp->X);        // T1 = 2 * X1 * Y1 ^ 2
    SM9_Fp2_Add(&Fp2_T1, &Fp2_T1, &Fp2_T1);        // T1 = 4 X1 * Y1 ^ 2 = A

    // C = 3 * X1 ^ 2 + a * Z1 ^ 4;    Cost: 1S+2A (a = 0)
    SM9_Fp2_Squ(&Fp2_T3, &pJp->X);                // T3 = X1 ^ 2
    SM9_Fp2_Add(&pJr->X, &Fp2_T3, &Fp2_T3);        // X3 = 2 * X1 ^ 2
    SM9_Fp2_Add(&Fp2_T3, &Fp2_T3, &pJr->X);        // T3 = 3 * X1 ^ 2 = C

    // Cost: 2M+1S+5A
    SM9_Fp2_Mul(&pJr->Z, &pJp->Y, &pJp->Z);        // Z3 = Y1 * Z1
    SM9_Fp2_Add(&pJr->Z, &pJr->Z, &pJr->Z);        // Z3 = 2 * Y1 * Z1
    SM9_Fp2_Squ(&pJr->X, &Fp2_T3);                // X3 = C ^ 2
    SM9_Fp2_Sub(&pJr->X, &pJr->X, &Fp2_T1);        // X3 = C ^ 2 - A
    SM9_Fp2_Sub(&pJr->X, &pJr->X, &Fp2_T1);        // X3 = C ^ 2 - 2A
    SM9_Fp2_Sub(&pJr->Y, &Fp2_T1, &pJr->X);        // T1 = A - X3
    SM9_Fp2_Mul(&pJr->Y, &pJr->Y, &Fp2_T3);        // T1 = C * (A - X3)
    SM9_Fp2_Sub(&pJr->Y, &pJr->Y, &Fp2_T2);        // Y3 = C * (A - X3) - B
}

void SM9_Ecp2_KP(SM9_ECP2_A *pKP, SM9_ECP2_A *pAp, uint32_t *pwK)
{
    /***********************************/
    int32_t bitlen;
    int32_t i;
    SM9_ECP2_J Jt;
    /***********************************/

    bitlen = bn_get_bitlen(pwK, sm9_sys_para.wsize);
    if (bitlen == 0) {
        SM9_Ecp2_A_Reset(pKP);
        return;
    }
    if (bitlen == 1) {
        SM9_Ecp2_A_Assign(pKP, pAp);
        return;
    }

    SM9_Ecp2_A_ToJ(&Jt, pAp);
    for (i = bitlen - 2; i >= 0; i--) {
        SM9_Ecp2_J_DoubleJ(&Jt, &Jt);
        if (BN_BIT(pwK, i))
            SM9_Ecp2_J_AddA(&Jt, &Jt, pAp);
    }
    SM9_Ecp2_J_ToA(pKP, &Jt);

    return;
}

#endif // HITLS_CRYPTO_SM9

