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

#include "sm9_pairing.h"

void SM9_Pairing_MulQuaRoot(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    uint32_t Fp_T0[BNWordLen];

    SM9_Fp_MulRoot(Fp_T0, pFp2_A->Coef_1); // a1*pCoe
    SM9_Fp_Add(Fp_T0, Fp_T0, Fp_T0); // 2*a1*pCoe
    SM9_Fp_MulRoot(pFp2_R->Coef_1, pFp2_A->Coef_0); // a0*pCoe
    SM9_Fp_Neg(pFp2_R->Coef_0, Fp_T0); // -2*a1*pCoe
}

void SM9_Pairing_MulCubRoot(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    uint32_t Fp_T0[BNWordLen];

    SM9_Fp_MulRoot(Fp_T0, pFp2_A->Coef_1); // a1*pCoe
    SM9_Fp_Add(Fp_T0, Fp_T0, Fp_T0); // 2*a1*pCoe
    SM9_Fp_MulRoot(pFp2_R->Coef_1, pFp2_A->Coef_0); // a0*pCoe
    SM9_Fp_Neg(pFp2_R->Coef_0, Fp_T0); // -2*a1*pCoe
}

void SM9_Pairing_MulQuaRoot_FrobMap(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_A)
{
    SM9_Fp2_FrobMap(pFp2_R, pFp2_A); // Frob(a0+a1*u)
    SM9_Fp2_Mul_Vq(pFp2_R, pFp2_R); // (Frob(a0+a1*u))* (v^q)
}

void SM9_Pairing_MulCubRoot_FrobMap(SM9_Fp2 *pFp2_R, SM9_Fp2 *pFp2_E)
{
    SM9_Fp2_FrobMap(pFp2_R, pFp2_E); // Frob(a0+a1*u)
    SM9_Fp2_Mul_Vq(pFp2_R, pFp2_R); // (Frob(a0+a1*u))* (v^q)
    SM9_Fp2_Mul_Wq(pFp2_R, pFp2_R); // (Frob(a0+a1*u))* (v^q) * (w^q)
}

void SM9_Pairing_EncDL(SM9_Fp12 *pLineEva, SM9_ECP2_J *pJSum, SM9_ECP2_J *pJT, SM9_ECP_A *pAP)
{
#define FP2_x1        (pJT->X)
#define FP2_y1        (pJT->Y)
#define FP2_z1        (pJT->Z)
#define FP_4INV        (sm9_sys_para.EC_4_Inv_Mont)
#define FP2_x3        (JSum_T.X)
#define FP2_y3        (JSum_T.Y)
#define FP2_z3        (JSum_T.Z)
    SM9_ECP2_J JSum_T;

    SM9_Fp2 FP2_T1;
    SM9_Fp2 FP2_T2;
    SM9_Fp2 FP2_T3;
    SM9_Fp2 FP2_T4;
    SM9_Fp2 FP2_T5;
    SM9_Fp2 FP2_T6;
    SM9_Fp2 FP2_T7;

    SM9_Fp2_Squ(&FP2_T1, &FP2_x1);                // T1 = X1 ^ 2 = A
    SM9_Fp2_Add(&FP2_T2, &FP2_T1, &FP2_T1);        // T2 = 2 * (X1 ^ 2)
    SM9_Fp2_Add(&FP2_T1, &FP2_T1, &FP2_T2);        // T2 = 3 * (X1 ^ 2)
    SM9_Fp2_Mul(&FP2_T2, &FP2_T1, &FP2_x1);        // T2 = 3 * (X1 ^ 3) = E
    SM9_Fp2_Mul_Coef0(&FP2_T3, &FP2_T2, FP_4INV);    // T3 = (3 * (X1 ^ 3)) / 4
    SM9_Fp2_Add(&FP2_T4, &FP2_T3, &FP2_T3);        // T4 = (6 * (X1 ^ 3)) / 4 = B0
    SM9_Fp2_Add(&FP2_T3, &FP2_T3, &FP2_T4);        // T3 = (9 * (X1 ^ 3)) / 4 = B
    SM9_Fp2_Squ(&FP2_T5, &FP2_y1);                // T5 = Y1^2 = C
    SM9_Fp2_Add(&FP2_T6, &FP2_T5, &FP2_T5);        // T6 = 2*Y1^2 = D;
    SM9_Fp2_Squ(&FP2_T5, &FP2_T5);                // T5 = C ^ 2 = F
    SM9_Fp2_Squ(&FP2_T7, &FP2_z1);                // T7 = Z ^ 2 = G

    // Z3 = Y*Z
    SM9_Fp2_Mul(&FP2_z3, &FP2_y1, &FP2_z1);

    // Y3 = B*(D - B0) - F
    SM9_Fp2_Sub(&FP2_T4, &FP2_T6, &FP2_T4);        // T4 = D - B0
    SM9_Fp2_Mul(&FP2_T4, &FP2_T4, &FP2_T3);        // T4 = B*(D - B0)
    SM9_Fp2_Sub(&FP2_y3, &FP2_T4, &FP2_T5);    // Y3 = B*(D - B0) - F

    // X3 = X1*(B-D)
    SM9_Fp2_Sub(&FP2_T4, &FP2_T3, &FP2_T6);        // T4 = B-D
    SM9_Fp2_Mul(&FP2_x3, &FP2_T4, &FP2_x1);    // X3 = X1*(B-D)

    SM9_Fp2_Mul(&FP2_T4, &FP2_z3, &FP2_T7);    // T4 = Z3 * G
    SM9_Fp2_Add(&FP2_T4, &FP2_T4, &FP2_T4);        // T4 = 2 * Z3 * G = H
    SM9_Fp2_Mul(&FP2_T5, &FP2_T1, &FP2_T7);        // T5 = A*G
    SM9_Fp2_Neg(&FP2_T5, &FP2_T5);                // T5 = -A*G

    // l_{2TP}=H * yP * (w ^3) + I * (w ^ 2) + J
    // = (J+H * yP * v) + (I + 0 * v) * w^2, where w^3 = v
    // LineEva_T = f0  + f1 * w + f2 * w ^ 2, f0, f1, f4 \in F(p^4)
    // f0 = f0_0 + f0_1 * v, f1 = f1_0 + f1_1 * v, f2 = f2_0 + f2_1 * v, f0_0, f0_1 \in F(p^2)
    SM9_Fp12_Reset(pLineEva);
    SM9_Fp2_Sub(&(pLineEva->Coef_0.Coef_0), &FP2_T2, &FP2_T6); // J = E -D
    SM9_Fp2_Mul_Coef0(&(pLineEva->Coef_0.Coef_1), &FP2_T4, pAP->Y); // H * yP
    SM9_Fp2_Mul_Coef0(&(pLineEva->Coef_2.Coef_0), &FP2_T5, pAP->X); // I = - A*G*xP

    SM9_Ecp2_J_Assign(pJSum, &JSum_T);

#undef FP2_x1
#undef FP2_y1
#undef FP2_z1
#undef FP_4INV
#undef FP2_x3
#undef FP2_y3
#undef FP2_z3
}

void SM9_Pairing_EncAL(SM9_Fp12 *pLineEva, SM9_ECP2_J *pJSum, SM9_ECP2_J *pJT, SM9_ECP2_A *pAQ, SM9_ECP_A *pAP)
{
#define FP2_x1        (pJT->X)
#define FP2_y1        (pJT->Y)
#define FP2_z1        (pJT->Z)
#define FP2_x2        (pAQ->X)
#define FP2_y2        (pAQ->Y)
#define FP2_x3        (JSum_T.X)
#define FP2_y3        (JSum_T.Y)
#define FP2_z3        (JSum_T.Z)

    SM9_Fp2 Fp2_T1;
    SM9_Fp2 Fp2_T2;
    SM9_Fp2 Fp2_T3;
    SM9_Fp2 Fp2_T4;

    SM9_ECP2_J JSum_T;

    SM9_Fp2_Squ(&Fp2_T1, &FP2_z1);                // T1 = Z1 ^ 2 = A
    SM9_Fp2_Mul(&Fp2_T2, &Fp2_T1, &FP2_z1);        // T2 = Z1 ^ 3 = B
    SM9_Fp2_Mul(&Fp2_T3, &FP2_y2, &Fp2_T2);        // T3 = Y2 * B
    SM9_Fp2_Sub(&Fp2_T3, &Fp2_T3, &FP2_y1);        // T3 = Y2 * B - Y1 = theta
    SM9_Fp2_Mul(&Fp2_T4, &FP2_x2, &Fp2_T1);        // T4 = X2 * A
    SM9_Fp2_Sub(&Fp2_T4, &Fp2_T4, &FP2_x1);        // T4 = X2 * A - X1 = lambda

    // Z3 = Z * lambda
    SM9_Fp2_Mul(&FP2_z3, &FP2_z1, &Fp2_T4);        // Z3 = Z * lambda

    SM9_Fp2_Squ(&Fp2_T1, &Fp2_T3);                // T1 = theta ^ 2 = C
    SM9_Fp2_Squ(&Fp2_T2, &Fp2_T4);                // T2 = lambda ^ 2 = D
    SM9_Fp2_Mul(&Fp2_T4, &Fp2_T2, &Fp2_T4);        // T4 = lambda ^ 3 = E
    SM9_Fp2_Sub(&Fp2_T1, &Fp2_T1, &Fp2_T4);        // T1 = C - E = F
    SM9_Fp2_Mul(&Fp2_T2, &Fp2_T2, &FP2_x1);        // T2 = X1 * D = G

    // X3 = F - 2 * G
    SM9_Fp2_Sub(&Fp2_T1, &Fp2_T1, &Fp2_T2);        // T1 = F - G
    SM9_Fp2_Sub(&FP2_x3, &Fp2_T1, &Fp2_T2);        // X3 = F - 2 * G

    // Y3 = theta * (G-X3) - Y1 * E
    SM9_Fp2_Sub(&Fp2_T2, &Fp2_T2, &FP2_x3);        // T2 = G-X3
    SM9_Fp2_Mul(&Fp2_T2, &Fp2_T2, &Fp2_T3);        // T2 = theta * (G-X3)
    SM9_Fp2_Mul(&Fp2_T4, &FP2_y1, &Fp2_T4);        // T4 = Y * E
    SM9_Fp2_Sub(&FP2_y3, &Fp2_T2, &Fp2_T4);        // Y3 = theta * (G-X3) - Y * E

    // M-type twist
    // l_{TQP}= Z3 * yP * w ^ 3 - theta * xp * w ^ 2 + J
    // = Z3 * yP * v - theta * xp * w ^ 2 + J
    // = (J+Z3 * yP * v) + (- theta * xp + 0 * v) * w ^ 2
    // J = theta*X2 - Y2 * Z3
    SM9_Fp12_Reset(pLineEva);
    SM9_Fp2_Mul(&Fp2_T1, &Fp2_T3, &FP2_x2);        // T1 = theta*X2
    SM9_Fp2_Mul(&Fp2_T2, &FP2_y2, &FP2_z3);        // T2 = Y2 * Z3
    SM9_Fp2_Sub(&(pLineEva->Coef_0.Coef_0), &Fp2_T1, &Fp2_T2);        // T1 = theta*X2 - Y2 * Z3

    SM9_Fp2_Mul_Coef0(&(pLineEva->Coef_0.Coef_1), &FP2_z3, pAP->Y); // Z3 * yP

    SM9_Fp2_Mul_Coef0(&Fp2_T3, &Fp2_T3, pAP->X); // theta * xp
    SM9_Fp2_Neg(&(pLineEva->Coef_2.Coef_0), &Fp2_T3); // -theta * xp

    SM9_Ecp2_J_Assign(pJSum, &JSum_T);

#undef FP2_x1
#undef FP2_y1
#undef FP2_z1
#undef FP2_x2
#undef FP2_y2
#undef FP2_x3
#undef FP2_y3
#undef FP2_z3
}

// pAQ=(xQ1,yQ1)=((cubic_root*xQ)^q, (quadratic_root*yQ)^q)=((a0+a1*u)*v*w, (b0+b1*u)*v)
// pJT=(cubic_root*X, quadratic_root*Y, Z)=((c0+c1*u)*v*w, (d0+d1*u)*v),e0+e1*u)
void SM9_Pairing_EncAL_R_Ate_Q1(SM9_Fp12 *pLineEva, SM9_ECP2_J *pJSum, SM9_ECP2_J *pJT,
                                SM9_ECP2_A *pAQ, SM9_ECP_A *pAP)
{
    SM9_ECP2_J JSum_T;
    SM9_Fp12 LineEva_T;

    SM9_Fp2 T1;
    SM9_Fp2 T2;
    SM9_Fp2 T3;
    SM9_Fp2 T4;
    SM9_Fp2 T5;

    // uint32_t BN_T[BNWordLen];

    SM9_Fp2_Squ(&T1, &(pJT->Z)); // T1 = Z ^ 2 = A, Z=e0+e1*u
    SM9_Fp2_Mul(&T2, &T1, &(pJT->Z)); // T2 = Z ^ 3 = B

    SM9_Fp2_Mul(&T3, &(pAQ->Y), &T2);
    SM9_Fp2_Sub(&T3, &T3, &(pJT->Y)); // T3= Y2 * B - Y1 = theta=(theat0 + theta1*u)*v
    SM9_Fp2_Mul(&T4, &(pAQ->X), &T1);
    SM9_Fp2_Sub(&T4, &T4, &(pJT->X)); // T4=X2 * A - X1 = lambda =(lambda0 + lambda1*u)*v*w

    // T1 = theta ^ 2 = C = ((theat0 + theta1*u)*v)^2
    // = (theat0 + theta1*u)^2 * v^2
    // = (theat0 + theta1*u)^2 * u
    // = c0 + c1*u
    SM9_Fp2_Squ(&T1, &T3);
    SM9_Fp2_Mul_U(&T1, &T1); // (theat0 + theta1*u)^2 * u

    // T2 = lambda ^ 2 = D
    // = ((lambda0 + lambda1*u)*v*w)^2
    // = (lambda0 + lambda1*u)^2*v^2*w^2
    // = (lambda0 + lambda1*u)^2*u*w^2
    // = (d0 + d1*u)*w^2
    SM9_Fp2_Squ(&T2, &T4);
    SM9_Fp2_Mul_U(&T2, &T2); // (lambda0 + lambda1*u)^2 * u

    // T5 = D*lambda = E
    // = (d0 + d1*u)*w^2 * (lambda0 + lambda1*u)*v*w
    // = (d0 + d1*u)*(lambda0 + lambda1*u)*v*w^3
    // = (d0 + d1*u)*(lambda0 + lambda1*u)*v^2
    // = (d0 + d1*u)*(lambda0 + lambda1*u)*u
    // = e0 + e1*u
    SM9_Fp2_Mul(&T5, &T2, &T4); // (d0 + d1*u)*(lambda0 + lambda1*u)
    SM9_Fp2_Mul_U(&T5, &T5); // (d0 + d1*u)*(lambda0 + lambda1*u)*u

    // T1 = C - E = F
    // = (c0 + c1*u)-(e0 + e1*u)
    // = f0 + f1*u
    SM9_Fp2_Sub(&T1, &T1, &T5);

    // T2 = X * D = G
    // = ((x0 + x1*u)*v*w) * (d0 + d1*u)*w^2
    // = (x0 + x1*u)*(d0 + d1*u)*v*w^3
    // = (x0 + x1*u)*(d0 + d1*u)*v*v
    // = (x0 + x1*u)*(d0 + d1*u)*u
    // = g0+g1*u
    SM9_Fp2_Mul(&T2, &T2, &(pJT->X)); // (x0 + x1*u)*(d0 + d1*u)
    SM9_Fp2_Mul_U(&T2, &T2); // (x0 + x1*u)*(d0 + d1*u)*u

    // X3 = F - 2 * G
    // = (f0 + f1*u)-2*(g0+g1*u)
    // = x30 + x31*u
    SM9_Fp2_Sub(&(JSum_T.X), &T1, &T2);
    SM9_Fp2_Sub(&(JSum_T.X), &(JSum_T.X), &T2);

    // Y3 = theta * (G-X3) - Y * E
    // = ((theat0 + theta1*u)*v) * ((g0+g1*u) - (x30 + x31*u))-((y0 + y1*u)*v)*(e0 + e1*u)
    // = (y30+y31*u)*v
    SM9_Fp2_Sub(&(JSum_T.Y), &T2, &(JSum_T.X)); // Y3 = G-X3
    SM9_Fp2_Mul(&(JSum_T.Y), &(JSum_T.Y), &T3); // Y3 = theta * (G-X3)
    SM9_Fp2_Mul(&T5, &(pJT->Y), &T5); // T5 = Y * E
    SM9_Fp2_Sub(&(JSum_T.Y), &(JSum_T.Y), &T5); // Y3 = theta * (G-X3) - Y * E

    // Z3 = Z * lambda
    // = (z0 + z1*u) * ((lambda0 + lambda1*u)*v*w)
    // = (z0 + z1*u)*(lambda0 + lambda1*u)*v*w
    // = (z30 + z31*u)*v*w
    SM9_Fp2_Mul(&(JSum_T.Z), &(pJT->Z), & T4);

    // M-type twist
    // l_TQ1P := Z3*(yP - Y2) - theta*(xP - X2);

    SM9_Fp12_Reset(&LineEva_T);

    // Z3*(yP - Y2)
    // = ((z30 + z31*u)*v*w) * ((yP+0*u) - (yq0 + yq1*u)*v)
    // = (z30 + z31*u)* (yP+0*u) *v*w -  (z30 + z31*u) * (yq0 + yq1*u)*v^2*w
    // = (z30 + z31*u)* (yP+0*u) *v*w -  (z30 + z31*u) * (yq0 + yq1*u)*u*w
    // = T1 * w - T2 * v * w
    SM9_Fp2_Mul(&T1, &(JSum_T.Z), &pAQ->Y);    // T1=(z30 + z31*u) * (yq0 + yq1*u)
    SM9_Fp2_Mul_U(&T1, &T1); // T1=(z30 + z31*u) * (yq0 + yq1*u)*u
    SM9_Fp2_Mul_Coef0(&T2, &(JSum_T.Z), pAP->Y); // T2=(z30 + z31*u)* (yP+0*u)

    // theta*(xP - X2)
    // = (theat0 + theta1*u)*v * ((xP+0*u) - ((xq0 + xq1*u)*v)*w)
    // = xP * (theat0 + theta1*u)*v - (theat0 + theta1*u)*(xq0 + xq1*u)*v^2*w
    // = xP * (theat0 + theta1*u)*v - (theat0 + theta1*u)*(xq0 + xq1*u)*u*w
    // = T4 * v - T5 * w
    SM9_Fp2_Mul_Coef0(&T4, &T3, pAP->X); // T4=xP * (theat0 + theta1*u)
    SM9_Fp2_Mul(&T5, &T3, &pAQ->X); // T5=(theat0 + theta1*u)*(xq0 + xq1*u)
    SM9_Fp2_Mul_U(&T5, &T5); // T5=(theat0 + theta1*u)*(xq0 + xq1*u)*u
    // Z3*(yP - Y2) - theta*(xP - X2)
    // = (T1 * w - T2 * v * w) - (T4 * v - T5 * w)
    // = -T4 * v + ((T1+T5)-T2*v)* w
    SM9_Fp2_Neg(&(LineEva_T.Coef_0.Coef_1), &T4);
    SM9_Fp2_Sub(&T1, &T1, &T5);
    SM9_Fp2_Neg(&(LineEva_T.Coef_1.Coef_0), &T1);
    SM9_Fp2_Assign(&(LineEva_T.Coef_1.Coef_1), &T2);

    SM9_Fp12_Assign(pLineEva, &LineEva_T);

    SM9_Ecp2_J_Assign(pJSum, &JSum_T);

    // SM9_Fp2_Assign(&pJSum->X, &JSum_T.X);
    // SM9_Fp2_Assign(&pJSum->Y, &JSum_T.Y);
    // SM9_Fp2_Assign(&pJSum->Z, &JSum_T.Z);
}

// pAQ=(xQ1,yQ1)=((cubic_root*xQ)^q2, (quadratic_root*yQ)^q2)=((x0+x1*u)*v*w, (y0+y1*u)*v)
// pJT=(x30 + x31*u, (y30+y31*u)*v, (z30 + z31*u)*v*w)
void SM9_Pairing_EncAL_R_Ate_Q2(SM9_Fp12 *pLineEva, SM9_ECP2_J *pJT, SM9_ECP2_A *pAQ, SM9_ECP_A *pAP)
{
    // SM9_ECP2_J JSum_T;
    SM9_Fp12 LineEva_T;
    SM9_Fp2 JSum_T_Z3;

    SM9_Fp2 T1;
    SM9_Fp2 T2;
    SM9_Fp2 T3;
    SM9_Fp2 T4;
    SM9_Fp2 T5;

    uint32_t BN_T[BNWordLen];

    int32_t wsize = 0;

    // wsize = pSysPara->wsize;

    // SM9_Fp2_Reset(&T1, wsize);
    // SM9_Fp2_Reset(&T2, wsize);
    // SM9_Fp2_Reset(&T3, wsize);
    // SM9_Fp2_Reset(&T4, wsize);
    // SM9_Fp2_Reset(&T5, wsize);

    SM9_Fp2_Reset(&JSum_T_Z3);

    bn_reset(BN_T, wsize);

    // T1 = Z ^ 2 = A, Z=(z30 + z31*u)*v*w
    // = ((z30 + z31*u)*v*w)^2
    // = (z30 + z31*u)^2*v^2*w^2
    // = (z30 + z31*u)^2*u*w^2
    // = (a0+a1*u)*w^2
    // SM9_Fp2_Mul(&T1, &(pJT->Z), &(pJT->Z)); // (z30 + z31*u)^2
    SM9_Fp2_Squ(&T1, &(pJT->Z));
    SM9_Fp2_Mul_U(&T1, &T1); // (z30 + z31*u)^2*u

    // T2 = Z ^ 3 = B
    // = (a0+a1*u)*w^2 * (z30 + z31*u)*v*w
    // = (a0+a1*u)*(z30 + z31*u)*v*w^3
    // = (a0+a1*u)*(z30 + z31*u)*v*v
    // = (a0+a1*u)*(z30 + z31*u)*u
    // = b0+b1*u
    SM9_Fp2_Mul(&T2, &T1, &(pJT->Z)); // (a0+a1*u)*(z30 + z31*u)
    SM9_Fp2_Mul_U(&T2, &T2); // (a0+a1*u)*(z30 + z31*u)*u

    // T3= Y2 * B - Y = theta=(theat0 + theta1*u)*v
    // = ((y0+y1*u)*v)*(b0+b1*u)-((y30+y31*u)*v)
    // = (t30+t31*u)*v
    SM9_Fp2_Mul(&T3, &(pAQ->Y), &T2);
    SM9_Fp2_Sub(&T3, &T3, &(pJT->Y));

    // T4=X2 * A - X = lambda =(lambda0 + lambda1*u)
    // = ((x0+x1*u)*v*w)*((a0+a1*u)*w^2)-(x30 + x31*u)
    // = (x0+x1*u)*(a0+a1*u)*v*w^3-(x30 + x31*u)
    // = (x0+x1*u)*(a0+a1*u)*v^2-(x30 + x31*u)
    // = (x0+x1*u)*(a0+a1*u)*u-(x30 + x31*u)
    // = t40+t41*u
    SM9_Fp2_Mul(&T4, &(pAQ->X), &T1); // (x0+x1*u)*(a0+a1*u)
    SM9_Fp2_Mul_U(&T4, &T4); // (x0+x1*u)*(a0+a1*u)*u

    SM9_Fp2_Sub(&T4, &T4, &(pJT->X));

    // Z3 = Z * lambda
    // = (z30 + z31*u)*v*w*(lambda0 + lambda1*u)
    // = (z0 + z1*u)*(lambda0 + lambda1*u)*v*w
    // = (z30 + z31*u)*v*w
    SM9_Fp2_Mul(&(JSum_T_Z3), &(pJT->Z), & T4);

    // M-type twist
    // l_TQ1P := Z3*(yP - Y2) - theta*(xP - X2);

    SM9_Fp12_Reset(&LineEva_T);

    // Z3*(yP - Y2)
    // = ((z30 + z31*u)*v*w) * ((yP+0*u) - (yq0 + yq1*u)*v)
    // = (z30 + z31*u)* (yP+0*u) *v*w -  (z30 + z31*u) * (yq0 + yq1*u)*v^2*w
    // = (z30 + z31*u)* (yP+0*u) *v*w -  (z30 + z31*u) * (yq0 + yq1*u)*u*w
    // = T1 * w - T2 * v * w
    SM9_Fp2_Mul(&T1, &(JSum_T_Z3), &pAQ->Y);     // T1=(z30 + z31*u) * (yq0 + yq1*u)
    SM9_Fp2_Mul_U(&T1, &T1); // z30 + z31*u) * (yq0 + yq1*u)*u

    SM9_Fp2_Mul_Coef0(&T2, &(JSum_T_Z3), pAP->Y); // T2=(z30 + z31*u)* (yP+0*u)

    // theta*(xP - X2)
    // = (theat0 + theta1*u)*v * ((xP+0*u) - ((xq0 + xq1*u)*v)*w)
    // = xP * (theat0 + theta1*u)*v - (theat0 + theta1*u)*(xq0 + xq1*u)*v^2*w
    // = xP * (theat0 + theta1*u)*v - (theat0 + theta1*u)*(xq0 + xq1*u)*u*w
    // = T4 * v - T5 * w
    SM9_Fp2_Mul_Coef0(&T4, &T3, pAP->X); // T4=xP * (theat0 + theta1*u)
    SM9_Fp2_Mul(&T5, &T3, &pAQ->X); // T5=(theat0 + theta1*u)*(xq0 + xq1*u)
    SM9_Fp2_Mul_U(&T5, &T5); // T5=(theat0 + theta1*u)*(xq0 + xq1*u)*u

    // Z3*(yP - Y2) - theta*(xP - X2)
    // = (T1 * w - T2 * v * w) - (T4 * v - T5 * w)
    // = -T4 * v + ((T1+T5)-T2*v)* w
    SM9_Fp2_Neg(&(LineEva_T.Coef_0.Coef_1), &T4);
    SM9_Fp2_Sub(&T1, &T1, &T5);
    SM9_Fp2_Neg(&(LineEva_T.Coef_1.Coef_0), &T1);
    SM9_Fp2_Assign(&(LineEva_T.Coef_1.Coef_1), &T2);

    SM9_Fp12_Assign(pLineEva, &LineEva_T);
}

void SM9_Pairing_Miller_R_Tate(SM9_Fp12 *pFp12_R, SM9_ECP_A *pEcp_P1, SM9_ECP2_A *pEcp2_P2, uint32_t *pBn_T)
{
    SM9_ECP2_J Ecp2_JT;
    SM9_ECP2_A Ecp2_AT;
    SM9_Fp12 Fp12_L;
    int32_t bitlen;
    int32_t i;

    bitlen = bn_get_bitlen(pBn_T, sm9_sys_para.wsize);
    if (bitlen == 0) {
        SM9_Fp12_Reset(pFp12_R);
        return;
    }

    SM9_Ecp2_J_Reset(&Ecp2_JT);
    SM9_Ecp2_A_ToJ(&Ecp2_JT, pEcp2_P2);

    // i = bitlen - 2
    SM9_Pairing_EncDL(pFp12_R, &Ecp2_JT, &Ecp2_JT, pEcp_P1);

    // for (i = bitlen - 2; i >= 0; i--)
    for (i = bitlen - 3; i >= 0; i--) {
        SM9_Fp12_Squ(pFp12_R, pFp12_R);
        SM9_Pairing_EncDL(&Fp12_L, &Ecp2_JT, &Ecp2_JT, pEcp_P1);
        SM9_Fp12_Mul_For_MillerLoop(pFp12_R, pFp12_R, &Fp12_L);
        if (BN_BIT(pBn_T, i)) {
            SM9_Pairing_EncAL(&Fp12_L, &Ecp2_JT, &Ecp2_JT, pEcp2_P2, pEcp_P1);
            SM9_Fp12_Mul_For_MillerLoop(pFp12_R, pFp12_R, &Fp12_L);
        }
    }

    // X := cubic_root*X;    Y := quadratic_root*Y;
    SM9_Pairing_MulCubRoot(&(Ecp2_JT.X), &(Ecp2_JT.X));
    SM9_Pairing_MulQuaRoot(&(Ecp2_JT.Y), &(Ecp2_JT.Y));

    // xQ := cubic_root*xQ;    yQ := quadratic_root*yQ;
    SM9_Pairing_MulCubRoot(&(Ecp2_AT.X), &(pEcp2_P2->X));
    SM9_Pairing_MulQuaRoot(&(Ecp2_AT.Y), &(pEcp2_P2->Y));

    // xQ1 := xQ^q; xQ = cubic_root*xQ;    yQ1 := yQ^q; yQ = quadratic_root*yQ;
    SM9_Pairing_MulCubRoot_FrobMap(&(Ecp2_AT.X), &(Ecp2_AT.X));
    SM9_Pairing_MulQuaRoot_FrobMap(&(Ecp2_AT.Y), &(Ecp2_AT.Y));
    SM9_Pairing_EncAL_R_Ate_Q1(&Fp12_L, &Ecp2_JT, &Ecp2_JT, &Ecp2_AT, pEcp_P1);
    SM9_Fp12_Mul_For_FrobMap(pFp12_R, pFp12_R, &Fp12_L);

    // X2 := X2^q;    Y2 := -Y2^q;
    SM9_Pairing_MulCubRoot_FrobMap(&(Ecp2_AT.X), &(Ecp2_AT.X));
    SM9_Pairing_MulQuaRoot_FrobMap(&(Ecp2_AT.Y), &(Ecp2_AT.Y));
    SM9_Fp2_Neg(&(Ecp2_AT.Y), &(Ecp2_AT.Y));
    SM9_Pairing_EncAL_R_Ate_Q2(&Fp12_L, &Ecp2_JT, &Ecp2_AT, pEcp_P1);
    SM9_Fp12_Mul_For_FrobMap(pFp12_R, pFp12_R, &Fp12_L);
}

void SM9_Pairing_Exp_Q6(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_E)
{
    SM9_Fp12 Fp12_T1;

    // T1 = Conj(f)
    SM9_Fp12_GetConj(&Fp12_T1, pFp12_E);
    // Inv = f ^ (-1)
    SM9_Fp12_Inv(pFp12_R, pFp12_E);
    // Res_T = Conj(f) / f
    SM9_Fp12_Mul(pFp12_R, pFp12_R, &Fp12_T1);
}

void SM9_Pairing_Exp_Q2(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_E)
{
    SM9_Fp12 Fp12_T1;

    // T1 = f ^ (p^2)
    SM9_Fp12_FrobMap(&Fp12_T1, pFp12_E); // T1 = f ^ p
    SM9_Fp12_FrobMap(&Fp12_T1, &Fp12_T1); // T1 = f ^ (p^2)

    // Res_T = f ^ (p^2 + 1)
    SM9_Fp12_Mul(pFp12_R, &Fp12_T1, pFp12_E);
}

void SM9_Pairing_Exp_Q4(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_E)
{
    SM9_Fp12 y0;
    SM9_Fp12 y1;
    SM9_Fp12 y2;
    SM9_Fp12 y3;
    SM9_Fp12 y4;
    SM9_Fp12 y5;
    SM9_Fp12 y6;

    SM9_Fp12 T0;
    SM9_Fp12 T1;
    // SM9_Fp12 T2;
    // SM9_Fp12 T3;

    SM9_Fp12_FrobMap(&y0, pFp12_E);    // y0 = f ^ q
    SM9_Fp12_FrobMap(&y2, &y0);        // y2 = f ^ (q^2)
    SM9_Fp12_FrobMap(&y3, &y2);        // y3 = f ^ (q^3)

    // y0 = (f^q) * f^{q^2} * f^{q^3}
    SM9_Fp12_Mul(&y0, &y0, &y2);    // y0 = (f^p) * f^{p^2}
    SM9_Fp12_Mul(&y0, &y0, &y3);    // y0 = (f^p) * f^{p^2} * f^{p^3}

    // y1 = 1 / f
    SM9_Fp12_GetConj(&y1, pFp12_E);

    // y2 = (f^(t^2))^(q^2)
    SM9_Fp12_Exp(&y2, &y2, sm9_sys_para.EC_T); // y2 = (f ^ (q^2))^t
    SM9_Fp12_Exp(&y2, &y2, sm9_sys_para.EC_T); // y2 = (f ^ (q^2))^(t^2)=(f^(t^2))^(q^2)

    // y3 = ((1/f)^t)^q
    SM9_Fp12_Exp(&y4, &y1, sm9_sys_para.EC_T); // T1 = (1/f) ^ t
    SM9_Fp12_FrobMap(&y3, &y4); // y3 = ((1/f)^t)^q

    // y5=(1/f)^(t^2)
    SM9_Fp12_Exp(&y5, &y4, sm9_sys_para.EC_T); // T2 = (1/f) ^ (t^2)

    // y4=1/(f^t * (f^(t^2))^q)
    SM9_Fp12_FrobMap(&y6, &y5); // T2=((1/f) ^ (t^2))^q
    SM9_Fp12_Mul(&y4, &y4, &y6); // y4=1/(f^t * (f^(t^2))^q)

    // y6=1/(f^(t^3)*(f^(t^3))^q)
    SM9_Fp12_Exp(&T0, &y5, sm9_sys_para.EC_T); // T1 = (1/f) ^ (t^3)
    SM9_Fp12_FrobMap(&T1, &T0); // T2=((1/f) ^ (t^3))^q
    SM9_Fp12_Mul(&y6, &T0, &T1); // y4=1/(f^t * (f^(t^2))^q)

    SM9_Fp12_Mul(&T0, &y6, &y6);        // T0=y6^2
    SM9_Fp12_Mul(&T0, &T0, &y4);        // T0=T0*y4 = y4 * y6^2
    SM9_Fp12_Mul(&T0, &T0, &y5);        // T0=T0*y5 = y4 * y5 *  y6^2
    SM9_Fp12_Mul(&T1, &y3, &y5);        // T1=y3*y5
    SM9_Fp12_Mul(&T1, &T1, &T0);        // T1=T1*T0 = y3 * y4 * y5^2 *  y6^2
    SM9_Fp12_Mul(&T0, &T0, &y2);        // T0=T0*y2 = y2 * y4 * y5 *  y6^2
    SM9_Fp12_Mul(&T1, &T1, &T1);        // T1=T1^2  = y3^2 * y4^2 * y5^4 *  y6^4
    SM9_Fp12_Mul(&T1, &T1, &T0);        // T1=T1*T0 = y2 * y3^2 * y4^3 * y5^5 *  y6^6
    SM9_Fp12_Mul(&T1, &T1, &T1);        // T1=T1^2  = y2^2 * y3^4 * y4^6 * y5^10 * y6^12
    SM9_Fp12_Mul(&T0, &T1, &y1);        // T0=T1*y1 = y1 * y2 * y4 * y5 *  y6^2
    SM9_Fp12_Mul(&T1, &T1, &y0);        // T1=T1*y0 = y0 * y2^2 * y3^4 * y4^6 * y5^10 * y6^12
    SM9_Fp12_Mul(&T0, &T0, &T0);        // T0=T0^2  = y1^2 * y2^2 * y4^2 * y5^2 *  y6^4
    SM9_Fp12_Mul(pFp12_R, &T0, &T1);    // T0=T0*T1 = y0 * y1^2 * y2^4 * y3^4 * y4^8 * y5^12 * y6^16
}

void SM9_Pairing_FinExp(SM9_Fp12 *pFp12_R, SM9_Fp12 *pFp12_E)
{
    SM9_Pairing_Exp_Q6(pFp12_R, pFp12_E);
    SM9_Pairing_Exp_Q2(pFp12_R, pFp12_R);
    SM9_Pairing_Exp_Q4(pFp12_R, pFp12_R);
}

void SM9_Pairing_R_Ate(SM9_Fp12 *pFp12_R, SM9_ECP_A *pEcp_P1, SM9_ECP2_A *pEcp2_P2)
{
    SM9_Pairing_Miller_R_Tate(pFp12_R, pEcp_P1, pEcp2_P2, sm9_sys_para.EC_6T2);
    SM9_Pairing_FinExp(pFp12_R, pFp12_R);
}

#endif // HITLS_CRYPTO_SM9
