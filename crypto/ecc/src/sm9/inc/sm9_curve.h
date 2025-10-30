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

#ifndef    __HEADER_SM9_CURVE_H__
#define    __HEADER_SM9_CURVE_H__

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include <stdint.h>
#include "bn.h"

#define SM9_BITLEN                    256
#define SM9_BYTELEN                    32
#define SM9_WORDLEN                    8

/*=======================SM3 Adaptation Layer for SM9========================*/

#define CRYPT_SM3_DIGESTSIZE 32
#define CRYPT_SM3_BLOCKSIZE 64
#define SM9_Hash_Size 32

/**
 * @brief Embedded CRYPT_SM3_Ctx structure
 *
 */
typedef struct {
    uint32_t h[CRYPT_SM3_DIGESTSIZE / sizeof(uint32_t)];
    uint32_t hNum, lNum;
    uint8_t block[CRYPT_SM3_BLOCKSIZE];
    uint32_t num;
} SM9_CRYPT_SM3_Ctx;

/**
 * @brief SM9 Hash Context
 *
 * Embeds SM3 state directly to support memcpy() in SM9_Hash_KDF_Block
 */
typedef struct {
    SM9_CRYPT_SM3_Ctx sm3State;
} SM9_Hash_Ctx;

// Function declarations are in sm9.h

/*============================================================================*/

// Coef_0 + Coef_1 * u and u ^ 2 = -2
typedef    struct _SM9_FP2
{
    uint32_t Coef_0[BNWordLen];
    uint32_t Coef_1[BNWordLen];
}SM9_Fp2;

// Coef_0 + Coef_1 * v, v ^ 2 = u
typedef    struct _SM9_FP4
{
    SM9_Fp2 Coef_0;
    SM9_Fp2 Coef_1;
}SM9_Fp4;

// Coef_0 +Coef_1 * w  + Coef_2 * w ^ 2 and w^3 = v
typedef    struct _SM9_FP12
{
    SM9_Fp4 Coef_0;
    SM9_Fp4 Coef_1;
    SM9_Fp4 Coef_2;
}SM9_Fp12;

// struct of affine coordinate
typedef struct _SM9_FP_ECP_A {
    uint32_t X[BNWordLen];
    uint32_t Y[BNWordLen];
}SM9_ECP_A;

// struct of projective coordinate
typedef    struct _SM9_FP_ECP_J
{
    uint32_t X[BNWordLen];
    uint32_t Y[BNWordLen];
    uint32_t Z[BNWordLen];
}SM9_ECP_J;

typedef struct _SM9_FP2_ECP_A {
    SM9_Fp2 X;
    SM9_Fp2 Y;
}SM9_ECP2_A;                // struct of affine coordinate

typedef    struct _SM9_FP2_ECP_J
{
    SM9_Fp2 X;
    SM9_Fp2 Y;
    SM9_Fp2 Z;
}SM9_ECP2_J;                // struct of projective coordinate

typedef struct _SM9_SYS_PARA {
    int32_t wsize;

    uint32_t EC_T[BNWordLen];
    uint32_t EC_6T2[BNWordLen];                        // 6*t+2
    uint32_t EC_Trace[BNWordLen];

    uint32_t EC_Q[BNWordLen];
    uint32_t Q_Mc;
    uint32_t Q_R1[BNWordLen];
    uint32_t Q_R2[BNWordLen];

    uint32_t EC_N[BNWordLen];
    uint32_t N_Mc;
    uint32_t N_R1[BNWordLen];                        // R mod n
    uint32_t N_R2[BNWordLen];                        // RR mod n

    uint32_t EC_Fp_A_Mont[BNWordLen];                // y^2 = x^3 + a*x + b mod q
    uint32_t EC_Fp_B_Mont[BNWordLen];                // y^2 = x^3 + a*x + b mod q
    SM9_ECP_A EC_Fp_G_Mont;

    SM9_Fp2 EC_Fp2_A_Mont;                        // y^2 = x^3 + a*x + b mod q^2
    SM9_Fp2 EC_Fp2_B_Mont;                        // y^2 = x^3 + a*x + b mod q^2
    SM9_ECP2_A EC_Fp2_G_Mont;

    uint32_t EC_Vq_Mont[BNWordLen];
    uint32_t EC_Wq_Mont[BNWordLen];
    uint32_t EC_W2q_Mont[BNWordLen];
    uint32_t EC_Root_Mont[BNWordLen];

    uint32_t EC_One[BNWordLen];                        //One
    uint32_t EC_4_Inv_Mont[BNWordLen];
}SM9_Sys_Para;

typedef struct _sm9_alg_context_st {
    uint32_t        buf[300][BNWordLen];
    SM9_Hash_Ctx    mac_ctx;

    struct {
        unsigned char k1[2 * BNByteLen];
        unsigned char *k2;
        unsigned char cnt[4];
        SM9_Hash_Ctx    xor_ctx;
        SM9_Hash_Ctx    tmp_ctx;
        unsigned int  bytes;
    } enc;
} SM9_CTX;

extern SM9_Sys_Para    sm9_sys_para;

extern unsigned char g_SM9_G1[64];
extern unsigned char g_SM9_G2[128];

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}  /* end extern "C" */
#endif

#endif // HITLS_CRYPTO_SM9

#endif /* __HEADER_SM9_CURVE_H__ */

