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

#ifndef SM9_LOCAL_H
#define SM9_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include <stdint.h>
#include "crypt_sm9.h"
#include "crypt_sm3.h"

#define SM9_BN_WORD_BITS  32
#define SM9_BN_BYTE_BITS  8
#define SM9_BN_WORD_BYTES (SM9_BN_WORD_BITS / SM9_BN_BYTE_BITS)
#define SM9_BN_LSB_MASK   0x00000001

// macro for BN in SM9
#define SM9_BN_BITS  256
#define SM9_BN_BYTES (SM9_BN_BITS / SM9_BN_BYTE_BITS)
#define SM9_BN_WORDS (SM9_BN_BITS / SM9_BN_WORD_BITS)

#define SM9_BN_MAX_WORDS 16

#define SM9_BN_GET_BIT(x, i) (((x)[(i) / SM9_BN_WORD_BITS] >> ((i) % SM9_BN_WORD_BITS)) & 1)

#define SM9_BN_ReadBytes(result, input) SM9_BN_ByteToBN(input, SM9_BN_BYTES, result, SM9_BN_WORDS)

#define SM9_Fn_LastRes(value) SM9_BN_GetResidue(value, g_sm9SysPara.ecN, g_sm9SysPara.wordSize)

#define SM9_Fn_Sub(result, left, right) SM9_BN_ModSub(result, left, right, g_sm9SysPara.ecN, g_sm9SysPara.wordSize)

#define SM9_Fn_Add(result, left, right) SM9_BN_ModAdd(result, left, right, g_sm9SysPara.ecN, g_sm9SysPara.wordSize)

#define SM9_CURVE_MODULE_BYTES 32

#define SM9_SIG_SYS_PRIKEY_BYTES SM9_CURVE_MODULE_BYTES
#define SM9_SIG_SYS_PUBKEY_BYTES (4 * SM9_CURVE_MODULE_BYTES)
#define SM9_SIG_USR_PRIKEY_BYTES (2 * SM9_CURVE_MODULE_BYTES)

#define SM9_ENC_SYS_PRIKEY_BYTES SM9_CURVE_MODULE_BYTES
#define SM9_ENC_SYS_PUBKEY_BYTES (2 * SM9_CURVE_MODULE_BYTES)
#define SM9_ENC_USR_PRIKEY_BYTES (4 * SM9_CURVE_MODULE_BYTES)

#define SM9_SIGNATURE_BYTES (3 * SM9_CURVE_MODULE_BYTES)

#define SM9_ENC_OVERHEAD_BYTES (3 * SM9_CURVE_MODULE_BYTES)

// coef0 + coef1 * u and u ^ 2 = -2
typedef struct {
    uint32_t coef0[SM9_BN_WORDS];
    uint32_t coef1[SM9_BN_WORDS];
} SM9_Fp2;

// coef0 + coef1 * v, v ^ 2 = u
typedef struct {
    SM9_Fp2 coef0;
    SM9_Fp2 coef1;
} SM9_Fp4;

// coef0 +coef1 * w  + coef2 * w ^ 2 and w^3 = v
typedef struct {
    SM9_Fp4 coef0;
    SM9_Fp4 coef1;
    SM9_Fp4 coef2;
} SM9_Fp12;

// struct of affine coordinate
typedef struct {
    uint32_t x[SM9_BN_WORDS];
    uint32_t y[SM9_BN_WORDS];
} SM9_EcpA;

// struct of projective coordinate
typedef struct {
    uint32_t x[SM9_BN_WORDS];
    uint32_t y[SM9_BN_WORDS];
    uint32_t z[SM9_BN_WORDS];
} SM9_EcpJ;

typedef struct {
    SM9_Fp2 x;
    SM9_Fp2 y;
} SM9_Ecp2A; // struct of affine coordinate

typedef struct {
    SM9_Fp2 x;
    SM9_Fp2 y;
    SM9_Fp2 z;
} SM9_Ecp2J; // struct of projective coordinate

typedef struct {
    int32_t wordSize;

    uint32_t ecT[SM9_BN_WORDS];
    uint32_t ec6T2[SM9_BN_WORDS]; // 6*t+2
    uint32_t ecTrace[SM9_BN_WORDS];

    uint32_t ecQ[SM9_BN_WORDS];
    uint32_t qMc;
    uint32_t qR1[SM9_BN_WORDS];
    uint32_t qR2[SM9_BN_WORDS];

    uint32_t ecN[SM9_BN_WORDS];
    uint32_t nMc;
    uint32_t nR1[SM9_BN_WORDS]; // R mod n
    uint32_t nR2[SM9_BN_WORDS]; // RR mod n

    uint32_t ecFpAMont[SM9_BN_WORDS]; // y^2 = x^3 + a*x + b mod q
    uint32_t ecFpBMont[SM9_BN_WORDS]; // y^2 = x^3 + a*x + b mod q
    SM9_EcpA ecFpGMont;

    SM9_Fp2 ecFp2AMont; // y^2 = x^3 + a*x + b mod q^2
    SM9_Fp2 ecFp2BMont; // y^2 = x^3 + a*x + b mod q^2
    SM9_Ecp2A ecFp2GMont;

    uint32_t ecVqMont[SM9_BN_WORDS];
    uint32_t ecWqMont[SM9_BN_WORDS];
    uint32_t ecW2qMont[SM9_BN_WORDS];
    uint32_t ecRootMont[SM9_BN_WORDS];

    uint32_t ecOne[SM9_BN_WORDS]; // One
    uint32_t ec4InvMont[SM9_BN_WORDS];
} SM9_SysPara;

typedef struct {
    uint32_t buf[300][SM9_BN_WORDS];
    CRYPT_SM3_Ctx macCtx;

    struct {
        uint8_t k1[2 * SM9_BN_BYTES];
        uint8_t *k2;
        uint8_t cnt[4];
        CRYPT_SM3_Ctx xorCtx;
        CRYPT_SM3_Ctx tmpCtx;
        uint32_t bytes;
    } enc;
} SM9_AlgCtx;

/**
 * @brief SM9 Context Structure
 *
 * Encapsulates all key materials and state information required for
 * signature and encryption operations.
 */
struct SM9_Ctx_st {
    uint8_t sigMsk[SM9_SIG_SYS_PRIKEY_BYTES];
    uint8_t sigMpk[SM9_SIG_SYS_PUBKEY_BYTES];
    uint8_t sigDsk[SM9_SIG_USR_PRIKEY_BYTES];
    uint8_t sigG[12 * SM9_CURVE_MODULE_BYTES];

    uint8_t encMsk[SM9_ENC_SYS_PRIKEY_BYTES];
    uint8_t encMpk[SM9_ENC_SYS_PUBKEY_BYTES];
    uint8_t encDek[SM9_ENC_USR_PRIKEY_BYTES];
    uint8_t encG[12 * SM9_CURVE_MODULE_BYTES];

    uint8_t userId[256];
    uint32_t userIdLen;

    uint32_t hasSigMsk : 1;
    uint32_t hasEncMsk : 1;
    uint32_t hasSigSys : 1;
    uint32_t hasSigUsr : 1;
    uint32_t hasSigG : 1;
    uint32_t hasEncSys : 1;
    uint32_t hasEncUsr : 1;
    uint32_t hasEncG : 1;
};

typedef struct SM9_Ctx_st SM9_Ctx;

extern SM9_SysPara g_sm9SysPara;

extern uint8_t g_sm9G1[64];
extern uint8_t g_sm9G2[128];

#ifdef __cplusplus
extern "C" {
#endif

int32_t SM9_SetSignMasterKey(SM9_Ctx *ctx, uint8_t *masterPrivateKey);

int32_t SM9_GenSignUserKey(SM9_Ctx *ctx, const uint8_t *userId, uint32_t userIdLen);

int32_t SM9_SetSignUserKey(SM9_Ctx *ctx, uint8_t *userId, uint32_t userIdLen, uint8_t *userPrivateKey);

int32_t SM9_Alg_MSKG(uint8_t *masterPrivateKey, uint8_t *masterPubKey);

int32_t SM9_Alg_Sign(const uint8_t *msg, uint32_t msgLen, const uint8_t *userPrivateKey, uint8_t *randomBytes,
                     const uint8_t *precomputedPairing, const uint8_t *masterPubKey, uint8_t *signature);

int32_t SM9_CheckSignKeyPair(const CRYPT_SM9_Ctx *masterCtx, const CRYPT_SM9_Ctx *userCtx);

int32_t SM9_SetEncMasterKey(SM9_Ctx *ctx, uint8_t *masterPrivateKey);

int32_t SM9_GenEncUserKey(SM9_Ctx *ctx, const uint8_t *userId, uint32_t userIdLen);

int32_t SM9_SetEncUserKey(SM9_Ctx *ctx, uint8_t *userId, uint32_t userIdLen, uint8_t *userPrivateKey);

int32_t SM9_Alg_MEKG(uint8_t *masterPrivateKey, uint8_t *masterPubKey);

int32_t SM9_Alg_UEKG(const uint8_t *userId, uint32_t userIdLen, uint8_t *masterPrivateKey, uint8_t *userPrivateKey);

int32_t SM9_Alg_Enc(const uint8_t *msg, uint32_t msgLen, const uint8_t *userId, uint32_t userIdLen,
                    uint8_t *randomBytes, const uint8_t *precomputedPairing, const uint8_t *masterPubKey,
                    uint8_t *ciphertext, uint32_t *ciphertextLen);

int32_t SM9_Alg_Dec(const uint8_t *ciphertext, uint32_t ciphertextLen, const uint8_t *userPrivateKey,
                    const uint8_t *userId, uint32_t userIdLen, uint8_t *msg, uint32_t *msgLen);

int32_t SM9_CheckEncKeyPair(const CRYPT_SM9_Ctx *masterCtx, const CRYPT_SM9_Ctx *userCtx);

int32_t SM9_BN_Compare(const uint32_t *left, const uint32_t *right, int32_t wordSize);

int32_t SM9_BN_IsZero(uint32_t *value, int32_t wordSize);

int32_t SM9_BN_Equal(const uint32_t *left, const uint32_t *right, int32_t wordSize);

void SM9_BN_ModAdd(uint32_t *result, const uint32_t *left, const uint32_t *right, const uint32_t *modulus,
                   int32_t wordSize);

void SM9_BN_ModSub(uint32_t *result, const uint32_t *left, const uint32_t *right, const uint32_t *modulus,
                   int32_t wordSize);

void SM9_BN_GetInvMont(uint32_t *result, uint32_t *value, uint32_t *modulus, uint32_t montConst, uint32_t *rSquared,
                       int32_t wordSize);

void SM9_BN_MontMul(uint32_t *result, const uint32_t *left, const uint32_t *right, const uint32_t *modulus,
                    uint32_t montConst, int32_t wordSize);

void SM9_BN_GetResidue(uint32_t *value, const uint32_t *modulus, int32_t wordSize);

int32_t SM9_BN_ByteToBN(const uint8_t *input, int32_t byteLen, uint32_t *result, int32_t wordSize);

void SM9_Fp12_Mul(SM9_Fp12 *result, SM9_Fp12 *left, SM9_Fp12 *right);

void SM9_Fp12_Exp(SM9_Fp12 *result, SM9_Fp12 *base, uint32_t *exponent);

void SM9_EcpA_ToJ(SM9_EcpJ *result, SM9_EcpA *point);

void SM9_EcpJ_ToA(SM9_EcpA *result, SM9_EcpJ *point);

void SM9_EcpJ_AddA(SM9_EcpJ *result, SM9_EcpJ *projectivePoint, SM9_EcpA *affinePoint);

void SM9_Ecp_KP(SM9_EcpA *result, SM9_EcpA *basePoint, uint32_t *scalar);

void SM9_FpEcp_KPAddAToA(SM9_EcpA *result, SM9_EcpA *basePoint, uint32_t *scalar, SM9_EcpA *addend,
                         SM9_SysPara *params);

void SM9_EcpA_ReadBytes(SM9_EcpA *dst, const uint8_t *src);

int32_t SM9_EcpA_Check(SM9_EcpA *point);

int32_t SM9_EcpA_ValidateBytes(const uint8_t *src);

void SM9_Ecp2A_ReadBytes(SM9_Ecp2A *dst, const uint8_t *src);

void SM9_Ecp2A_ToJ(SM9_Ecp2J *result, SM9_Ecp2A *point);

void SM9_Ecp2J_ToA(SM9_Ecp2A *result, SM9_Ecp2J *point);

void SM9_Ecp2J_AddA(SM9_Ecp2J *result, SM9_Ecp2J *projectivePoint, SM9_Ecp2A *affinePoint);

void SM9_Ecp2_KP(SM9_Ecp2A *result, SM9_Ecp2A *basePoint, uint32_t *scalar);

int32_t SM9_Ecp2A_ValidateBytes(const uint8_t *src);

void SM9_Pairing_RAte(SM9_Fp12 *result, SM9_EcpA *g1Point, SM9_Ecp2A *g2Point);

uint32_t SM9_BN_AddInt(uint32_t *result, const uint32_t *value, uint32_t word, int32_t wordSize);

int32_t SM9_BN_ToByte(uint32_t *value, int32_t wordSize, uint8_t *output, int32_t *byteLen);

void SM9_Fp_WriteBytes(uint8_t *dst, uint32_t *src);

int32_t SM9_Hash_H(uint32_t *result, uint8_t tag, const uint8_t *msg, uint32_t msgLen, const uint8_t *suffix,
                   uint32_t suffixLen);

void SM9_Fp12_ReadBytes(SM9_Fp12 *dst, const uint8_t *src);

void SM9_Fp12_WriteBytes(uint8_t *dst, SM9_Fp12 *src);

int32_t SM9_Alg_Pair(uint8_t *result, uint8_t *g1Bytes, uint8_t *g2Bytes);

int32_t SM9_Alg_PairEqual(SM9_EcpA *firstG1, SM9_Ecp2A *firstG2, SM9_EcpA *secondG1, SM9_Ecp2A *secondG2);

void SM9_Ecp2A_WriteBytes(uint8_t *dst, SM9_Ecp2A *src);

void SM9_EcpA_WriteBytes(uint8_t *dst, SM9_EcpA *src);

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif // HITLS_CRYPTO_SM9

#endif /* SM9_LOCAL_H */
