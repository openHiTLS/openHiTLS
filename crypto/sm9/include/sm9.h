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

#ifndef __HEADER_SM9_ALG_H__
#define __HEADER_SM9_ALG_H__

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include <stdint.h>
#include "sm9_curve.h"

/*==================================DEFINES===================================*/

#ifdef _MSC_VER
#define SM9_API        __declspec(dllexport)
#else
#define SM9_API        __attribute__ ((visibility("default")))
#endif

/*=======================SM3 Adaptation Layer Functions======================*/

// SM3 hash functions
void SM9_Hash_Init(SM9_Hash_Ctx *ctx);
void SM9_Hash_Update(SM9_Hash_Ctx *ctx, const unsigned char *data, unsigned int len);
void SM9_Hash_Final(SM9_Hash_Ctx *ctx, unsigned char *digest);
void SM9_Hash_Final_and_Xor(SM9_Hash_Ctx *ctx, unsigned char *pbXor, unsigned char *pbMsg);
void SM9_Hash_Data(const unsigned char *data, unsigned int len, unsigned char *digest);

#define SM3_Alg_Data SM9_Hash_Data

/**
 * @brief Generate random bytes for SM9 algorithms
 * @param p Output buffer for random bytes
 * @param len Number of random bytes to generate
 */
void sm9_rand(unsigned char *p, int len);

/*----------------------SM9 algorithem length define--------------------------*/
#define    SM9_CURVE_MODULE_BYTES        32

#define SM9_MODE_NUL                0
#define SM9_MODE_SIG                1
#define SM9_MODE_ENC                3

#define    SM9_SIG_SYS_PRIKEY_BYTES    SM9_CURVE_MODULE_BYTES
#define    SM9_SIG_SYS_PUBKEY_BYTES    (4*SM9_CURVE_MODULE_BYTES)
#define    SM9_SIG_USR_PRIKEY_BYTES    (2*SM9_CURVE_MODULE_BYTES)

#define    SM9_ENC_SYS_PRIKEY_BYTES    SM9_CURVE_MODULE_BYTES
#define    SM9_ENC_SYS_PUBKEY_BYTES    (2*SM9_CURVE_MODULE_BYTES)
#define    SM9_ENC_USR_PRIKEY_BYTES    (4*SM9_CURVE_MODULE_BYTES)

#define SM9_SIGNATURE_BYTES            (3*SM9_CURVE_MODULE_BYTES)

#define SM9_KEYEX_RA_BYTES            (2*SM9_CURVE_MODULE_BYTES)
#define SM9_KEYEX_RB_BYTES            (2*SM9_CURVE_MODULE_BYTES)

#define SM9_OPT_DM_MODE0                0x00
#define SM9_OPT_DM_MODE1                0x04
#define SM9_OPT_DM_MODE2                0x02
#define SM9_OPT_DM_MODE3                0x06

/*----------------------SM9 algorithem error code-----------------------------*/
#define    SM9_OK                        0            //OK
#define    SM9_ERR_ID_UNUSEABLE        0x3F01        //Current ID cannot use
#define    SM9_ERR_RND_UNUSEABLE        0x3F02        //Current rand number cannot use
#define SM9_ERR_BAD_INPUT            0x3F03
#define SM9_ERR_VERIFY_FAILED        0x3F04
#define    SM9_ERR_INVALID_POINT        0x3F05
#define    SM9_ERR_MAC_FAILED            0x3F06
#define SM9_ERR_INPUT                0x3F07
#define SM9_ERR_MODE_UNUSEABLE        0x3F0E
#define SM9_ERR_NODEINFO            0x3F0A
#define SM9_ERR_UNSUPPORT            0x3F0F

/*============================================================================*/

#ifdef  __cplusplus
extern "C" {
#endif

SM9_API int SM9_Alg_GetVersion();

SM9_API int SM9_Alg_Pair(
    unsigned char *g,
    unsigned char *p1,
    unsigned char *p2);

SM9_API int SM9_Get_Sig_G(unsigned char *g, unsigned char *mpk);

SM9_API int SM9_Get_Enc_G(unsigned char *g, unsigned char *mpk);

SM9_API int SM9_Alg_MSKG(
    unsigned char *ks,
    unsigned char *mpk);

SM9_API int SM9_Alg_USKG(
    const unsigned char *id,
    unsigned int  ilen,
    unsigned char *ks,
    unsigned char *ds);

SM9_API int SM9_Alg_Sign(
    const unsigned char *msg,
    unsigned int  mlen,
    const unsigned char *ds,
    unsigned char *r,
    const unsigned char *g,
    const unsigned char *mpk,
    unsigned char *sign);

SM9_API int SM9_Sign(
    unsigned int  opt,
    const unsigned char *msg,
    unsigned int  mlen,
    const unsigned char *ds,
    unsigned char *r,
    const unsigned char *g,
    const unsigned char *mpk,
    unsigned char *sign,
    unsigned int  *slen);

SM9_API int SM9_Alg_Verify(
    const unsigned char *msg,
    unsigned int  mlen,
    const unsigned char *id,
    unsigned int  ilen,
    const unsigned char *g,
    const unsigned char *mpk,
    const unsigned char *sign);

SM9_API int SM9_Verify(
    unsigned int  opt,
    const unsigned char *msg,
    unsigned int  mlen,
    const unsigned char *id,
    unsigned int  ilen,
    const unsigned char *g,
    const unsigned char *mpk,
    const unsigned char *sign,
    unsigned char slen);

SM9_API int SM9_Alg_MEKG(
    unsigned char *ke,
    unsigned char *mpk);

SM9_API int SM9_Alg_UEKG(
    const unsigned char *id,
    unsigned int  ilen,
    unsigned char *ke,
    unsigned char *de);

SM9_API int SM9_Alg_Enc(
    const unsigned char *msg,
    unsigned int  mlen,
    const unsigned char *id,
    unsigned int  ilen,
    unsigned char *r,
    const unsigned char *g,
    const unsigned char *mpk,
    unsigned char *enc,
    unsigned int  *elen);

SM9_API int SM9_Alg_Dec(
    const unsigned char *enc,
    unsigned int  elen,
    const unsigned char *de,
    const unsigned char *id,
    unsigned int ilen,
    unsigned char *msg,
    unsigned int *mlen);

SM9_API int SM9_Alg_KeyEx_InitA(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *ra,
    unsigned char *da,
    unsigned char *mpk,
    unsigned char *RA);

SM9_API int SM9_Alg_KeyEx_InitB(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *rb,
    unsigned char *db,
    unsigned char *mpk,
    unsigned char *RB);

// User A confirms and generates shared key SK_A and confirmation value SA
// This function only generates, does not verify SB
SM9_API int SM9_Alg_KeyEx_ConfirmA(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *ra,
    unsigned char *RA,
    unsigned char *RB,
    unsigned char *da,
    unsigned char *mpk,
    unsigned int  klen,
    unsigned char *SK,   // Output: Shared key
    unsigned char *SA);  // Output: Confirmation value SA for User A

// User B confirms and generates shared key SK_B and confirmation value SB
// This function only generates, does not verify SA
SM9_API int SM9_Alg_KeyEx_ConfirmB(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *rb,
    unsigned char *RA,
    unsigned char *RB,
    unsigned char *db,
    unsigned char *mpk,
    unsigned int  klen,
    unsigned char *SK,   // Output: Shared key
    unsigned char *SB);  // Output: Confirmation value SB for User B

// User B verifies SA received from User A (standalone verification function)
SM9_API int SM9_Alg_KeyEx_VerifySA(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *rb,
    unsigned char *RA,
    unsigned char *RB,
    unsigned char *db,
    unsigned char *mpk,
    unsigned char *SA);  // Input: SA received from User A

// User A verifies SB received from User B (standalone verification function)
SM9_API int SM9_Alg_KeyEx_VerifySB(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *ra,
    unsigned char *RA,
    unsigned char *RB,
    unsigned char *da,
    unsigned char *mpk,
    unsigned char *SB);  // Input: SB received from User B

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9
#endif /* __HEADER_SM9_Alg_H__ */
