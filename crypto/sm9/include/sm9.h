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

/*=======================SM3 Adaptation Layer Functions======================*/

// SM3 hash functions
void SM9_Hash_Init(SM9_Hash_Ctx *ctx);
void SM9_Hash_Update(SM9_Hash_Ctx *ctx, const uint8_t *data, uint32_t len);
void SM9_Hash_Final(SM9_Hash_Ctx *ctx, uint8_t *digest);
void SM9_Hash_Data(const uint8_t *data, uint32_t len, uint8_t *digest);

#define SM3_Alg_Data SM9_Hash_Data

/**
 * @brief Generate random bytes for SM9 algorithms
 * @param p Output buffer for random bytes
 * @param len Number of random bytes to generate
 */
void sm9_rand(uint8_t *p, uint32_t len);

/*----------------------SM9 algorithem length define--------------------------*/
#define SM9_CURVE_MODULE_BYTES        32

#define SM9_MODE_NUL                0
#define SM9_MODE_SIG                1
#define SM9_MODE_ENC                3

#define SM9_SIG_SYS_PRIKEY_BYTES    SM9_CURVE_MODULE_BYTES
#define SM9_SIG_SYS_PUBKEY_BYTES    (4*SM9_CURVE_MODULE_BYTES)
#define SM9_SIG_USR_PRIKEY_BYTES    (2*SM9_CURVE_MODULE_BYTES)

#define SM9_ENC_SYS_PRIKEY_BYTES    SM9_CURVE_MODULE_BYTES
#define SM9_ENC_SYS_PUBKEY_BYTES    (2*SM9_CURVE_MODULE_BYTES)
#define SM9_ENC_USR_PRIKEY_BYTES    (4*SM9_CURVE_MODULE_BYTES)

#define SM9_SIGNATURE_BYTES         (3*SM9_CURVE_MODULE_BYTES)

#define SM9_KEYEX_RA_BYTES          (2*SM9_CURVE_MODULE_BYTES)
#define SM9_KEYEX_RB_BYTES          (2*SM9_CURVE_MODULE_BYTES)

#define SM9_OPT_DM_MODE0            0x00
#define SM9_OPT_DM_MODE1            0x04
#define SM9_OPT_DM_MODE2            0x02
#define SM9_OPT_DM_MODE3            0x06

/*----------------------SM9 algorithem error code-----------------------------*/
#define SM9_OK                      0             // OK
#define SM9_ERR_ID_UNUSEABLE        0x3F01        // Current ID cannot use
#define SM9_ERR_RND_UNUSEABLE       0x3F02        // Current rand number cannot use
#define SM9_ERR_BAD_INPUT           0x3F03
#define SM9_ERR_VERIFY_FAILED       0x3F04
#define SM9_ERR_INVALID_POINT       0x3F05
#define SM9_ERR_MAC_FAILED          0x3F06
#define SM9_ERR_INPUT               0x3F07
#define SM9_ERR_MODE_UNUSEABLE      0x3F0E
#define SM9_ERR_NODEINFO            0x3F0A
#define SM9_ERR_UNSUPPORT           0x3F0F

/*============================================================================*/

#ifdef  __cplusplus
extern "C" {
#endif

int32_t SM9_Alg_GetVersion();

int32_t SM9_Alg_Pair(
    uint8_t *g,
    uint8_t *p1,
    uint8_t *p2);

int32_t SM9_Get_Sig_G(uint8_t *g, uint8_t *mpk);

int32_t SM9_Get_Enc_G(uint8_t *g, uint8_t *mpk);

int32_t SM9_Alg_MSKG(
    uint8_t *ks,
    uint8_t *mpk);

int32_t SM9_Alg_USKG(
    const uint8_t *id,
    uint32_t ilen,
    uint8_t *ks,
    uint8_t *ds);

int32_t SM9_Alg_Sign(
    const uint8_t *msg,
    uint32_t mlen,
    const uint8_t *ds,
    uint8_t *r,
    const uint8_t *g,
    const uint8_t *mpk,
    uint8_t *sign);

int32_t SM9_Sign(
    uint32_t opt,
    const uint8_t *msg,
    uint32_t mlen,
    const uint8_t *ds,
    uint8_t *r,
    const uint8_t *g,
    const uint8_t *mpk,
    uint8_t *sign,
    uint32_t *slen);

int32_t SM9_Alg_Verify(
    const uint8_t *msg,
    uint32_t mlen,
    const uint8_t *id,
    uint32_t ilen,
    const uint8_t *g,
    const uint8_t *mpk,
    const uint8_t *sign);

int32_t SM9_Verify(
    uint32_t opt,
    const uint8_t *msg,
    uint32_t mlen,
    const uint8_t *id,
    uint32_t ilen,
    const uint8_t *g,
    const uint8_t *mpk,
    const uint8_t *sign,
    uint8_t slen);

int32_t SM9_Alg_MEKG(
    uint8_t *ke,
    uint8_t *mpk);

int32_t SM9_Alg_UEKG(
    const uint8_t *id,
    uint32_t ilen,
    uint8_t *ke,
    uint8_t *de);

int32_t SM9_Alg_Enc(
    const uint8_t *msg,
    uint32_t mlen,
    const uint8_t *id,
    uint32_t ilen,
    uint8_t *r,
    const uint8_t *g,
    const uint8_t *mpk,
    uint8_t *enc,
    uint32_t *elen);

int32_t SM9_Alg_Dec(
    const uint8_t *enc,
    uint32_t elen,
    const uint8_t *de,
    const uint8_t *id,
    uint32_t ilen,
    uint8_t *msg,
    uint32_t *mlen);

int32_t SM9_Alg_KeyEx_InitA(
    uint8_t *ida,
    uint32_t ilen_a,
    uint8_t *idb,
    uint32_t ilen_b,
    uint8_t *ra,
    uint8_t *da,
    uint8_t *mpk,
    uint8_t *RA);

int32_t SM9_Alg_KeyEx_InitB(
    uint8_t *ida,
    uint32_t ilen_a,
    uint8_t *idb,
    uint32_t ilen_b,
    uint8_t *rb,
    uint8_t *db,
    uint8_t *mpk,
    uint8_t *RB);

// User A confirms and generates shared key SK_A and confirmation value SA
// This function only generates, does not verify SB
int32_t SM9_Alg_KeyEx_ConfirmA(
    uint8_t *ida,
    uint32_t ilen_a,
    uint8_t *idb,
    uint32_t ilen_b,
    uint8_t *ra,
    uint8_t *RA,
    uint8_t *RB,
    uint8_t *da,
    uint8_t *mpk,
    uint32_t klen,
    uint8_t *SK,   // Output: Shared key
    uint8_t *SA);  // Output: Confirmation value SA for User A

// User B confirms and generates shared key SK_B and confirmation value SB
// This function only generates, does not verify SA
int32_t SM9_Alg_KeyEx_ConfirmB(
    uint8_t *ida,
    uint32_t ilen_a,
    uint8_t *idb,
    uint32_t ilen_b,
    uint8_t *rb,
    uint8_t *RA,
    uint8_t *RB,
    uint8_t *db,
    uint8_t *mpk,
    uint32_t klen,
    uint8_t *SK,   // Output: Shared key
    uint8_t *SB);  // Output: Confirmation value SB for User B

// User B verifies SA received from User A (standalone verification function)
int32_t SM9_Alg_KeyEx_VerifySA(
    uint8_t *ida,
    uint32_t ilen_a,
    uint8_t *idb,
    uint32_t ilen_b,
    uint8_t *rb,
    uint8_t *RA,
    uint8_t *RB,
    uint8_t *db,
    uint8_t *mpk,
    uint8_t *SA);  // Input: SA received from User A

// User A verifies SB received from User B (standalone verification function)
int32_t SM9_Alg_KeyEx_VerifySB(
    uint8_t *ida,
    uint32_t ilen_a,
    uint8_t *idb,
    uint32_t ilen_b,
    uint8_t *ra,
    uint8_t *RA,
    uint8_t *RB,
    uint8_t *da,
    uint8_t *mpk,
    uint8_t *SB);  // Input: SB received from User B

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9
#endif /* __HEADER_SM9_Alg_H__ */
