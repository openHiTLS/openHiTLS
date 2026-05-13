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
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t sm9_rand(uint8_t *p, uint32_t len);

/**
 * @brief Check if key is in valid range [1, N-1]
 * @param key Key bytes (big-endian)
 * @param len Key length in bytes (must be SM9_CURVE_MODULE_BYTES)
 * @return CRYPT_SUCCESS if valid, error code otherwise
 */
void SM9_ModifyKeyRange(uint8_t *key);

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

#define SM9_ENC_OVERHEAD_BYTES      (3*SM9_CURVE_MODULE_BYTES)

#define SM9_OPT_DM_MODE0            0x00
#define SM9_OPT_DM_MODE1            0x04
#define SM9_OPT_DM_MODE2            0x02
#define SM9_OPT_DM_MODE3            0x06


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

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9
#endif /* __HEADER_SM9_Alg_H__ */
