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

#ifndef __CRYPT_SM9_H__
#define __CRYPT_SM9_H__

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include "sm9.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * @brief SM9 Context Structure
 *
 * Encapsulates all key materials and state information required for
 * signature, encryption, and key exchange operations.
 */
struct SM9_Ctx_st {
    uint8_t sig_msk[SM9_SIG_SYS_PRIKEY_BYTES];
    uint8_t sig_mpk[SM9_SIG_SYS_PUBKEY_BYTES];
    uint8_t sig_dsk[SM9_SIG_USR_PRIKEY_BYTES];
    uint8_t sig_g[12 * SM9_CURVE_MODULE_BYTES];

    uint8_t enc_msk[SM9_ENC_SYS_PRIKEY_BYTES];
    uint8_t enc_mpk[SM9_ENC_SYS_PUBKEY_BYTES];
    uint8_t enc_dek[SM9_ENC_USR_PRIKEY_BYTES];
    uint8_t enc_g[12 * SM9_CURVE_MODULE_BYTES];

    uint8_t user_id[256];
    uint32_t user_id_len;

    uint8_t keyex_r[SM9_CURVE_MODULE_BYTES];
    uint8_t keyex_R[SM9_KEYEX_RA_BYTES];

    uint32_t has_sig_sys : 1;
    uint32_t has_sig_usr : 1;
    uint32_t has_sig_g   : 1;
    uint32_t has_enc_sys : 1;
    uint32_t has_enc_usr : 1;
    uint32_t has_enc_g   : 1;
};

typedef struct SM9_Ctx_st SM9_Ctx;

void SM9_ResetCtx(SM9_Ctx *ctx);
SM9_Ctx* SM9_NewCtx(void);
void SM9_FreeCtx(SM9_Ctx *ctx);

int32_t SM9_SetSignMasterKey(SM9_Ctx *ctx, uint8_t *msk);
int32_t SM9_GenSignUserKey(SM9_Ctx *ctx, const uint8_t *user_id, uint32_t id_len);
int32_t SM9_SetSignUserKey(SM9_Ctx *ctx, uint8_t *user_id, uint32_t id_len, uint8_t *dsk);

int32_t SM9_SignCtx(const SM9_Ctx *ctx, const uint8_t *msg, uint32_t mlen, uint8_t *rand, uint8_t *sign);
int32_t SM9_VerifyCtx(const SM9_Ctx *ctx, const uint8_t *user_id, uint32_t id_len,
                      const uint8_t *msg, uint32_t mlen, const uint8_t *sign);

int32_t SM9_SetEncMasterKey(SM9_Ctx *ctx, uint8_t *msk);
int32_t SM9_GenEncUserKey(SM9_Ctx *ctx, const uint8_t *user_id, uint32_t id_len);
int32_t SM9_SetEncUserKey(SM9_Ctx *ctx, uint8_t *user_id, uint32_t id_len, uint8_t *dek);

int32_t SM9_EncryptCtx(const SM9_Ctx *ctx, const uint8_t *user_id, uint32_t id_len,
                       const uint8_t *msg, uint32_t mlen, uint8_t *rand, uint8_t *cipher, uint32_t *clen);
int32_t SM9_DecryptCtx(const SM9_Ctx *ctx, const uint8_t *cipher, uint32_t clen, uint8_t *msg, uint32_t *mlen);

int32_t SM9_KeyExchangeInit(SM9_Ctx *ctx, uint8_t *peer_id, uint32_t peer_id_len,
                            int32_t is_initiator, uint8_t *rand, uint8_t *R);
int32_t SM9_KeyExchangeConfirm(SM9_Ctx *ctx, uint8_t *peer_id, uint32_t peer_id_len,
                               int32_t is_initiator, uint8_t *peer_R, uint32_t klen,
                               uint8_t *shared_key, uint8_t *confirm_value);
int32_t SM9_KeyExchangeVerify(SM9_Ctx *ctx, uint8_t *peer_id, uint32_t peer_id_len,
                              int32_t is_initiator, uint8_t *peer_R, uint8_t *peer_confirm);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9
#endif /* __CRYPT_SM9_H__ */
