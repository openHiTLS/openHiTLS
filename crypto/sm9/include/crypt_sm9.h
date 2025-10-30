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
    unsigned char sig_msk[SM9_SIG_SYS_PRIKEY_BYTES];
    unsigned char sig_mpk[SM9_SIG_SYS_PUBKEY_BYTES];
    unsigned char sig_dsk[SM9_SIG_USR_PRIKEY_BYTES];
    unsigned char sig_g[12 * SM9_CURVE_MODULE_BYTES];

    unsigned char enc_msk[SM9_ENC_SYS_PRIKEY_BYTES];
    unsigned char enc_mpk[SM9_ENC_SYS_PUBKEY_BYTES];
    unsigned char enc_dek[SM9_ENC_USR_PRIKEY_BYTES];
    unsigned char enc_g[12 * SM9_CURVE_MODULE_BYTES];

    unsigned char user_id[256];
    unsigned int  user_id_len;

    unsigned char keyex_r[SM9_CURVE_MODULE_BYTES];
    unsigned char keyex_R[SM9_KEYEX_RA_BYTES];

    unsigned int has_sig_sys : 1;
    unsigned int has_sig_usr : 1;
    unsigned int has_sig_g   : 1;
    unsigned int has_enc_sys : 1;
    unsigned int has_enc_usr : 1;
    unsigned int has_enc_g   : 1;
};

typedef struct SM9_Ctx_st SM9_Ctx;

SM9_API SM9_Ctx* SM9_NewCtx(void);
SM9_API void SM9_FreeCtx(SM9_Ctx *ctx);
SM9_API void SM9_ResetCtx(SM9_Ctx *ctx);

SM9_API int SM9_SetSignMasterKey(SM9_Ctx *ctx, unsigned char *msk);
SM9_API int SM9_GenSignUserKey(SM9_Ctx *ctx, const unsigned char *user_id, unsigned int id_len);
SM9_API int SM9_SetSignUserKey(SM9_Ctx *ctx, unsigned char *user_id, unsigned int id_len, unsigned char *dsk);

SM9_API int SM9_SignCtx(const SM9_Ctx *ctx, const unsigned char *msg, unsigned int mlen,
                        unsigned char *rand, unsigned char *sign);
SM9_API int SM9_VerifyCtx(const SM9_Ctx *ctx, const unsigned char *user_id, unsigned int id_len,
                          const unsigned char *msg, unsigned int mlen, const unsigned char *sign);

SM9_API int SM9_SetEncMasterKey(SM9_Ctx *ctx, unsigned char *msk);
SM9_API int SM9_GenEncUserKey(SM9_Ctx *ctx, const unsigned char *user_id, unsigned int id_len);
SM9_API int SM9_SetEncUserKey(SM9_Ctx *ctx, unsigned char *user_id, unsigned int id_len, unsigned char *dek);

SM9_API int SM9_EncryptCtx(const SM9_Ctx *ctx, const unsigned char *user_id, unsigned int id_len,
                           const unsigned char *msg, unsigned int mlen,
                           unsigned char *rand, unsigned char *cipher, unsigned int *clen);
SM9_API int SM9_DecryptCtx(const SM9_Ctx *ctx, const unsigned char *cipher, unsigned int clen,
                           unsigned char *msg, unsigned int *mlen);

SM9_API int SM9_KeyExchangeInit(SM9_Ctx *ctx, unsigned char *peer_id, unsigned int peer_id_len,
                                int is_initiator, unsigned char *rand, unsigned char *R);
SM9_API int SM9_KeyExchangeConfirm(SM9_Ctx *ctx, unsigned char *peer_id, unsigned int peer_id_len,
                                   int is_initiator, unsigned char *peer_R, unsigned int klen,
                                   unsigned char *shared_key, unsigned char *confirm_value);
SM9_API int SM9_KeyExchangeVerify(SM9_Ctx *ctx, unsigned char *peer_id, unsigned int peer_id_len,
                                  int is_initiator, unsigned char *peer_R, unsigned char *peer_confirm);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9
#endif /* __CRYPT_SM9_H__ */
