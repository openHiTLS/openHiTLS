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

#include "crypt_sm9.h"
#include "sm9.h"
#include <string.h>

/*============================================================================*/

SM9_API int SM9_SetEncMasterKey(SM9_Ctx *ctx, unsigned char *msk)
{
    if (!ctx || !msk) {
        return SM9_ERR_BAD_INPUT;
    }

    memcpy(ctx->enc_msk, msk, SM9_ENC_SYS_PRIKEY_BYTES);

    int ret = SM9_Alg_MEKG(ctx->enc_msk, ctx->enc_mpk);
    if (ret != SM9_OK) {
        return ret;
    }

    ret = SM9_Get_Enc_G(ctx->enc_g, ctx->enc_mpk);
    if (ret != SM9_OK) {
        return ret;
    }

    ctx->has_enc_sys = 1;
    ctx->has_enc_g = 1;

    return SM9_OK;
}

SM9_API int SM9_GenEncUserKey(SM9_Ctx *ctx, const unsigned char *user_id, unsigned int id_len)
{
    if (!ctx || !user_id || id_len == 0 || id_len > 256) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!ctx->has_enc_sys) {
        return SM9_ERR_BAD_INPUT;
    }

    memcpy(ctx->user_id, user_id, id_len);
    ctx->user_id_len = id_len;

    int ret = SM9_Alg_UEKG(user_id, id_len, ctx->enc_msk, ctx->enc_dek);
    if (ret != SM9_OK) {
        return ret;
    }

    ctx->has_enc_usr = 1;

    return SM9_OK;
}

SM9_API int SM9_SetEncUserKey(SM9_Ctx *ctx, unsigned char *user_id, unsigned int id_len, unsigned char *dek)
{
    if (!ctx || !user_id || id_len == 0 || id_len > 256 || !dek) {
        return SM9_ERR_BAD_INPUT;
    }

    memcpy(ctx->user_id, user_id, id_len);
    ctx->user_id_len = id_len;

    memcpy(ctx->enc_dek, dek, SM9_ENC_USR_PRIKEY_BYTES);

    ctx->has_enc_usr = 1;

    return SM9_OK;
}

/*============================================================================*/
/*============================================================================*/

SM9_API int SM9_EncryptCtx(const SM9_Ctx *ctx, const unsigned char *user_id, unsigned int id_len,
                           const unsigned char *msg, unsigned int mlen,
                           unsigned char *rand, unsigned char *cipher, unsigned int *clen)
{
    static unsigned char default_rand[32];

    if (!ctx || !user_id || !msg || !cipher || !clen) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!ctx->has_enc_sys) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!rand) {
        sm9_rand(default_rand, sizeof(default_rand));
        rand = default_rand;
    }

    const unsigned char *g_ptr = ctx->has_enc_g ? ctx->enc_g : NULL;

    return SM9_Alg_Enc(msg, mlen, user_id, id_len, rand, g_ptr, ctx->enc_mpk, cipher, clen);
}

SM9_API int SM9_DecryptCtx(const SM9_Ctx *ctx, const unsigned char *cipher, unsigned int clen,
                           unsigned char *msg, unsigned int *mlen)
{
    if (!ctx || !cipher || !msg || !mlen) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!ctx->has_enc_usr) {
        return SM9_ERR_BAD_INPUT;
    }

    return SM9_Alg_Dec(cipher, clen, ctx->enc_dek, ctx->user_id, ctx->user_id_len, msg, mlen);
}

#endif // HITLS_CRYPTO_SM9
