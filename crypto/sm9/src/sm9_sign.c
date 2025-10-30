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
#include "sm9_curve.h"
#include "sm9_pairing.h"
#include "sm9_fp.h"
#include <stdlib.h>
#include <string.h>

/*============================================================================*/

SM9_API SM9_Ctx* SM9_NewCtx(void)
{
    SM9_Ctx *ctx = (SM9_Ctx*)malloc(sizeof(SM9_Ctx));
    if (ctx) {
        memset(ctx, 0, sizeof(SM9_Ctx));
    }
    return ctx;
}

SM9_API void SM9_FreeCtx(SM9_Ctx *ctx)
{
    if (ctx) {
        memset(ctx, 0, sizeof(SM9_Ctx));
        free(ctx);
    }
}

SM9_API void SM9_ResetCtx(SM9_Ctx *ctx)
{
    if (ctx) {
        memset(ctx, 0, sizeof(SM9_Ctx));
    }
}

/*============================================================================*/

SM9_API int SM9_SetSignMasterKey(SM9_Ctx *ctx, unsigned char *msk)
{
    if (!ctx || !msk) {
        return SM9_ERR_BAD_INPUT;
    }

    memcpy(ctx->sig_msk, msk, SM9_SIG_SYS_PRIKEY_BYTES);

    int ret = SM9_Alg_MSKG(ctx->sig_msk, ctx->sig_mpk);
    if (ret != SM9_OK) {
        return ret;
    }

    ret = SM9_Get_Sig_G(ctx->sig_g, ctx->sig_mpk);
    if (ret != SM9_OK) {
        return ret;
    }

    ctx->has_sig_sys = 1;
    ctx->has_sig_g = 1;

    return SM9_OK;
}

SM9_API int SM9_GenSignUserKey(SM9_Ctx *ctx, const unsigned char *user_id, unsigned int id_len)
{
    if (!ctx || !user_id || id_len == 0 || id_len > 256) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!ctx->has_sig_sys) {
        return SM9_ERR_BAD_INPUT;
    }

    memcpy(ctx->user_id, user_id, id_len);
    ctx->user_id_len = id_len;

    int ret = SM9_Alg_USKG(user_id, id_len, ctx->sig_msk, ctx->sig_dsk);
    if (ret != SM9_OK) {
        return ret;
    }

    ctx->has_sig_usr = 1;

    return SM9_OK;
}

SM9_API int SM9_SetSignUserKey(SM9_Ctx *ctx, unsigned char *user_id, unsigned int id_len, unsigned char *dsk)
{
    if (!ctx || !user_id || id_len == 0 || id_len > 256 || !dsk) {
        return SM9_ERR_BAD_INPUT;
    }

    memcpy(ctx->user_id, user_id, id_len);
    ctx->user_id_len = id_len;

    memcpy(ctx->sig_dsk, dsk, SM9_SIG_USR_PRIKEY_BYTES);

    ctx->has_sig_usr = 1;

    return SM9_OK;
}

/*============================================================================*/

SM9_API int SM9_SignCtx(const SM9_Ctx *ctx, const unsigned char *msg, unsigned int mlen,
                        unsigned char *rand, unsigned char *sign)
{
    static unsigned char default_rand[32];

    if (!ctx || !msg || !sign) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!ctx->has_sig_usr) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!rand) {
        sm9_rand(default_rand, sizeof(default_rand));
        rand = default_rand;
    }

    const unsigned char *g_ptr = ctx->has_sig_g ? ctx->sig_g : NULL;
    const unsigned char *mpk_ptr = ctx->has_sig_sys ? ctx->sig_mpk : NULL;

    return SM9_Alg_Sign(msg, mlen, ctx->sig_dsk, rand, g_ptr, mpk_ptr, sign);
}

SM9_API int SM9_VerifyCtx(const SM9_Ctx *ctx, const unsigned char *user_id, unsigned int id_len,
                          const unsigned char *msg, unsigned int mlen, const unsigned char *sign)
{
    if (!ctx || !user_id || !msg || !sign) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!ctx->has_sig_sys) {
        return SM9_ERR_BAD_INPUT;
    }

    const unsigned char *g_ptr = ctx->has_sig_g ? ctx->sig_g : NULL;

    return SM9_Alg_Verify(msg, mlen, user_id, id_len, g_ptr, ctx->sig_mpk, sign);
}

#endif // HITLS_CRYPTO_SM9
