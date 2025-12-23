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
#include <string.h>

int32_t SM9_KeyExchangeInit(SM9_Ctx *ctx, uint8_t *peer_id, uint32_t peer_id_len,
                            int32_t is_initiator, uint8_t *rand, uint8_t *R)
{
    if (!ctx || !peer_id || !R) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!ctx->has_enc_usr || !ctx->has_enc_sys) {
        return SM9_ERR_BAD_INPUT;
    }

    if (rand) {
        memcpy(ctx->keyex_r, rand, SM9_CURVE_MODULE_BYTES);
    } else {
        sm9_rand(ctx->keyex_r, SM9_CURVE_MODULE_BYTES);
    }

    int32_t ret;
    if (is_initiator) {
        ret = SM9_Alg_KeyEx_InitA(
            ctx->user_id, ctx->user_id_len,
            peer_id, peer_id_len,
            ctx->keyex_r, ctx->enc_dek,
            ctx->enc_mpk, ctx->keyex_R);
    } else {
        ret = SM9_Alg_KeyEx_InitB(
            peer_id, peer_id_len,
            ctx->user_id, ctx->user_id_len,
            ctx->keyex_r, ctx->enc_dek,
            ctx->enc_mpk, ctx->keyex_R);
    }

    if (ret == SM9_OK) {
        memcpy(R, ctx->keyex_R, SM9_KEYEX_RA_BYTES);
    }

    return ret;
}

int32_t SM9_KeyExchangeConfirm(SM9_Ctx *ctx, uint8_t *peer_id, uint32_t peer_id_len,
                               int32_t is_initiator, uint8_t *peer_R, uint32_t klen,
                               uint8_t *shared_key, uint8_t *confirm_value)
{
    if (!ctx || !peer_id || !peer_R || !shared_key || !confirm_value) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!ctx->has_enc_usr || !ctx->has_enc_sys) {
        return SM9_ERR_BAD_INPUT;
    }

    if (is_initiator) {
        return SM9_Alg_KeyEx_ConfirmA(
            ctx->user_id, ctx->user_id_len,
            peer_id, peer_id_len,
            ctx->keyex_r, ctx->keyex_R, peer_R,
            ctx->enc_dek, ctx->enc_mpk,
            klen, shared_key, confirm_value);
    } else {
        return SM9_Alg_KeyEx_ConfirmB(
            peer_id, peer_id_len,
            ctx->user_id, ctx->user_id_len,
            ctx->keyex_r, peer_R, ctx->keyex_R,
            ctx->enc_dek, ctx->enc_mpk,
            klen, shared_key, confirm_value);
    }
}

int32_t SM9_KeyExchangeVerify(SM9_Ctx *ctx, uint8_t *peer_id, uint32_t peer_id_len,
                              int32_t is_initiator, uint8_t *peer_R, uint8_t *peer_confirm)
{
    if (!ctx || !peer_id || !peer_R || !peer_confirm) {
        return SM9_ERR_BAD_INPUT;
    }

    if (!ctx->has_enc_usr || !ctx->has_enc_sys) {
        return SM9_ERR_BAD_INPUT;
    }

    if (is_initiator) {
        return SM9_Alg_KeyEx_VerifySB(
            ctx->user_id, ctx->user_id_len,
            peer_id, peer_id_len,
            ctx->keyex_r, ctx->keyex_R, peer_R,
            ctx->enc_dek, ctx->enc_mpk,
            peer_confirm);
    } else {
        return SM9_Alg_KeyEx_VerifySA(
            peer_id, peer_id_len,
            ctx->user_id, ctx->user_id_len,
            ctx->keyex_r, peer_R, ctx->keyex_R,
            ctx->enc_dek, ctx->enc_mpk,
            peer_confirm);
    }
}

#endif // HITLS_CRYPTO_SM9
