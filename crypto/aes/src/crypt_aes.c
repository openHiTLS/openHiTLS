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
#ifdef HITLS_CRYPTO_AES

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#ifdef HITLS_CRYPTO_AES_PRECALC_TABLES
#include "crypt_aes_tbox.h"
#else
#include "crypt_aes_sbox.h"
#endif
#include "crypt_aes.h"

void SetEncryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key)
{
    ctx->rounds = 10;  // 10 rounds
#ifdef HITLS_CRYPTO_AES_PRECALC_TABLES
    SetAesKeyExpansionTbox(ctx, CRYPT_AES_128, key, true);
#else
    SetAesKeyExpansionSbox(ctx, CRYPT_AES_128, key);
#endif
}

void SetEncryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key)
{
    ctx->rounds = 12;  // 12 rounds
#ifdef HITLS_CRYPTO_AES_PRECALC_TABLES
    SetAesKeyExpansionTbox(ctx, CRYPT_AES_192, key, true);
#else
    SetAesKeyExpansionSbox(ctx, CRYPT_AES_192, key);
#endif
}

void SetEncryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key)
{
    ctx->rounds = 14;  // 14 rounds
#ifdef HITLS_CRYPTO_AES_PRECALC_TABLES
    SetAesKeyExpansionTbox(ctx, CRYPT_AES_256, key, true);
#else
    SetAesKeyExpansionSbox(ctx, CRYPT_AES_256, key);
#endif
}

void SetDecryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key)
{
    ctx->rounds = 10;  // 10 rounds
#ifdef HITLS_CRYPTO_AES_PRECALC_TABLES
    SetAesKeyExpansionTbox(ctx, CRYPT_AES_128, key, false);
#else
    SetAesKeyExpansionSbox(ctx, CRYPT_AES_128, key);
#endif
}

void SetDecryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key)
{
    ctx->rounds = 12;  // 12 rounds
#ifdef HITLS_CRYPTO_AES_PRECALC_TABLES
    SetAesKeyExpansionTbox(ctx, CRYPT_AES_192, key, false);
#else
    SetAesKeyExpansionSbox(ctx, CRYPT_AES_192, key);
#endif
}

void SetDecryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key)
{
    ctx->rounds = 14;  // 14 rounds
#ifdef HITLS_CRYPTO_AES_PRECALC_TABLES
    SetAesKeyExpansionTbox(ctx, CRYPT_AES_256, key, false);
#else
    SetAesKeyExpansionSbox(ctx, CRYPT_AES_256, key);
#endif
}

int32_t CRYPT_AES_Encrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
#ifdef HITLS_CRYPTO_AES_PRECALC_TABLES
    CRYPT_AES_EncryptTbox(ctx, in, out, len);
#else
    CRYPT_AES_EncryptSbox(ctx, in, out, len);
#endif
    return CRYPT_SUCCESS;
}

int32_t CRYPT_AES_Decrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
#ifdef HITLS_CRYPTO_AES_PRECALC_TABLES
    CRYPT_AES_DecryptTbox(ctx, in, out, len);
#else
    CRYPT_AES_DecryptSbox(ctx, in, out, len);
#endif
    return CRYPT_SUCCESS;
}
#endif /* HITLS_CRYPTO_AES */
