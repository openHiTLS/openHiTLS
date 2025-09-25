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
#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include "crypt_eal_implprovider.h"
#include "crypt_rsa.h"
#include "crypt_sm2.h"
#include "crypt_paillier.h"
#include "crypt_elgamal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_iso_selftest.h"
#include "crypt_iso_provderimpl.h"

#define PKEY_CIPHER_ENCRYPT_FUNC(name)                                                                              \
    static int32_t CRYPT_##name##_EncryptWrapper(CRYPT_Iso_Pkey_Ctx *ctx, const uint8_t *data, uint32_t dataLen,    \
        uint8_t *out, uint32_t *outLen)                                                                             \
    {                                                                                                               \
        if (ctx == NULL) {                                                                                          \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                                   \
            return CRYPT_NULL_INPUT;                                                                                \
        }                                                                                                           \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_ENC, CRYPT_ALGO_PKEY, ctx->algId);                    \
        if (ret != CRYPT_SUCCESS) {                                                                                 \
            return ret;                                                                                             \
        }                                                                                                           \
        return CRYPT_##name##_Encrypt(ctx->ctx, data, dataLen, out, outLen);                                        \
    }

#define PKEY_CIPHER_DECRYPT_FUNC(name)                                                                              \
    static int32_t CRYPT_##name##_DecryptWrapper(CRYPT_Iso_Pkey_Ctx *ctx, const uint8_t *data, uint32_t dataLen,    \
        uint8_t *out, uint32_t *outLen)                                                                             \
    {                                                                                                               \
        if (ctx == NULL) {                                                                                          \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                                   \
            return CRYPT_NULL_INPUT;                                                                                \
        }                                                                                                           \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_DEC, CRYPT_ALGO_PKEY, ctx->algId);                    \
        if (ret != CRYPT_SUCCESS) {                                                                                 \
            return ret;                                                                                             \
        }                                                                                                           \
        return CRYPT_##name##_Decrypt(ctx->ctx, data, dataLen, out, outLen);                                        \
    }

PKEY_CIPHER_ENCRYPT_FUNC(RSA)
PKEY_CIPHER_DECRYPT_FUNC(RSA)

PKEY_CIPHER_ENCRYPT_FUNC(SM2)
PKEY_CIPHER_DECRYPT_FUNC(SM2)

const CRYPT_EAL_Func g_isoAsymCipherRsa[] = {
#ifdef HITLS_CRYPTO_RSA_ENCRYPT
    {CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, (CRYPT_EAL_ImplPkeyEncrypt)CRYPT_RSA_EncryptWrapper},
#endif
#ifdef HITLS_CRYPTO_RSA_DECRYPT
    {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, (CRYPT_EAL_ImplPkeyDecrypt)CRYPT_RSA_DecryptWrapper},
#endif
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_isoAsymCipherSm2[] = {
#ifdef HITLS_CRYPTO_SM2_CRYPT
    {CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, (CRYPT_EAL_ImplPkeyEncrypt)CRYPT_SM2_EncryptWrapper},
    {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, (CRYPT_EAL_ImplPkeyDecrypt)CRYPT_SM2_DecryptWrapper},
#endif
    CRYPT_EAL_FUNC_END
};

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */