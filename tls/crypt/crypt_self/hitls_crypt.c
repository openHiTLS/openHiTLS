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
#if defined(HITLS_TLS_FEATURE_PROVIDER) || defined(HITLS_TLS_CALLBACK_CRYPT)
#include <string.h>
#include "securec.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_params.h"
#include "tls_binlog_id.h"
#include "crypt_algid.h"
#include "hitls_crypt_type.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_kdf.h"
#include "crypt_errno.h"
#include "hitls_error.h"
#include "crypt_default.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "config_type.h"
#include "hitls_crypt.h"

#ifndef HITLS_CRYPTO_EAL
#error "Missing definition of HITLS_CRYPTO_EAL"
#endif

#ifdef HITLS_TLS_SUITE_KX_DHE
#define MIN_DH8192_SECBITS 192
#define MIN_DH4096_SECBITS 152
#define MIN_DH3072_SECBITS 128
#define MIN_DH2048_SECBITS 112
#ifdef HITLS_CRYPTO_PKEY
#define MAX_PKEY_PARA_LEN 1024
#endif
#endif // HITLS_TLS_SUITE_KX_DHE


#define CCM_TLS_TAG_LEN 16u
#define CCM8_TLS_TAG_LEN 8u

/* The default user id as specified in GM/T 0009-2012 */
char g_sm2DefaultUserid[] = "1234567812345678";
#ifdef HITLS_TLS_PROTO_TLCP11
#define SM2_DEFAULT_USERID_LEN 16u
#define SM2_PUBKEY_LEN 65
#define SM2_PRVKEY_LEN 33
#endif // HITLS_TLS_PROTO_TLCP11

#ifdef HITLS_CRYPTO_MAC
static uint32_t GetHmacAlgId(HITLS_HashAlgo hashAlgo)
{
    switch (hashAlgo) {
        case HITLS_HASH_SHA_256:
            return CRYPT_MAC_HMAC_SHA256;
        case HITLS_HASH_SHA_384:
            return CRYPT_MAC_HMAC_SHA384;
        case HITLS_HASH_SHA_512:
            return CRYPT_MAC_HMAC_SHA512;
        case HITLS_HASH_MD5:
            return CRYPT_MAC_HMAC_MD5;
        case HITLS_HASH_SHA1:
            return CRYPT_MAC_HMAC_SHA1;
        case HITLS_HASH_SHA_224:
            return CRYPT_MAC_HMAC_SHA224;
        case HITLS_HASH_SM3:
            return CRYPT_MAC_HMAC_SM3;
        default:
            break;
    }
    return CRYPT_MAC_MAX;
}
#endif // HITLS_CRYPTO_MAC

#ifdef HITLS_CRYPTO_CIPHER
static int32_t GetCipherAlgId(HITLS_CipherAlgo cipherAlgo)
{
    switch (cipherAlgo) {
        case HITLS_CIPHER_AES_128_CCM8:
            return CRYPT_CIPHER_AES128_CCM;
        case HITLS_CIPHER_AES_256_CCM8:
            return CRYPT_CIPHER_AES256_CCM;
        default:
            break;
    }
    return cipherAlgo;
}

static bool IsCipherCCM8(HITLS_CipherAlgo cipherAlgo)
{
    switch (cipherAlgo) {
        case HITLS_CIPHER_AES_128_CCM8:
            return true;
        case HITLS_CIPHER_AES_256_CCM8:
            return true;
        default:
            break;
    }
    return false;
}
#endif

#ifdef HITLS_TLS_FEATURE_PROVIDER
static int32_t SetHmacMdAttr(CRYPT_EAL_MacCtx *ctx, const char *attrName)
{
    if (attrName == NULL) {
        return CRYPT_SUCCESS;
    }
    BSL_Param param[] = {
        {.key = CRYPT_PARAM_MD_ATTR, .valueType = BSL_PARAM_TYPE_UTF8_STR,
            .value = (void *)(uintptr_t)attrName, .valueLen = strlen(attrName), .useLen = 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_EAL_MacSetParam(ctx, param);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(ctx);
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17372, "MacSetParam fail");
    }
    return ret;
}
#endif

#ifdef HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES
HITLS_HMAC_Ctx *HITLS_CRYPT_HMAC_Init(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len)
{
#ifdef HITLS_CRYPTO_MAC
    CRYPT_MAC_AlgId id = GetHmacAlgId(hashAlgo);
    if (id == CRYPT_MAC_MAX) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16618, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "hashAlgo err", 0, 0, 0, 0);
        return NULL;
    }
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_ProviderMacNewCtx(libCtx, id, attrName);
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16619, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "MacNewCtx fail", 0, 0, 0, 0);
        return NULL;
    }
#ifdef HITLS_TLS_FEATURE_PROVIDER
    if (SetHmacMdAttr(ctx, attrName) != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17365, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "MacSetParam fail", 0, 0, 0,
            0);
        CRYPT_EAL_MacFreeCtx(ctx);
        return NULL;
    }
#endif /* HITLS_TLS_FEATURE_PROVIDER */

    if (CRYPT_EAL_MacInit(ctx, key, len) != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16620, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "MacInit fail", 0, 0, 0, 0);
        CRYPT_EAL_MacFreeCtx(ctx);
        return NULL;
    }

    return ctx;
#else // HITLS_CRYPTO_MAC
    (void)hashAlgo;
    (void)key;
    (void)len;
    (void)libCtx;
    (void)attrName;
    return NULL;
#endif // HITLS_CRYPTO_MAC
}

int32_t HITLS_CRYPT_HMAC_ReInit(HITLS_HMAC_Ctx *ctx)
{
#ifdef HITLS_CRYPTO_MAC
    return CRYPT_EAL_MacReinit(ctx);
#else
    (void)ctx;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

void HITLS_CRYPT_HMAC_Free(HITLS_HMAC_Ctx *ctx)
{
#ifdef HITLS_CRYPTO_MAC
    CRYPT_EAL_MacFreeCtx(ctx);
#else
    (void)ctx;
#endif
}

int32_t HITLS_CRYPT_HMAC_Update(HITLS_HMAC_Ctx *ctx, const uint8_t *data, uint32_t len)
{
#ifdef HITLS_CRYPTO_MAC
    return CRYPT_EAL_MacUpdate(ctx, data, len);
#else
    (void)ctx;
    (void)data;
    (void)len;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

int32_t HITLS_CRYPT_HMAC_Final(HITLS_HMAC_Ctx *ctx, uint8_t *out, uint32_t *len)
{
#ifdef HITLS_CRYPTO_MAC
    return CRYPT_EAL_MacFinal(ctx, out, len);
#else
    (void)ctx;
    (void)out;
    (void)len;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

#endif /* HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES */

int32_t HITLS_CRYPT_HMAC(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_MAC
    CRYPT_MAC_AlgId id = GetHmacAlgId(hashAlgo);
    if (id == CRYPT_MAC_MAX) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_HMAC, BINLOG_ID16621, "No proper id");
    }
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_ProviderMacNewCtx(libCtx, id, attrName);
    if (ctx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_HMAC, BINLOG_ID16622, "new ctx fail");
    }
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = SetHmacMdAttr(ctx, attrName);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(ctx);
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17373, "MacSetParam fail");
    }
#endif /* HITLS_TLS_FEATURE_PROVIDER */

    ret = CRYPT_EAL_MacInit(ctx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(ctx);
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16623, "mac init fail");
    }

    ret = CRYPT_EAL_MacUpdate(ctx, in, inLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_MacFreeCtx(ctx);
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16624, "MacUpdate fail");
    }

    ret = CRYPT_EAL_MacFinal(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_MacFreeCtx(ctx);
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16625, "MacFinal fail");
    }

    CRYPT_EAL_MacFreeCtx(ctx);
    return HITLS_SUCCESS;
#else // HITLS_CRYPTO_MAC
    (void)hashAlgo;
    (void)key;
    (void)keyLen;
    (void)in;
    (void)inLen;
    (void)out;
    (void)outLen;
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif // HITLS_CRYPTO_MAC
}

HITLS_HASH_Ctx *HITLS_CRYPT_DigestInit(HITLS_Lib_Ctx *libCtx, const char *attrName, HITLS_HashAlgo hashAlgo)
{
#ifdef HITLS_CRYPTO_MD
    CRYPT_EAL_MdCTX *ctx = NULL;
    ctx = CRYPT_EAL_ProviderMdNewCtx(libCtx, hashAlgo, attrName);
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16628, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,  "MdNewCtx fail", 0, 0, 0, 0);
        return NULL;
    }

    int32_t ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16629, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "MdInit fail", 0, 0, 0, 0);
        CRYPT_EAL_MdFreeCtx(ctx);
        return NULL;
    }

    return ctx;
#else // HITLS_CRYPTO_MD
    (void)hashAlgo;
    (void)libCtx;
    (void)attrName;
    return NULL;
#endif // HITLS_CRYPTO_MD
}

int32_t HITLS_CRYPT_Digest(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_MD
    int32_t ret;
    CRYPT_EAL_MdCTX *ctx = NULL;
    ctx = CRYPT_EAL_ProviderMdNewCtx(libCtx, hashAlgo, attrName);
    if (ctx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_DIGEST, BINLOG_ID16631, "MdNewCtx fail");
    }

    ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16632, "MdInit fail");
    }

    ret = CRYPT_EAL_MdUpdate(ctx, in, inLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16633, "MdUpdate fail");
    }

    ret = CRYPT_EAL_MdFinal(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16634, "MdFinal fail");
    }

    CRYPT_EAL_MdFreeCtx(ctx);
    return HITLS_SUCCESS;
#else // HITLS_CRYPTO_MD
    (void)hashAlgo;
    (void)in;
    (void)inLen;
    (void)out;
    (void)outLen;
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif // HITLS_CRYPTO_MD
}

static int32_t SpecialModeEncryptPreSolve(CRYPT_EAL_CipherCtx *ctx, const HITLS_CipherParameters *cipher,
    uint64_t inLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    int32_t ret = CRYPT_SUCCESS;

    if (IsCipherCCM8(cipher->algo)) {
        uint32_t tagLen = CCM8_TLS_TAG_LEN;
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen));
        if (ret != CRYPT_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16635, "SET_TAGLEN fail");
        }
    }
    // In the case of CCM processing, msgLen needs to be set.
    bool isCCM = (cipher->algo == HITLS_CIPHER_AES_128_CCM) || (cipher->algo == HITLS_CIPHER_AES_128_CCM8) ||
                 (cipher->algo == HITLS_CIPHER_AES_256_CCM) || (cipher->algo == HITLS_CIPHER_AES_256_CCM8) ||
				 (cipher->algo == HITLS_CIPHER_SM4_CCM);
    if (isCCM == true) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &inLen, sizeof(inLen));
        if (ret != CRYPT_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16636, "SET_MSGLEN fail");
        }
    }

    if (cipher->type == HITLS_AEAD_CIPHER) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, cipher->aad, cipher->aadLen);
    }

    return ret;
#else // HITLS_CRYPTO_CIPHER
    (void)ctx;
    (void)cipher;
    (void)inLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif // HITLS_CRYPTO_CIPHER
}

#ifdef HITLS_CRYPTO_CIPHER
static int32_t GetCipherInitCtx(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const HITLS_CipherParameters *cipher, CRYPT_EAL_CipherCtx **ctx, bool enc)
{
    if (*ctx != NULL) {
        return CRYPT_EAL_CipherReinit(*ctx, (uint8_t *)(uintptr_t)cipher->iv, cipher->ivLen);
    }

    *ctx = CRYPT_EAL_ProviderCipherNewCtx(libCtx, GetCipherAlgId(cipher->algo), attrName);

    int32_t ret = CRYPT_EAL_CipherInit(*ctx, cipher->key, cipher->keyLen, cipher->iv, cipher->ivLen, enc);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(*ctx);
        *ctx = NULL;
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16639, "CipherInit fail");
    }
    return CRYPT_SUCCESS;
}
#endif

int32_t HITLS_CRYPT_Encrypt(HITLS_Lib_Ctx *libCtx, const char *attrName, const HITLS_CipherParameters *cipher,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    if (cipher == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID17313, "encrypt null input");
    }
    CRYPT_EAL_CipherCtx *tmpCtx = NULL;
    CRYPT_EAL_CipherCtx **ctx = cipher->ctx == NULL ? &tmpCtx : (CRYPT_EAL_CipherCtx **)cipher->ctx;
    int32_t ret = GetCipherInitCtx(libCtx, attrName, cipher, ctx, true);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16640, "GetCipherInitCtx fail");
    }

    ret = SpecialModeEncryptPreSolve(*ctx, cipher, inLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(*ctx);
        *ctx = NULL;
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16641, "SpecialModeEncryptPreSolve fail");
    }

    uint32_t cipherLen = *outLen;
    ret = CRYPT_EAL_CipherUpdate(*ctx, in, inLen, out, &cipherLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(*ctx);
        *ctx = NULL;
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16642, "CipherUpdate fail");
    }

    if (*outLen < cipherLen) {
        CRYPT_EAL_CipherFreeCtx(*ctx);
        *ctx = NULL;
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_ENCRYPT, BINLOG_ID16643, "outLen less than cipherLen");
    }

    uint32_t finLen = *outLen - cipherLen;
    if (cipher->type == HITLS_AEAD_CIPHER) {
        finLen = IsCipherCCM8(cipher->algo) ? CCM8_TLS_TAG_LEN : CCM_TLS_TAG_LEN;
        ret = CRYPT_EAL_CipherCtrl(*ctx, CRYPT_CTRL_GET_TAG, out + cipherLen, finLen);
    } else {
        ret = CRYPT_EAL_CipherFinal(*ctx, out + cipherLen, &finLen);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16644, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "%d , get finLen fail", cipher->type, 0, 0, 0);
        CRYPT_EAL_CipherFreeCtx(*ctx);
        *ctx = NULL;
        return ret;
    }
    *outLen = cipherLen + finLen;
    if (cipher->ctx == NULL) {
        CRYPT_EAL_CipherFreeCtx(*ctx);
    }
    return HITLS_SUCCESS;
#else // HITLS_CRYPTO_CIPHER
    (void)cipher;
    (void)in;
    (void)inLen;
    (void)out;
    (void)outLen;
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif // HITLS_CRYPTO_CIPHER
}

static int32_t AeadDecrypt(CRYPT_EAL_CipherCtx *ctx, const HITLS_CipherParameters *cipher, const uint8_t *in,
    uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    int32_t ret;
    uint32_t tagLen = IsCipherCCM8(cipher->algo) ?
        CCM8_TLS_TAG_LEN : CCM_TLS_TAG_LEN;
    uint32_t cipherLen = inLen - tagLen;
    uint32_t plainLen = *outLen;

    ret = CRYPT_EAL_CipherUpdate(ctx, in, cipherLen, out, &plainLen);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16645, "CipherUpdate fail");
    }

    if (plainLen != cipherLen) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_DECRYPT, BINLOG_ID16646, "decrypt err");
    }

    uint8_t tag[16u] = {0};
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16647, "GET_TAG err");
    }

    if (memcmp(tag, in + cipherLen, tagLen) != 0) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_DECRYPT, BINLOG_ID16648, "memcmp tag fail");
    }

    *outLen = plainLen;
    return HITLS_SUCCESS;
#else // HITLS_CRYPTO_CIPHER
    (void)cipher;
    (void)out;
    (void)outLen;
    (void)in;
    (void)inLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif // HITLS_CRYPTO_CIPHER
}

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
int32_t CbcDecrypt(CRYPT_EAL_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    int32_t ret;
    uint32_t plainLen = *outLen;

    ret = CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &plainLen);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16649, "CipherUpdate fail");
    }

    if (*outLen < plainLen) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_DECRYPT, BINLOG_ID16650, "CipherUpdate fail");
    }

    uint32_t finLen = *outLen - plainLen;
    ret = CRYPT_EAL_CipherFinal(ctx, out + plainLen, &finLen);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16651, "CipherUpdate fail");
    }
    plainLen += finLen;

    *outLen = plainLen;
    return HITLS_SUCCESS;
#else
    (void)ctx;
    (void)out;
    (void)outLen;
    (void)in;
    (void)inLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}
#endif /* HITLS_TLS_SUITE_CIPHER_CBC */

#ifdef HITLS_CRYPTO_CIPHER
static int32_t DEFAULT_DecryptPrepare(CRYPT_EAL_CipherCtx *ctx, const HITLS_CipherParameters *cipher, uint32_t inLen)
{
    int32_t ret = CRYPT_SUCCESS;
    uint32_t tagLen = CCM_TLS_TAG_LEN;
    if (IsCipherCCM8(cipher->algo)) {
        tagLen = CCM8_TLS_TAG_LEN;
        /* The default value of tagLen is 16 for the ctx generated by the CRYPT_EAL_CipherNewCtx.
           Therefore, need to set this parameter again. */
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(ctx);
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16652, "CipherUpdate fail");
        }
    }
    bool isCCM = (cipher->algo == HITLS_CIPHER_AES_128_CCM) || (cipher->algo == HITLS_CIPHER_AES_128_CCM8) ||
                 (cipher->algo == HITLS_CIPHER_AES_256_CCM) || (cipher->algo == HITLS_CIPHER_AES_256_CCM8) ||
				 (cipher->algo == HITLS_CIPHER_SM4_CCM);
    if (isCCM == true) {
        // The length of the decrypted ciphertext consists of msgLen and tagLen, so tagLen needs to be subtracted.
        uint64_t msgLen = inLen - tagLen;
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(ctx);
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16653, "CipherUpdate fail");
        }
    }
    return ret;
}
#endif

int32_t HITLS_CRYPT_Decrypt(HITLS_Lib_Ctx *libCtx, const char *attrName, const HITLS_CipherParameters *cipher,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    if (cipher == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID17312, "encrypt null input");
    }
    CRYPT_EAL_CipherCtx *tmpCtx = NULL;
    CRYPT_EAL_CipherCtx **ctx = cipher->ctx == NULL ? &tmpCtx : (CRYPT_EAL_CipherCtx **)cipher->ctx;
    int32_t ret = GetCipherInitCtx(libCtx, attrName, cipher, ctx, false);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16654, "CipherUpdate fail");
    }

    ret = DEFAULT_DecryptPrepare(*ctx, cipher, inLen);
    if (ret != CRYPT_SUCCESS) {
        *ctx = NULL;
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16655, "CipherUpdate fail");
    }

    if (cipher->type == HITLS_AEAD_CIPHER) {
        ret = CRYPT_EAL_CipherCtrl(*ctx, CRYPT_CTRL_SET_AAD, cipher->aad, cipher->aadLen);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(*ctx);
            *ctx = NULL;
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16656, "SET_AAD fail");
        }
        ret = AeadDecrypt(*ctx, cipher, in, inLen, out, outLen);
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    } else if (cipher->type == HITLS_CBC_CIPHER) {
        ret = CbcDecrypt(*ctx, in, inLen, out, outLen);
#endif
    } else {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16657, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "not support other cipher type", 0, 0, 0, 0);
        ret = HITLS_CRYPT_ERR_DECRYPT;
    }
    if (cipher->ctx == NULL) {
        CRYPT_EAL_CipherFreeCtx(*ctx);
    }
    return ret;
#else
    (void)cipher;
    (void)in;
    (void)out;
    (void)outLen;
    (void)inLen;
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

#ifdef HITLS_CRYPTO_PKEY
CRYPT_EAL_PkeyCtx *GeneratePkeyByParaId(HITLS_Lib_Ctx *libCtx, const char *attrName,
    CRYPT_PKEY_AlgId algId, CRYPT_PKEY_ParaId paraId, bool isKem)
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, algId,
        isKem ? CRYPT_EAL_PKEY_KEM_OPERATE : CRYPT_EAL_PKEY_EXCH_OPERATE, attrName);
    if (pkey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16658, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PkeyNewCtx fail, algId is %d", algId, 0, 0, 0);
        return NULL;
    }

    if (paraId != CRYPT_PKEY_PARAID_MAX) {
        ret = CRYPT_EAL_PkeySetParaById(pkey, paraId);
        if (ret != CRYPT_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16659, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "PkeySetParaById fail", 0, 0, 0, 0);
            CRYPT_EAL_PkeyFreeCtx(pkey);
            return NULL;
        }
    }

    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16660,
            BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "PkeyGen fail %u", ret, 0, 0, 0);
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }

    return pkey;
}
#endif

CRYPT_EAL_PkeyCtx *GenerateKeyByNamedGroup(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const HITLS_Config *config, HITLS_NamedGroup groupId)
{
#ifdef HITLS_CRYPTO_PKEY
    const TLS_GroupInfo *groupInfo = ConfigGetGroupInfo(config, groupId);
    if (groupInfo == NULL) {
        return NULL;
    }
    return GeneratePkeyByParaId(libCtx, attrName, groupInfo->algId, groupInfo->paraId, groupInfo->isKem);
#else
    (void)libCtx;
    (void)attrName;
    (void)config;
    (void)groupId;
#endif
    return NULL;
}

HITLS_CRYPT_Key *HITLS_CRYPT_GenerateEcdhKey(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const HITLS_Config *config, const HITLS_ECParameters *curveParams)
{
    switch (curveParams->type) {
        case HITLS_EC_CURVE_TYPE_NAMED_CURVE:
            return GenerateKeyByNamedGroup(libCtx, attrName, config, curveParams->param.namedcurve);
        default:
            break;
    }
    return NULL;
}

#ifdef HITLS_CRYPTO_PKEY
#ifdef HITLS_TLS_PROTO_TLCP11
static int32_t SetSM2SelfCtx(CRYPT_EAL_PkeyCtx *selfCtx, HITLS_Sm2GenShareKeyParameters *sm2Params)
{
    uint8_t localPrvData[SM2_PRVKEY_LEN] = {0};
    CRYPT_EAL_PkeyPrv localPrv = { 0 };
    localPrv.id = CRYPT_PKEY_SM2;
    localPrv.key.eccPrv.data = localPrvData;
    localPrv.key.eccPrv.len = sizeof(localPrvData);

    int32_t ret = CRYPT_EAL_PkeyGetPrv(sm2Params->tmpPriKey, &localPrv);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16667, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "GetPrv fail", 0, 0, 0, 0);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(selfCtx, CRYPT_CTRL_SET_SM2_RANDOM, localPrv.key.eccPrv.data, localPrv.key.eccPrv.len);
    (void)memset_s(localPrvData, SM2_PRVKEY_LEN, 0, SM2_PRVKEY_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16668, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SET_SM2_RANDOM fail", 0, 0, 0, 0);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(selfCtx, CRYPT_CTRL_SET_SM2_USER_ID, (void *)g_sm2DefaultUserid, SM2_DEFAULT_USERID_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16669, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SET_SM2_USER_ID fail", 0, 0, 0, 0);
        return ret;
    }
    int32_t server = sm2Params->isClient ? 0 : 1;
    return CRYPT_EAL_PkeyCtrl(selfCtx, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t));
}

static int32_t CalcSM2SecretPre(
    CRYPT_EAL_PkeyCtx *peerCtx, HITLS_Sm2GenShareKeyParameters *sm2Params)
{
    uint8_t peerPubData[SM2_PUBKEY_LEN] = {0};
    BSL_Param param[2] = { {0}, BSL_PARAM_END };
    (void)BSL_PARAM_InitValue(param, CRYPT_PARAM_PKEY_ENCODE_PUBKEY, BSL_PARAM_TYPE_OCTETS,
        peerPubData, SM2_PUBKEY_LEN);
    int32_t ret = CRYPT_EAL_PkeyGetPubEx(sm2Params->peerPubKey, param);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16673, "GetPub fail");
    }
    param[0].valueLen = param[0].useLen;
    ret = CRYPT_EAL_PkeySetPubEx(peerCtx, param);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16674, "SetPub fail");
    }
    ret = CRYPT_EAL_PkeyCtrl(peerCtx, CRYPT_CTRL_SET_SM2_R, sm2Params->tmpPeerPubkey, sm2Params->tmpPeerPubKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16675, "SET_SM2_R fail");
    }
    ret = CRYPT_EAL_PkeyCtrl(peerCtx, CRYPT_CTRL_SET_SM2_USER_ID, (void *)g_sm2DefaultUserid, SM2_DEFAULT_USERID_LEN);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16676, "SET_SM2_USER_ID fail");
    }
    return CRYPT_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLCP11 */
#endif

#ifdef HITLS_TLS_PROTO_TLCP11
int32_t HITLS_CRYPT_CalcSM2SharedSecret(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_Sm2GenShareKeyParameters *sm2Params, uint8_t *sharedSecret,
    uint32_t *sharedSecretLen)
{
#ifdef HITLS_CRYPTO_PKEY
    bool nullInput = sm2Params->priKey == NULL || sm2Params->peerPubKey == NULL || sm2Params->tmpPriKey == NULL ||
                     sm2Params->tmpPeerPubkey == NULL;
    if (nullInput == true) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_CALC_SHARED_KEY, BINLOG_ID16670, "input null");
    }
    CRYPT_EAL_PkeyCtx *selfCtx = (CRYPT_EAL_PkeyCtx *)sm2Params->priKey;
    int32_t ret = SetSM2SelfCtx(selfCtx, sm2Params);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16671, "SetSM2SelfCtx fail");
    }
    CRYPT_EAL_PkeyCtx *peerCtx = NULL;
    peerCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_SM2, CRYPT_EAL_PKEY_EXCH_OPERATE, attrName);
    if (peerCtx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_CALC_SHARED_KEY, BINLOG_ID16672, "peerCtx new fail");
    }
    ret = CalcSM2SecretPre(peerCtx, sm2Params);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyComputeShareKey(selfCtx, peerCtx, sharedSecret, sharedSecretLen);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(peerCtx);
    return ret;
#else
    (void)sm2Params;
    (void)sharedSecret;
    (void)sharedSecretLen;
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

#endif /* HITLS_TLS_PROTO_TLCP11 */

int32_t HITLS_CRYPT_DhCalcSharedSecret(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
#ifdef HITLS_CRYPTO_PKEY
    uint32_t flag = CRYPT_DH_NO_PADZERO;
    int32_t ret = CRYPT_EAL_PkeyCtrl(key, CRYPT_CTRL_SET_DH_FLAG, (void *)&flag, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17354, "SET_DH_NOLEANDING_FLAG fail");
    }
    return HITLS_CRYPT_EcdhCalcSharedSecret(libCtx, attrName, key, peerPubkey, pubKeyLen, sharedSecret,
        sharedSecretLen);
#else // HITLS_CRYPTO_PKEY
    (void)key;
    (void)pubKeyLen;
    (void)peerPubkey;
    (void)sharedSecret;
    (void)sharedSecretLen;
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

int32_t HITLS_CRYPT_EcdhCalcSharedSecret(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
#ifdef HITLS_CRYPTO_PKEY
    int32_t ret;
    int32_t id = CRYPT_EAL_PkeyGetId(key);
    CRYPT_EAL_PkeyCtx *peerPk = NULL;
    peerPk = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, id, CRYPT_EAL_PKEY_EXCH_OPERATE, attrName);
    if (peerPk == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_CALC_SHARED_KEY, BINLOG_ID16678, "peerPk new fail");
    }

    if (id == CRYPT_PKEY_ECDH) {
        CRYPT_PKEY_ParaId paraId = CRYPT_EAL_PkeyGetParaId(key);
        if (paraId == CRYPT_PKEY_PARAID_MAX) {
            ret = CRYPT_EAL_ERR_ALGID;
            (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16679, "paraId error");
            goto EXIT;
        }
        ret = CRYPT_EAL_PkeySetParaById(peerPk, paraId);
        if (ret != CRYPT_SUCCESS) {
            (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16680, "SetParaById fail");
            goto EXIT;
        }
    }
    BSL_Param param[2] = { {0}, BSL_PARAM_END };
    (void)BSL_PARAM_InitValue(param, CRYPT_PARAM_PKEY_ENCODE_PUBKEY, BSL_PARAM_TYPE_OCTETS, peerPubkey, pubKeyLen);
    ret = CRYPT_EAL_PkeySetPubEx(peerPk, param);
    if (ret != CRYPT_SUCCESS) {
        (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16681, "SetPub fail");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyComputeShareKey(key, peerPk, sharedSecret, sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16682, "ComputeShareKey fail");
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(peerPk);
    return ret;
#else // HITLS_CRYPTO_PKEY
    (void)key;
    (void)pubKeyLen;
    (void)peerPubkey;
    (void)sharedSecret;
    (void)sharedSecretLen;
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

#ifdef HITLS_TLS_SUITE_KX_DHE

HITLS_CRYPT_Key *HITLS_CRYPT_GenerateDhKeyBySecbits(HITLS_Lib_Ctx *libCtx,
    const char *attrName, const HITLS_Config *tlsConfig, int32_t secBits)
{
    (void)tlsConfig;
    CRYPT_PKEY_ParaId paraId = CRYPT_DH_RFC2409_1024;
    if (secBits >= MIN_DH8192_SECBITS) {
        paraId = CRYPT_DH_RFC3526_8192;
    } else if (secBits >= MIN_DH4096_SECBITS) {
        paraId = CRYPT_DH_RFC3526_4096;
    } else if (secBits >= MIN_DH3072_SECBITS) {
        paraId = CRYPT_DH_RFC3526_3072;
    } else if (secBits >= MIN_DH2048_SECBITS) {
        paraId = CRYPT_DH_RFC3526_2048;
    }
    return GeneratePkeyByParaId(libCtx, attrName, CRYPT_PKEY_DH, paraId, false);
}

HITLS_CRYPT_Key *HITLS_CRYPT_GenerateDhKeyByParameters(HITLS_Lib_Ctx *libCtx,
    const char *attrName, uint8_t *p, uint16_t pLen, uint8_t *g, uint16_t gLen)
{
#ifdef HITLS_CRYPTO_DH
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_EXCH_OPERATE, attrName);
    if (pkey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16683, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PkeyNewCtx fail", 0, 0, 0, 0);
        return NULL;
    }

    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_PKEY_DH;
    para.para.dhPara.p = p;
    para.para.dhPara.pLen = pLen;
    para.para.dhPara.g = g;
    para.para.dhPara.gLen = gLen;

    int32_t ret = CRYPT_EAL_PkeySetPara(pkey, &para);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16684, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "SetPara fail", 0, 0, 0, 0);
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }

    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16685, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "PkeyGen fail", 0, 0, 0, 0);
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }

    return pkey;
#else
    (void)p;
    (void)pLen;
    (void)g;
    (void)gLen;
    (void)libCtx;
    (void)attrName;
    return NULL;
#endif
}

int32_t HITLS_CRYPT_GetDhParameters(HITLS_CRYPT_Key *key, uint8_t *p, uint16_t *pLen, uint8_t *g, uint16_t *gLen)
{
#ifdef HITLS_CRYPTO_PKEY
    int32_t ret;
    uint8_t tmpP[MAX_PKEY_PARA_LEN] = {0};
    uint8_t tmpQ[MAX_PKEY_PARA_LEN] = {0};
    uint8_t tmpG[MAX_PKEY_PARA_LEN] = {0};

    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_PKEY_DH;
    para.para.dhPara.p = p;
    para.para.dhPara.pLen = *pLen;
    para.para.dhPara.q = tmpQ;
    para.para.dhPara.qLen = sizeof(tmpQ);
    para.para.dhPara.g = g;
    para.para.dhPara.gLen = *gLen;

    if (p == NULL) {
        para.para.dhPara.p = tmpP;
        para.para.dhPara.pLen = sizeof(tmpP);
    }
    if (g == NULL) {
        para.para.dhPara.g = tmpG;
        para.para.dhPara.gLen = sizeof(tmpG);
    }

    ret = CRYPT_EAL_PkeyGetPara(key, &para);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16686, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "GetPara fail", 0, 0, 0, 0);
        return ret;
    }

    *pLen = (uint16_t)para.para.dhPara.pLen;
    *gLen = (uint16_t)para.para.dhPara.gLen;
    return HITLS_SUCCESS;
#else
    (void)key;
    (void)p;
    (void)pLen;
    (void)g;
    (void)gLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}


#endif /* HITLS_TLS_SUITE_KX_DHE */

int32_t HITLS_CRYPT_HkdfExtract(HITLS_Lib_Ctx *libCtx,
    const char *attrName, const HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen)
{
#ifdef HITLS_CRYPTO_HKDF
    int32_t ret;
    uint32_t tmpLen = *prkLen;
    CRYPT_MAC_AlgId id = GetHmacAlgId(input->hashAlgo);
    if (id == CRYPT_MAC_MAX) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16687, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetHmacAlgId fail", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_HMAC;
    }
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_HKDF, attrName);
    if (kdfCtx == NULL) {
        return HITLS_CRYPT_ERR_HKDF_EXTRACT;
    }
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXTRACT;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, sizeof(id));
    (void)BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode));
    (void)BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        (void *)(uintptr_t)input->inputKeyMaterial, input->inputKeyMaterialLen);
    (void)BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        (void *)(uintptr_t)input->salt, input->saltLen);
    (void)BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_EXLEN, BSL_PARAM_TYPE_UINT32_PTR, &tmpLen, sizeof(tmpLen));
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, params);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = CRYPT_EAL_KdfDerive(kdfCtx, prk, tmpLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    *prkLen = tmpLen;
    ret = HITLS_SUCCESS;
EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    return ret;
#else
    (void)input;
    (void)prk;
    (void)prkLen;
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

int32_t HITLS_CRYPT_HkdfExpand(HITLS_Lib_Ctx *libCtx,
    const char *attrName, const HITLS_CRYPT_HkdfExpandInput *input, uint8_t *okm, uint32_t okmLen)
{
#ifdef HITLS_CRYPTO_HKDF
    int32_t ret;
    CRYPT_MAC_AlgId id = GetHmacAlgId(input->hashAlgo);
    if (id == CRYPT_MAC_MAX) {
        return HITLS_CRYPT_ERR_HMAC;
    }
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_HKDF, attrName);
    if (kdfCtx == NULL) {
        return HITLS_CRYPT_ERR_HKDF_EXPAND;
    }
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXPAND;
    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, sizeof(id));
    (void)BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode));
    (void)BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_PRK, BSL_PARAM_TYPE_OCTETS,
        (void *)(uintptr_t)input->prk, input->prkLen);
    (void)BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        (void *)(uintptr_t)input->info, input->infoLen);
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, params);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_KdfDerive(kdfCtx, okm, okmLen);
EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    return ret;
#else
    (void)input;
    (void)okm;
    (void)okmLen;
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

#ifdef HITLS_TLS_FEATURE_PROVIDER
int32_t HITLS_CRYPT_RandbytesEx(HITLS_Lib_Ctx *libCtx, uint8_t *bytes, uint32_t bytesLen)
{
    return CRYPT_EAL_RandbytesEx(libCtx, bytes, bytesLen);
}
#endif /* HITLS_TLS_FEATURE_PROVIDER */

void HITLS_CRYPT_FreeKey(HITLS_CRYPT_Key *key)
{
    CRYPT_EAL_PkeyFreeCtx(key);
}

uint32_t HITLS_CRYPT_DigestSize(HITLS_HashAlgo hashAlgo)
{
#ifdef HITLS_CRYPTO_MD
    return CRYPT_EAL_MdGetDigestSize((CRYPT_MD_AlgId)hashAlgo);
#else
    (void)hashAlgo;
    return 0;
#endif
}

HITLS_HASH_Ctx *HITLS_CRYPT_DigestCopy(HITLS_HASH_Ctx *ctx)
{
#ifdef HITLS_CRYPTO_MD
    return CRYPT_EAL_MdDupCtx(ctx);
#else
    (void)ctx;
    return NULL;
#endif
}

void HITLS_CRYPT_DigestFree(HITLS_HASH_Ctx *ctx)
{
#ifdef HITLS_CRYPTO_MD
    CRYPT_EAL_MdFreeCtx(ctx);
#else
    (void)ctx;
#endif
}

int32_t HITLS_CRYPT_DigestUpdate(HITLS_HASH_Ctx *ctx, const uint8_t *data, uint32_t len)
{
#ifdef HITLS_CRYPTO_MD
    return CRYPT_EAL_MdUpdate(ctx, data, len);
#else
    (void)ctx;
    (void)data;
    (void)len;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

int32_t HITLS_CRYPT_DigestFinal(HITLS_HASH_Ctx *ctx, uint8_t *out, uint32_t *len)
{
#ifdef HITLS_CRYPTO_MD
    return CRYPT_EAL_MdFinal(ctx, out, len);
#else
    (void)ctx;
    (void)out;
    (void)len;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

void HITLS_CRYPT_CipherFree(HITLS_Cipher_Ctx *ctx)
{
    CRYPT_EAL_CipherFreeCtx(ctx);
}

#ifdef HITLS_TLS_CONFIG_MANUAL_DH
HITLS_CRYPT_Key *HITLS_CRYPT_DupKey(HITLS_CRYPT_Key *key)
{
#ifdef HITLS_CRYPTO_PKEY
    return CRYPT_EAL_PkeyDupCtx(key);
#else
    (void)key;
    return NULL;
#endif
}
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */

int32_t HITLS_CRYPT_GetPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
#ifdef HITLS_CRYPTO_PKEY
    BSL_Param param[2] = { {0}, BSL_PARAM_END };
    (void)BSL_PARAM_InitValue(param, CRYPT_PARAM_PKEY_ENCODE_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, bufLen);
    int32_t ret = CRYPT_EAL_PkeyGetPubEx(key, param);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16664, "GetPub fail");
    }
    *pubKeyLen = param[0].useLen;
    return ret;
#else
    (void)key;
    (void)pubKeyBuf;
    (void)bufLen;
    (void)pubKeyLen;
    return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
#endif
}

#ifdef HITLS_TLS_FEATURE_KEM
int32_t HITLS_CRYPT_KemEncapsulate(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const HITLS_Config *config, HITLS_KemEncapsulateParams *params)
{
    const TLS_GroupInfo *groupInfo = ConfigGetGroupInfo(config, params->groupId);
    if (groupInfo == NULL) {
        return HITLS_INVALID_INPUT;
    }
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, groupInfo->algId, CRYPT_EAL_PKEY_KEM_OPERATE, attrName);
    if (pkey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15656, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PkeyNewCtx fail id is %d", groupInfo->algId, 0, 0, 0);
        return HITLS_CRYPT_ERR_KEM_ENCAPSULATE;
    }

    if (groupInfo->paraId != CRYPT_PKEY_PARAID_MAX) {
        ret = CRYPT_EAL_PkeySetParaById(pkey, groupInfo->paraId);
        if (ret != CRYPT_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16659, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "PkeySetParaById fail", 0, 0, 0, 0);
            CRYPT_EAL_PkeyFreeCtx(pkey);
            return ret;
        }
    }
    BSL_Param param[2] = { {0}, BSL_PARAM_END };
    (void)BSL_PARAM_InitValue(param, CRYPT_PARAM_PKEY_ENCODE_PUBKEY, BSL_PARAM_TYPE_OCTETS, params->peerPubkey,
        params->pubKeyLen);
    ret = CRYPT_EAL_PkeySetPubEx(pkey, param);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16660, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PkeySetPub fail", 0, 0, 0, 0);
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return ret;
    }

    ret = CRYPT_EAL_PkeyEncaps(pkey, params->ciphertext, params->ciphertextLen, params->sharedSecret,
        params->sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16661, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PkeyEncaps fail", 0, 0, 0, 0);
    }
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

int32_t HITLS_CRYPT_KemDecapsulate(HITLS_CRYPT_Key *key, const uint8_t *ciphertext, uint32_t ciphertextLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    return CRYPT_EAL_PkeyDecaps(key, ciphertext, ciphertextLen, sharedSecret, sharedSecretLen);
}
#endif /* HITLS_TLS_FEATURE_KEM */

#ifdef HITLS_CRYPTO_KDFTLS12
static void InitKdfTls12Param(CRYPT_KeyDeriveParameters *input, CRYPT_MAC_AlgId *id, BSL_Param *params)
{
    (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, id, sizeof(int32_t));
    (void)BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        (void *)(uintptr_t)input->secret, input->secretLen);
    (void)BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS, // 2: index of label
        (void *)(uintptr_t)input->label, input->labelLen);
    (void)BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS, // 3: index of seed
        (void *)(uintptr_t)input->seed, input->seedLen);
    if (input->attrName != NULL && strlen(input->attrName) > 0) {
        (void)BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_MD_ATTR, BSL_PARAM_TYPE_UTF8_STR, // 4: index of md attr
            (void *)(uintptr_t)input->attrName, strlen(input->attrName));
    }
}
#endif

int32_t HITLS_CRYPT_PRF(CRYPT_KeyDeriveParameters *input, uint8_t *out, uint32_t outLen)
{
#ifdef HITLS_CRYPTO_KDFTLS12
    CRYPT_MAC_AlgId id = GetHmacAlgId(input->hashAlgo);
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END}; // Set 5 parameters for kdftls12
    InitKdfTls12Param(input, &id, params);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_ProviderKdfNewCtx(input->libCtx, CRYPT_KDF_KDFTLS12, input->attrName);
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17374, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "KdfNewCtx fail", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_KDF;
    }

    int32_t ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17375, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "KdfSetParam fail", 0, 0, 0, 0);
        return ret;
    }

    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    CRYPT_EAL_KdfFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17376, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "KdfDerive fail", 0, 0, 0, 0);
    }
    return ret;
#else
    (void)input;
    (void)out;
    (void)outLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

#endif /* HITLS_TLS_CALLBACK_CRYPT || HITLS_TLS_FEATURE_PROVIDER */