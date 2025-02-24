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
#ifdef HITLS_TLS_CALLBACK_CRYPT
#include <string.h>
#include "securec.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
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
#include "hitls_build.h"

#include "crypt_default.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "config_type.h"

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
#endif


#define CCM_TLS_TAG_LEN 16u
#define CCM8_TLS_TAG_LEN 8u

/* The default user id as specified in GM/T 0009-2012 */
char g_SM2DefaultUserid[] = "1234567812345678";
#ifdef HITLS_TLS_PROTO_TLCP11
#define SM2_DEFAULT_USERID_LEN 16u
#define SM2_PUBKEY_LEN 65
#define SM2_PRVKEY_LEN 33
#endif
#ifdef HITLS_CRYPTO_MD
static uint32_t GetMDAlgId(HITLS_HashAlgo hashAlgo)
{
    switch (hashAlgo) {
        case HITLS_HASH_SHA_256:
            return CRYPT_MD_SHA256;
        case HITLS_HASH_SHA_384:
            return CRYPT_MD_SHA384;
        case HITLS_HASH_SHA_512:
            return CRYPT_MD_SHA512;
        case HITLS_HASH_MD5:
            return CRYPT_MD_MD5;
        case HITLS_HASH_SHA1:
            return CRYPT_MD_SHA1;
        case HITLS_HASH_SHA_224:
            return CRYPT_MD_SHA224;
        case HITLS_HASH_SM3:
            return CRYPT_MD_SM3;
        default:
            break;
    }
    return CRYPT_MD_MAX;
}
#endif

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
#endif

#ifdef HITLS_CRYPTO_CIPHER
static uint32_t GetCipherAlgId(HITLS_CipherAlgo cipherAlgo)
{
    switch (cipherAlgo) {
        case HITLS_CIPHER_AES_128_GCM:
            return CRYPT_CIPHER_AES128_GCM;
        case HITLS_CIPHER_AES_256_GCM:
            return CRYPT_CIPHER_AES256_GCM;
        case HITLS_CIPHER_CHACHA20_POLY1305:
            return CRYPT_CIPHER_CHACHA20_POLY1305;
        case HITLS_CIPHER_AES_128_CCM:
        case HITLS_CIPHER_AES_128_CCM8:
            return CRYPT_CIPHER_AES128_CCM;
        case HITLS_CIPHER_AES_128_CBC:
            return CRYPT_CIPHER_AES128_CBC;
        case HITLS_CIPHER_AES_256_CBC:
            return CRYPT_CIPHER_AES256_CBC;
        case HITLS_CIPHER_AES_256_CCM:
        case HITLS_CIPHER_AES_256_CCM8:
            return CRYPT_CIPHER_AES256_CCM;
        case HITLS_CIPHER_SM4_CBC:
            return CRYPT_CIPHER_SM4_CBC;
        default:
            break;
    }
    return CRYPT_CIPHER_MAX;
}
#endif

int32_t CRYPT_DEFAULT_RandomBytes(uint8_t *buf, uint32_t len)
{
#ifdef HITLS_CRYPTO_DRBG
    return CRYPT_EAL_Randbytes(buf, len);
#else
    (void)buf;
    (void)len;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

uint32_t CRYPT_DEFAULT_HMAC_Size(HITLS_HashAlgo hashAlgo)
{
    return CRYPT_DEFAULT_DigestSize(hashAlgo);
}

#ifdef HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES
HITLS_HMAC_Ctx *CRYPT_DEFAULT_HMAC_Init(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len)
{
#ifdef HITLS_CRYPTO_MAC
    CRYPT_MAC_AlgId id = GetHmacAlgId(hashAlgo);
    if (id == CRYPT_MAC_MAX) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16618, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "hashAlgo err", 0, 0, 0, 0);
        return NULL;
    }

    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(id);
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16619, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "MacNewCtx fail", 0, 0, 0, 0);
        return NULL;
    }

    int32_t ret = CRYPT_EAL_MacInit(ctx, key, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16620, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "MacInit fail", 0, 0, 0, 0);
        CRYPT_EAL_MacFreeCtx(ctx);
        return NULL;
    }

    return ctx;
#else
    (void)hashAlgo;
    (void)key;
    (void)len;
    return NULL;
#endif
}

int32_t CRYPT_DEFAULT_HMAC_ReInit(HITLS_HMAC_Ctx *ctx)
{
#ifdef HITLS_CRYPTO_MAC
    return CRYPT_EAL_MacReinit(ctx);
#else
    (void)ctx;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

void CRYPT_DEFAULT_HMAC_Free(HITLS_HMAC_Ctx *ctx)
{
#ifdef HITLS_CRYPTO_MAC
    CRYPT_EAL_MacFreeCtx(ctx);
#else
    (void)ctx;
#endif
    return;
}

int32_t CRYPT_DEFAULT_HMAC_Update(HITLS_HMAC_Ctx *ctx, const uint8_t *data, uint32_t len)
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

int32_t CRYPT_DEFAULT_HMAC_Final(HITLS_HMAC_Ctx *ctx, uint8_t *out, uint32_t *len)
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

int32_t CRYPT_DEFAULT_HMAC(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_MAC
    CRYPT_MAC_AlgId id = GetHmacAlgId(hashAlgo);
    if (id == CRYPT_MAC_MAX) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_HMAC, BINLOG_ID16621, "No proper id");
    }

    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(id);
    if (ctx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_HMAC, BINLOG_ID16622, "new ctx fail");
    }

    int32_t ret = CRYPT_EAL_MacInit(ctx, key, keyLen);
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
#else
    (void)hashAlgo;
    (void)key;
    (void)keyLen;
    (void)in;
    (void)inLen;
    (void)out;
    (void)outLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

uint32_t CRYPT_DEFAULT_DigestSize(HITLS_HashAlgo hashAlgo)
{
#ifdef HITLS_CRYPTO_MD
    CRYPT_MD_AlgId id = GetMDAlgId(hashAlgo);
    if (id == CRYPT_MD_MAX) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16626, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetMDAlgId fail", 0, 0, 0, 0);
        return 0;
    }

    return CRYPT_EAL_MdGetDigestSize(id);
#else
    (void)hashAlgo;
    return 0;
#endif
}

HITLS_HASH_Ctx *CRYPT_DEFAULT_DigestInit(HITLS_HashAlgo hashAlgo)
{
#ifdef HITLS_CRYPTO_MD
    CRYPT_MD_AlgId id = GetMDAlgId(hashAlgo);
    if (id == CRYPT_MD_MAX) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16627, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetMDAlgId fail", 0, 0, 0, 0);
        return NULL;
    }

    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(id);
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
#else
    (void)hashAlgo;
    return NULL;
#endif
}

HITLS_HASH_Ctx *CRYPT_DEFAULT_DigestCopy(HITLS_HASH_Ctx *ctx)
{
#ifdef HITLS_CRYPTO_MD
    return CRYPT_EAL_MdDupCtx(ctx);
#else
    (void)ctx;
    return NULL;
#endif
}

void CRYPT_DEFAULT_DigestFree(HITLS_HASH_Ctx *ctx)
{
#ifdef HITLS_CRYPTO_MD
    CRYPT_EAL_MdFreeCtx(ctx);
#else
    (void)ctx;
#endif
    return;
}

int32_t CRYPT_DEFAULT_DigestUpdate(HITLS_HASH_Ctx *ctx, const uint8_t *data, uint32_t len)
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

int32_t CRYPT_DEFAULT_DigestFinal(HITLS_HASH_Ctx *ctx, uint8_t *out, uint32_t *len)
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

int32_t CRYPT_DEFAULT_Digest(HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_MD
    int32_t ret;
    CRYPT_MD_AlgId id = GetMDAlgId(hashAlgo);
    if (id == CRYPT_MD_MAX) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_DIGEST, BINLOG_ID16630, "GetMDAlgId fail");
    }

    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(id);
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
#else
    (void)hashAlgo;
    (void)in;
    (void)inLen;
    (void)out;
    (void)outLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

static int32_t SpecialModeEncryptPreSolve(CRYPT_EAL_CipherCtx *ctx, const HITLS_CipherParameters *cipher,
    uint64_t inLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    int32_t ret = CRYPT_SUCCESS;

    if (cipher->algo == HITLS_CIPHER_AES_128_CCM8 || cipher->algo == HITLS_CIPHER_AES_256_CCM8
        ) {
        uint32_t tagLen = CCM8_TLS_TAG_LEN;
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen));
        if (ret != CRYPT_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16635, "SET_TAGLEN fail");
        }
    }
    // In the case of CCM processing, msgLen needs to be set.
    if ((cipher->algo == HITLS_CIPHER_AES_128_CCM) || (cipher->algo == HITLS_CIPHER_AES_128_CCM8) ||
        (cipher->algo == HITLS_CIPHER_AES_256_CCM) || (cipher->algo == HITLS_CIPHER_AES_256_CCM8)) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &inLen, sizeof(inLen));
        if (ret != CRYPT_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16636, "SET_MSGLEN fail");
        }
    }

    if (cipher->type == HITLS_AEAD_CIPHER) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, cipher->aad, cipher->aadLen);
    }

    return ret;
#else
    (void)ctx;
    (void)cipher;
    (void)inLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

#ifdef HITLS_CRYPTO_CIPHER
static int32_t GetCipherInitCtx(const HITLS_CipherParameters *cipher, CRYPT_EAL_CipherCtx **ctx, bool enc)
{
    if (*ctx != NULL) {
        return CRYPT_EAL_CipherReinit(*ctx, cipher->iv, cipher->ivLen);
    }
    CRYPT_CIPHER_AlgId id = GetCipherAlgId(cipher->algo);
    if (id == CRYPT_CIPHER_MAX) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_ENCRYPT, BINLOG_ID16637, "GetCipherAlgId fail");
    }

    *ctx = CRYPT_EAL_CipherNewCtx(id);
    if (*ctx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_ENCRYPT, BINLOG_ID16638, "CipherNewCtx fail");
    }

    int32_t ret = CRYPT_EAL_CipherInit(*ctx, cipher->key, cipher->keyLen, cipher->iv, cipher->ivLen, enc);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(*ctx);
        *ctx = NULL;
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16639, "CipherInit fail");
    }
    return CRYPT_SUCCESS;
}
#endif

int32_t CRYPT_DEFAULT_Encrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    if (cipher == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID17313, "encrypt null input");
    }
    CRYPT_EAL_CipherCtx *tmpCtx = NULL;
    CRYPT_EAL_CipherCtx **ctx = cipher->ctx == NULL ? &tmpCtx : (CRYPT_EAL_CipherCtx **)cipher->ctx;
    int32_t ret = GetCipherInitCtx(cipher, ctx, true);
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
        finLen = (cipher->algo == HITLS_CIPHER_AES_128_CCM8 || cipher->algo == HITLS_CIPHER_AES_256_CCM8) ?
            CCM8_TLS_TAG_LEN : CCM_TLS_TAG_LEN;
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
#else
    (void)cipher;
    (void)in;
    (void)inLen;
    (void)out;
    (void)outLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

static int32_t AeadDecrypt(CRYPT_EAL_CipherCtx *ctx, const HITLS_CipherParameters *cipher, const uint8_t *in,
    uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    int32_t ret;
    uint32_t tagLen = (cipher->algo == HITLS_CIPHER_AES_128_CCM8 || cipher->algo == HITLS_CIPHER_AES_256_CCM8) ?
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
#else
    (void)cipher;
    (void)out;
    (void)outLen;
    (void)in;
    (void)inLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
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
    if (cipher->algo == HITLS_CIPHER_AES_128_CCM8 || cipher->algo == HITLS_CIPHER_AES_256_CCM8) {
        tagLen = CCM8_TLS_TAG_LEN;
        /* The default value of tagLen is 16 for the ctx generated by the CRYPT_EAL_CipherNewCtx.
           Therefore, need to set this parameter again. */
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(ctx);
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16652, "CipherUpdate fail");
        }
    }
    if ((cipher->algo == HITLS_CIPHER_AES_128_CCM) || (cipher->algo == HITLS_CIPHER_AES_128_CCM8) ||
        (cipher->algo == HITLS_CIPHER_AES_256_CCM) || (cipher->algo == HITLS_CIPHER_AES_256_CCM8)) {
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

int32_t CRYPT_DEFAULT_Decrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    if (cipher == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID17312, "encrypt null input");
    }
    CRYPT_EAL_CipherCtx *tmpCtx = NULL;
    CRYPT_EAL_CipherCtx **ctx = cipher->ctx == NULL ? &tmpCtx : (CRYPT_EAL_CipherCtx **)cipher->ctx;
    int32_t ret = GetCipherInitCtx(cipher, ctx, false);
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
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

void CRYPT_DEFAULT_CipherFree(HITLS_Cipher_Ctx *ctx)
{
    CRYPT_EAL_CipherFreeCtx(ctx);
}

#ifdef HITLS_CRYPTO_PKEY
CRYPT_EAL_PkeyCtx *GeneratePkeyByParaId(CRYPT_PKEY_AlgId algId, CRYPT_PKEY_ParaId paraId)
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(algId);
    if (pkey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16658, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PkeyNewCtx fail", 0, 0, 0, 0);
        return NULL;
    }

    if (algId != CRYPT_PKEY_X25519
#ifdef HITLS_TLS_PROTO_TLCP11
     && algId != CRYPT_PKEY_SM2
#endif
     ) {
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
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16660, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "PkeyGen fail", 0, 0, 0, 0);
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }

    return pkey;
}
#endif

CRYPT_EAL_PkeyCtx *GenerateKeyByNamedGroup(HITLS_NamedGroup groupId)
{
#ifdef HITLS_CRYPTO_PKEY
    const TLS_GroupInfo *groupInfo = ConfigGetGroupInfo(NULL, groupId);
    if (groupInfo == NULL) {
        return NULL;
    }
    return GeneratePkeyByParaId(groupInfo->algId, groupInfo->paraId);
#else
    (void)groupId;
#endif
    return NULL;
}

HITLS_CRYPT_Key *CRYPT_DEFAULT_GenerateEcdhKey(const HITLS_ECParameters *curveParams)
{
    switch (curveParams->type) {
        case HITLS_EC_CURVE_TYPE_NAMED_CURVE:
            return GenerateKeyByNamedGroup(curveParams->param.namedcurve);
        default:
            break;
    }
    return NULL;
}

#ifdef HITLS_TLS_CONFIG_MANUAL_DH
HITLS_CRYPT_Key *CRYPT_DEFAULT_DupKey(HITLS_CRYPT_Key *key)
{
#ifdef HITLS_CRYPTO_PKEY
    return CRYPT_EAL_PkeyDupCtx(key);
#else
    (void)key;
    return NULL;
#endif
}
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */

void CRYPT_DEFAULT_FreeKey(HITLS_CRYPT_Key *key)
{
#ifdef HITLS_CRYPTO_PKEY
    CRYPT_EAL_PkeyFreeCtx(key);
#endif
    (void)key;
    return;
}

#ifdef HITLS_TLS_PROTO_TLCP11
static int32_t SM2KeyGetPub(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
#ifdef HITLS_CRYPTO_PKEY
    CRYPT_EAL_PkeyPub pub;
    pub.id = CRYPT_PKEY_SM2;
    pub.key.eccPub.data = pubKeyBuf;
    pub.key.eccPub.len = bufLen;

    int32_t ret = CRYPT_EAL_PkeyGetPub(key, &pub);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16661, "GetPub fail");
    }
    *pubKeyLen = pub.key.eccPub.len;
    return HITLS_SUCCESS;
#else
    (void)key;
    (void)pubKeyBuf;
    (void)bufLen;
    (void)pubKeyLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}
#endif /* HITLS_TLS_PROTO_TLCP11 */

static int32_t EcdhKeyGetPub(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
#ifdef HITLS_CRYPTO_PKEY
    CRYPT_EAL_PkeyPub pub;
    pub.id = CRYPT_PKEY_ECDH;
    pub.key.eccPub.data = pubKeyBuf;
    pub.key.eccPub.len = bufLen;

    int32_t ret = CRYPT_EAL_PkeyGetPub(key, &pub);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16662, "GetPub fail");
    }

    *pubKeyLen = pub.key.eccPub.len;
    return HITLS_SUCCESS;
#else
    (void)key;
    (void)pubKeyBuf;
    (void)bufLen;
    (void)pubKeyLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

static int32_t X25519KeyGetPub(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
#ifdef HITLS_CRYPTO_X25519
    CRYPT_EAL_PkeyPub pub;
    pub.id = CRYPT_PKEY_X25519;
    pub.key.curve25519Pub.data = pubKeyBuf;
    pub.key.curve25519Pub.len = bufLen;

    int32_t ret = CRYPT_EAL_PkeyGetPub(key, &pub);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16663, "GetPub fail");
    }

    *pubKeyLen = pub.key.curve25519Pub.len;
    return HITLS_SUCCESS;
#else
    (void)key;
    (void)pubKeyBuf;
    (void)bufLen;
    (void)pubKeyLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

#ifdef HITLS_TLS_SUITE_KX_DHE
static int32_t DhKeyGetPub(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
#ifdef HITLS_CRYPTO_DH
    CRYPT_EAL_PkeyPub pub;
    pub.id = CRYPT_PKEY_DH;
    pub.key.dhPub.data = pubKeyBuf;
    pub.key.dhPub.len = bufLen;

    int32_t ret = CRYPT_EAL_PkeyGetPub(key, &pub);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16664, "GetPub fail");
    }

    *pubKeyLen = pub.key.dhPub.len;
    uint32_t padLen = bufLen - (*pubKeyLen);
    if (padLen == 0) {
        return HITLS_SUCCESS;
    }

    (void)memmove_s(pubKeyBuf + padLen, *pubKeyLen + padLen, pubKeyBuf, *pubKeyLen);
    (void)memset_s(pubKeyBuf, *pubKeyLen + padLen, 0, padLen);
    *pubKeyLen += padLen;
    return HITLS_SUCCESS;
#else
    (void)key;
    (void)bufLen;
    (void)pubKeyLen;
    (void)pubKeyBuf;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}
#endif /* HITLS_TLS_SUITE_KX_DHE */

int32_t CRYPT_DEFAULT_GetPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
#ifdef HITLS_CRYPTO_PKEY
    CRYPT_PKEY_AlgId id = CRYPT_EAL_PkeyGetId(key);

    switch (id) {
        case CRYPT_PKEY_ECDH:
            return EcdhKeyGetPub(key, pubKeyBuf, bufLen, pubKeyLen);
        case CRYPT_PKEY_X25519:
            return X25519KeyGetPub(key, pubKeyBuf, bufLen, pubKeyLen);
#ifdef HITLS_TLS_SUITE_KX_DHE
        case CRYPT_PKEY_DH:
            return DhKeyGetPub(key, pubKeyBuf, bufLen, pubKeyLen);
#endif
#ifdef HITLS_TLS_PROTO_TLCP11
        case CRYPT_PKEY_SM2:
            return SM2KeyGetPub(key, pubKeyBuf, bufLen, pubKeyLen);
#endif
        default:
            *pubKeyLen = 0;
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16666, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "unknow id", 0, 0, 0, 0);
            break;
    }
    return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
#else
    (void)key;
    (void)pubKeyBuf;
    (void)bufLen;
    (void)pubKeyLen;
    return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
#endif
}

#ifdef HITLS_CRYPTO_PKEY
static int32_t SetPubData(CRYPT_EAL_PkeyPub *pub, uint8_t *peerPubkey, uint32_t pubKeyLen)
{
    switch (pub->id) {
        case CRYPT_PKEY_ECDH:
        case CRYPT_PKEY_SM2:
            pub->key.eccPub.data = peerPubkey;
            pub->key.eccPub.len = pubKeyLen;
            break;
        case CRYPT_PKEY_X25519:
            pub->key.curve25519Pub.data = peerPubkey;
            pub->key.curve25519Pub.len = pubKeyLen;
            break;
#ifdef HITLS_TLS_SUITE_KX_DHE
        case CRYPT_PKEY_DH:
            pub->key.dhPub.data = peerPubkey;
            pub->key.dhPub.len = pubKeyLen;
            break;
#endif
        default:
            return HITLS_CRYPT_ERR_CALC_SHARED_KEY;
    }
    return CRYPT_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_TLCP11
static int32_t SetSM2SelfCtx(CRYPT_EAL_PkeyCtx *selfCtx, HITLS_Sm2GenShareKeyParameters *sm2Params)
{
    uint8_t localPrvData[SM2_PRVKEY_LEN] = {0};
    CRYPT_EAL_PkeyPrv localPrv = { 0 };
    localPrv.id = CRYPT_PKEY_SM2;
    localPrv.key.eccPrv.data = localPrvData;
    localPrv.key.eccPrv.len = sizeof(localPrvData);

    int32_t ret = 0;
    ret = CRYPT_EAL_PkeyGetPrv(sm2Params->tmpPriKey, &localPrv);
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
    ret = CRYPT_EAL_PkeyCtrl(selfCtx, CRYPT_CTRL_SET_SM2_USER_ID, (void *)g_SM2DefaultUserid, SM2_DEFAULT_USERID_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16669, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SET_SM2_USER_ID fail", 0, 0, 0, 0);
        return ret;
    }
    int32_t server = sm2Params->isClient ? 0 : 1;
    return CRYPT_EAL_PkeyCtrl(selfCtx, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t));
}

static int32_t CalcSM2SecretPre(
    CRYPT_EAL_PkeyCtx *peerCtx, HITLS_Sm2GenShareKeyParameters *sm2Params, CRYPT_EAL_PkeyPub *peerPub)
{
    int32_t ret = CRYPT_EAL_PkeyGetPub(sm2Params->peerPubKey, peerPub);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16673, "GetPub fail");
    }
    ret = CRYPT_EAL_PkeySetPub(peerCtx, peerPub);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16674, "SetPub fail");
    }
    ret = CRYPT_EAL_PkeyCtrl(peerCtx, CRYPT_CTRL_SET_SM2_R, sm2Params->tmpPeerPubkey, sm2Params->tmpPeerPubKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16675, "SET_SM2_R fail");
    }
    ret = CRYPT_EAL_PkeyCtrl(peerCtx, CRYPT_CTRL_SET_SM2_USER_ID, (void *)g_SM2DefaultUserid, SM2_DEFAULT_USERID_LEN);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16676, "SET_SM2_USER_ID fail");
    }
    return CRYPT_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLCP11 */
#endif

#ifdef HITLS_TLS_PROTO_TLCP11
int32_t CRYPT_DEFAULT_CalcSM2SharedSecret(HITLS_Sm2GenShareKeyParameters *sm2Params, uint8_t *sharedSecret,
    uint32_t *sharedSecretLen)
{
#ifdef HITLS_CRYPTO_PKEY
    if (sm2Params->priKey == NULL || sm2Params->peerPubKey == NULL || sm2Params->tmpPriKey == NULL ||
        sm2Params->tmpPeerPubkey == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_CALC_SHARED_KEY, BINLOG_ID16670, "input null");
    }

    uint8_t peerPubData[SM2_PUBKEY_LEN] = {0};
    CRYPT_EAL_PkeyPub peerPub = { 0 };
    peerPub.id = CRYPT_PKEY_SM2;
    peerPub.key.eccPub.data = peerPubData;
    peerPub.key.eccPub.len = sizeof(peerPubData);

    CRYPT_EAL_PkeyCtx *selfCtx = (CRYPT_EAL_PkeyCtx *)sm2Params->priKey;
    int32_t ret = SetSM2SelfCtx(selfCtx, sm2Params);
    if (ret != CRYPT_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16671, "SetSM2SelfCtx fail");
    }

    CRYPT_EAL_PkeyCtx *peerCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (peerCtx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_CALC_SHARED_KEY, BINLOG_ID16672, "peerCtx new fail");
    }
    ret = CalcSM2SecretPre(peerCtx, sm2Params, &peerPub);
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
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}
#endif /* HITLS_TLS_PROTO_TLCP11 */

int32_t CRYPT_DEFAULT_CalcSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
#ifdef HITLS_CRYPTO_PKEY
    CRYPT_PKEY_AlgId id = CRYPT_EAL_PkeyGetId(key);

    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = id;
    int32_t ret = SetPubData(&pub, peerPubkey, pubKeyLen);
    if (ret != CRYPT_SUCCESS) {
        *sharedSecretLen = 0;
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16677, "SetPubData fail");
    }

    CRYPT_EAL_PkeyCtx *peerPk = CRYPT_EAL_PkeyNewCtx(id);
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

    ret = CRYPT_EAL_PkeySetPub(peerPk, &pub);
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
#else
    (void)key;
    (void)pubKeyLen;
    (void)peerPubkey;
    (void)sharedSecret;
    (void)sharedSecretLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

#ifdef HITLS_TLS_SUITE_KX_DHE
uint32_t GetDhParaIdBySecbits(int32_t secbits)
{
    if (secbits >= MIN_DH8192_SECBITS) {
        return CRYPT_DH_RFC3526_8192;
    }
    if (secbits >= MIN_DH4096_SECBITS) {
        return CRYPT_DH_RFC3526_4096;
    }
    if (secbits >= MIN_DH3072_SECBITS) {
        return CRYPT_DH_RFC3526_3072;
    }
    if (secbits >= MIN_DH2048_SECBITS) {
        return CRYPT_DH_RFC3526_2048;
    }
    return CRYPT_DH_RFC2409_1024;
}

HITLS_CRYPT_Key *CRYPT_DEFAULT_GenerateDhKeyBySecbits(int32_t secbits)
{
    CRYPT_PKEY_ParaId id = GetDhParaIdBySecbits(secbits);
    return GeneratePkeyByParaId(CRYPT_PKEY_DH, id);
}

HITLS_CRYPT_Key *CRYPT_DEFAULT_GenerateDhKeyByParameters(uint8_t *p, uint16_t pLen, uint8_t *g, uint16_t gLen)
{
#ifdef HITLS_CRYPTO_DH
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DH);
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
    return NULL;
#endif
}

int32_t CRYPT_DEFAULT_GetDhParameters(HITLS_CRYPT_Key *key, uint8_t *p, uint16_t *pLen, uint8_t *g, uint16_t *gLen)
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

int32_t CRYPT_DEFAULT_HkdfExtract(const HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen)
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

    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
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
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

int32_t CRYPT_DEFAULT_HkdfExpand(const HITLS_CRYPT_HkdfExpandInput *input, uint8_t *okm, uint32_t okmLen)
{
#ifdef HITLS_CRYPTO_HKDF
    int32_t ret;
    CRYPT_MAC_AlgId id = GetHmacAlgId(input->hashAlgo);
    if (id == CRYPT_MAC_MAX) {
        return HITLS_CRYPT_ERR_HMAC;
    }

    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
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
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}
#endif /* HITLS_TLS_CALLBACK_CRYPT */