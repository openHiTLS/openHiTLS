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

#include <string.h>
#include "securec.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
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

#ifndef HITLS_CRYPTO_EAL
#error "Missing definition of HITLS_CRYPTO_EAL"
#endif

#define MIN_DH8192_SECBITS 192
#define MIN_DH4096_SECBITS 152
#define MIN_DH3072_SECBITS 128
#define MIN_DH2048_SECBITS 112

#define MAX_PKEY_PARA_LEN 1024

#define CCM_TLS_TAG_LEN 16u
#define CCM8_TLS_TAG_LEN 8u

/* The default user id as specified in GM/T 0009-2012 */
char g_SM2DefaultUserid[] = "1234567812345678";
#define SM2_DEFAULT_USERID_LEN 16u
#define SM2_PUBKEY_LEN 65
#define SM2_PRVKEY_LEN 33

#ifdef HITLS_CRYPTO_MD
static uint32_t GetMDAlgId(HITLS_HashAlgo hashAlgo)
{
    switch (hashAlgo) {
        case HITLS_HASH_MD5:
            return CRYPT_MD_MD5;
        case HITLS_HASH_SHA1:
            return CRYPT_MD_SHA1;
        case HITLS_HASH_SHA_224:
            return CRYPT_MD_SHA224;
        case HITLS_HASH_SHA_256:
            return CRYPT_MD_SHA256;
        case HITLS_HASH_SHA_384:
            return CRYPT_MD_SHA384;
        case HITLS_HASH_SHA_512:
            return CRYPT_MD_SHA512;
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
        case HITLS_HASH_MD5:
            return CRYPT_MAC_HMAC_MD5;
        case HITLS_HASH_SHA1:
            return CRYPT_MAC_HMAC_SHA1;
        case HITLS_HASH_SHA_224:
            return CRYPT_MAC_HMAC_SHA224;
        case HITLS_HASH_SHA_256:
            return CRYPT_MAC_HMAC_SHA256;
        case HITLS_HASH_SHA_384:
            return CRYPT_MAC_HMAC_SHA384;
        case HITLS_HASH_SHA_512:
            return CRYPT_MAC_HMAC_SHA512;
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
        case HITLS_CIPHER_AES_128_CBC:
            return CRYPT_CIPHER_AES128_CBC;
        case HITLS_CIPHER_AES_256_CBC:
            return CRYPT_CIPHER_AES256_CBC;
        case HITLS_CIPHER_AES_128_GCM:
            return CRYPT_CIPHER_AES128_GCM;
        case HITLS_CIPHER_AES_256_GCM:
            return CRYPT_CIPHER_AES256_GCM;
        case HITLS_CIPHER_CHACHA20_POLY1305:
            return CRYPT_CIPHER_CHACHA20_POLY1305;
        case HITLS_CIPHER_AES_128_CCM:
        case HITLS_CIPHER_AES_128_CCM8:
            return CRYPT_CIPHER_AES128_CCM;
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
#ifdef HITLS_CRYPTO_MD
    CRYPT_MD_AlgId id = GetMDAlgId(hashAlgo);
    if (id == CRYPT_MD_MAX) {
        return 0;
    }
    return CRYPT_EAL_MdGetDigestSize(id);
#else
    (void)hashAlgo;
    return 0;
#endif
}

HITLS_HMAC_Ctx *CRYPT_DEFAULT_HMAC_Init(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len)
{
#ifdef HITLS_CRYPTO_MAC
    CRYPT_MAC_AlgId id = GetHmacAlgId(hashAlgo);
    if (id == CRYPT_MAC_MAX) {
        return NULL;
    }

    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(id);
    if (ctx == NULL) {
        return NULL;
    }

    int32_t ret = CRYPT_EAL_MacInit(ctx, key, len);
    if (ret != CRYPT_SUCCESS) {
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
    return CRYPT_EAL_MacUpdate(ctx, (uint8_t *)data, len);
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

int32_t CRYPT_DEFAULT_HMAC(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_MAC
    int32_t ret;
    CRYPT_MAC_AlgId id = GetHmacAlgId(hashAlgo);
    if (id == CRYPT_MAC_MAX) {
        return HITLS_CRYPT_ERR_HMAC;
    }

    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(id);
    if (ctx == NULL) {
        return HITLS_CRYPT_ERR_HMAC;
    }

    ret = CRYPT_EAL_MacInit(ctx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_MacUpdate(ctx, (uint8_t *)in, inLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_MacFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_MacFinal(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_MacFreeCtx(ctx);
        return ret;
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
        return NULL;
    }

    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(id);
    if (ctx == NULL) {
        return NULL;
    }

    int32_t ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
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
    return NULL;
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
    return NULL;
#endif
}

int32_t CRYPT_DEFAULT_Digest(HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_MD
    int32_t ret;
    CRYPT_MD_AlgId id = GetMDAlgId(hashAlgo);
    if (id == CRYPT_MD_MAX) {
        return HITLS_CRYPT_ERR_DIGEST;
    }

    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(id);
    if (ctx == NULL) {
        return HITLS_CRYPT_ERR_DIGEST;
    }

    ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_MdUpdate(ctx, in, inLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_MdFinal(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        return ret;
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

    if (cipher->algo == HITLS_CIPHER_AES_128_CCM8 || cipher->algo == HITLS_CIPHER_AES_256_CCM8) {
        uint32_t tagLen = CCM8_TLS_TAG_LEN;
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen));
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    // In the case of CCM processing, msgLen needs to be set.
    if ((cipher->algo == HITLS_CIPHER_AES_128_CCM) || (cipher->algo == HITLS_CIPHER_AES_128_CCM8) ||
        (cipher->algo == HITLS_CIPHER_AES_256_CCM) || (cipher->algo == HITLS_CIPHER_AES_256_CCM8)) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &inLen, sizeof(inLen));
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    if (cipher->type == HITLS_AEAD_CIPHER) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, cipher->aad, cipher->aadLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
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
    CRYPT_CIPHER_AlgId id = GetCipherAlgId(cipher->algo);
    if (id == CRYPT_CIPHER_MAX) {
        return HITLS_CRYPT_ERR_ENCRYPT;
    }

    *ctx = CRYPT_EAL_CipherNewCtx(id);
    if (*ctx == NULL) {
        return HITLS_CRYPT_ERR_ENCRYPT;
    }

    int32_t ret = CRYPT_EAL_CipherInit(*ctx, cipher->key, cipher->keyLen, cipher->iv, cipher->ivLen, enc);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(*ctx);
        return ret;
    }
    return CRYPT_SUCCESS;
}
#endif

int32_t CRYPT_DEFAULT_Encrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    CRYPT_EAL_CipherCtx *ctx = NULL;
    int32_t ret = GetCipherInitCtx(cipher, &ctx, true);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = SpecialModeEncryptPreSolve(ctx, cipher, inLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }

    uint32_t cipherLen = *outLen;
    ret = CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &cipherLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }

    if (*outLen < cipherLen) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        return HITLS_CRYPT_ERR_ENCRYPT;
    }

    uint32_t finLen = *outLen - cipherLen;
    if (cipher->type == HITLS_AEAD_CIPHER) {
        finLen = (cipher->algo == HITLS_CIPHER_AES_128_CCM8 || cipher->algo == HITLS_CIPHER_AES_256_CCM8) ?
            CCM8_TLS_TAG_LEN :
            CCM_TLS_TAG_LEN;
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, out + cipherLen, finLen);
    } else {
        ret = CRYPT_EAL_CipherFinal(ctx, out + cipherLen, &finLen);
    }
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }

    cipherLen += finLen;
    *outLen = cipherLen;

    CRYPT_EAL_CipherFreeCtx(ctx);
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
    uint32_t tagLen = (cipher->algo == HITLS_CIPHER_AES_128_CCM8 || cipher->algo == HITLS_CIPHER_AES_256_CCM8) ?
        CCM8_TLS_TAG_LEN :
        CCM_TLS_TAG_LEN;
    uint32_t cipherLen = inLen - tagLen;
    uint32_t plainLen = *outLen;

    int32_t ret = CRYPT_EAL_CipherUpdate(ctx, in, cipherLen, out, &plainLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (plainLen != cipherLen) {
        return HITLS_CRYPT_ERR_DECRYPT;
    }

    uint8_t tag[16u] = {0};
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (memcmp(tag, in + cipherLen, tagLen) != 0) {
        return HITLS_CRYPT_ERR_DECRYPT;
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

int32_t CbcDecrypt(CRYPT_EAL_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    int32_t ret;
    uint32_t plainLen = *outLen;

    ret = CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &plainLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (*outLen < plainLen) {
        return HITLS_CRYPT_ERR_DECRYPT;
    }

    uint32_t finLen = *outLen - plainLen;
    ret = CRYPT_EAL_CipherFinal(ctx, out + plainLen, &finLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
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

int32_t CRYPT_DEFAULT_Decrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_CRYPTO_CIPHER
    CRYPT_EAL_CipherCtx *ctx = NULL;
    int32_t ret = GetCipherInitCtx(cipher, &ctx, false);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t tagLen = CCM_TLS_TAG_LEN;
    if (cipher->algo == HITLS_CIPHER_AES_128_CCM8 || cipher->algo == HITLS_CIPHER_AES_256_CCM8) {
        tagLen = CCM8_TLS_TAG_LEN;
        /* The default value of tagLen is 16 for the ctx generated by the CRYPT_EAL_CipherNewCtx.
           Therefore, need to set this parameter again. */
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(ctx);
            return ret;
        }
    }
    if ((cipher->algo == HITLS_CIPHER_AES_128_CCM) || (cipher->algo == HITLS_CIPHER_AES_128_CCM8) ||
        (cipher->algo == HITLS_CIPHER_AES_256_CCM) || (cipher->algo == HITLS_CIPHER_AES_256_CCM8)) {
        // The length of the decrypted ciphertext consists of msgLen and tagLen, so tagLen needs to be subtracted.
        uint64_t msgLen = inLen - tagLen;
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(ctx);
            return ret;
        }
    }

    if (cipher->type == HITLS_AEAD_CIPHER) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, cipher->aad, cipher->aadLen);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(ctx);
            return ret;
        }
        ret = AeadDecrypt(ctx, cipher, in, inLen, out, outLen);
    } else if (cipher->type == HITLS_CBC_CIPHER) {
        ret = CbcDecrypt(ctx, in, inLen, out, outLen);
    } else {
        ret = HITLS_CRYPT_ERR_DECRYPT;
    }

    CRYPT_EAL_CipherFreeCtx(ctx);
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

#ifdef HITLS_CRYPTO_PKEY
CRYPT_EAL_PkeyCtx *GeneratePkeyByParaId(CRYPT_PKEY_AlgId algId, CRYPT_PKEY_ParaId paraId)
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(algId);
    if (pkey == NULL) {
        return NULL;
    }

    if (algId != CRYPT_PKEY_X25519 && algId != CRYPT_PKEY_SM2) {
        ret = CRYPT_EAL_PkeySetParaById(pkey, paraId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            return NULL;
        }
    }

    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }

    return pkey;
}
#endif

static CRYPT_EAL_PkeyCtx *GenerateKeyByNamedGroup(HITLS_NamedGroup groupId)
{
#ifdef HITLS_CRYPTO_PKEY
    switch (groupId) {
        case HITLS_EC_GROUP_SECP256R1:
            return GeneratePkeyByParaId(CRYPT_PKEY_ECDH, CRYPT_ECC_NISTP256);
        case HITLS_EC_GROUP_SECP384R1:
            return GeneratePkeyByParaId(CRYPT_PKEY_ECDH, CRYPT_ECC_NISTP384);
        case HITLS_EC_GROUP_SECP521R1:
            return GeneratePkeyByParaId(CRYPT_PKEY_ECDH, CRYPT_ECC_NISTP521);
        case HITLS_EC_GROUP_BRAINPOOLP256R1:
            return GeneratePkeyByParaId(CRYPT_PKEY_ECDH, CRYPT_ECC_BRAINPOOLP256R1);
        case HITLS_EC_GROUP_BRAINPOOLP384R1:
            return GeneratePkeyByParaId(CRYPT_PKEY_ECDH, CRYPT_ECC_BRAINPOOLP384R1);
        case HITLS_EC_GROUP_BRAINPOOLP512R1:
            return GeneratePkeyByParaId(CRYPT_PKEY_ECDH, CRYPT_ECC_BRAINPOOLP512R1);
        case HITLS_EC_GROUP_CURVE25519:
            return GeneratePkeyByParaId(CRYPT_PKEY_X25519, CRYPT_PKEY_PARAID_MAX);
        case HITLS_EC_GROUP_SM2:
            return GeneratePkeyByParaId(CRYPT_PKEY_SM2, CRYPT_ECC_SM2);
        case HITLS_FF_DHE_2048:
            return GeneratePkeyByParaId(CRYPT_PKEY_DH, CRYPT_DH_RFC7919_2048);
        case HITLS_FF_DHE_3072:
            return GeneratePkeyByParaId(CRYPT_PKEY_DH, CRYPT_DH_RFC7919_3072);
        case HITLS_FF_DHE_4096:
            return GeneratePkeyByParaId(CRYPT_PKEY_DH, CRYPT_DH_RFC7919_4096);
        case HITLS_FF_DHE_6144:
            return GeneratePkeyByParaId(CRYPT_PKEY_DH, CRYPT_DH_RFC7919_6144);
        case HITLS_FF_DHE_8192:
            return GeneratePkeyByParaId(CRYPT_PKEY_DH, CRYPT_DH_RFC7919_8192);
        default:
            break;
    }
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

HITLS_CRYPT_Key *CRYPT_DEFAULT_DupKey(HITLS_CRYPT_Key *key)
{
#ifdef HITLS_CRYPTO_PKEY
    return CRYPT_EAL_PkeyDupCtx(key);
#else
    (void)key;
    return NULL;
#endif
}

void CRYPT_DEFAULT_FreeKey(HITLS_CRYPT_Key *key)
{
#ifdef HITLS_CRYPTO_PKEY
    CRYPT_EAL_PkeyFreeCtx(key);
#endif
    (void)key;
    return;
}

static int32_t SM2KeyGetPub(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
#ifndef HITLS_CRYPTO_NO_PKEY
    CRYPT_EAL_PkeyPub pub;
    pub.id = CRYPT_PKEY_SM2;
    pub.key.eccPub.data = pubKeyBuf;
    pub.key.eccPub.len = bufLen;

    int32_t ret = CRYPT_EAL_PkeyGetPub(key, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
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

static int32_t EcdhKeyGetPub(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
#ifdef HITLS_CRYPTO_PKEY
    CRYPT_EAL_PkeyPub pub;
    pub.id = CRYPT_PKEY_ECDH;
    pub.key.eccPub.data = pubKeyBuf;
    pub.key.eccPub.len = bufLen;

    int32_t ret = CRYPT_EAL_PkeyGetPub(key, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
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
        return ret;
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

static int32_t DhKeyGetPub(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
#ifdef HITLS_CRYPTO_DH
    CRYPT_EAL_PkeyPub pub;
    pub.id = CRYPT_PKEY_DH;
    pub.key.dhPub.data = pubKeyBuf;
    pub.key.dhPub.len = bufLen;

    int32_t ret = CRYPT_EAL_PkeyGetPub(key, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
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

int32_t CRYPT_DEFAULT_GetPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
#ifdef HITLS_CRYPTO_PKEY
    CRYPT_PKEY_AlgId id = CRYPT_EAL_PkeyGetId(key);

    switch (id) {
        case CRYPT_PKEY_ECDH:
            return EcdhKeyGetPub(key, pubKeyBuf, bufLen, pubKeyLen);
        case CRYPT_PKEY_X25519:
            return X25519KeyGetPub(key, pubKeyBuf, bufLen, pubKeyLen);
        case CRYPT_PKEY_DH:
            return DhKeyGetPub(key, pubKeyBuf, bufLen, pubKeyLen);
        case CRYPT_PKEY_SM2:
            return SM2KeyGetPub(key, pubKeyBuf, bufLen, pubKeyLen);
        default:
            *pubKeyLen = 0;
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
        case CRYPT_PKEY_DH:
            pub->key.dhPub.data = peerPubkey;
            pub->key.dhPub.len = pubKeyLen;
            break;
        default:
            return HITLS_CRYPT_ERR_CALC_SHARED_KEY;
    }
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_PKEY
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
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(selfCtx, CRYPT_CTRL_SET_SM2_RANDOM, localPrv.key.eccPrv.data, localPrv.key.eccPrv.len);
    (void)memset_s(localPrvData, SM2_PRVKEY_LEN, 0, SM2_PRVKEY_LEN);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(selfCtx, CRYPT_CTRL_SET_SM2_USER_ID, (void *)g_SM2DefaultUserid, SM2_DEFAULT_USERID_LEN);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    int32_t server = sm2Params->isClient ? 0 : 1;
    ret = CRYPT_EAL_PkeyCtrl(selfCtx, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t));
    return ret;
}
#endif

int32_t CRYPT_DEFAULT_CalcSM2SharedSecret(HITLS_Sm2GenShareKeyParameters *sm2Params, uint8_t *sharedSecret,
    uint32_t *sharedSecretLen)
{
#ifdef HITLS_CRYPTO_PKEY
    int32_t ret = 0;

    if (sm2Params->priKey == NULL || sm2Params->peerPubKey == NULL || sm2Params->tmpPriKey == NULL ||
        sm2Params->tmpPeerPubkey == NULL) {
        return HITLS_CRYPT_ERR_CALC_SHARED_KEY;
    }

    uint8_t peerPubData[SM2_PUBKEY_LEN] = {0};
    CRYPT_EAL_PkeyPub peerPub = { 0 };
    peerPub.id = CRYPT_PKEY_SM2;
    peerPub.key.eccPub.data = peerPubData;
    peerPub.key.eccPub.len = sizeof(peerPubData);

    CRYPT_EAL_PkeyCtx *selfCtx = (CRYPT_EAL_PkeyCtx *)sm2Params->priKey;
    ret = SetSM2SelfCtx(selfCtx, sm2Params);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_EAL_PkeyCtx *peerCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (peerCtx == NULL) {
        return HITLS_CRYPT_ERR_CALC_SHARED_KEY;
    }
    ret = CRYPT_EAL_PkeyGetPub(sm2Params->peerPubKey, &peerPub);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }
    ret = CRYPT_EAL_PkeySetPub(peerCtx, &peerPub);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }
    ret = CRYPT_EAL_PkeyCtrl(peerCtx, CRYPT_CTRL_SET_SM2_R, sm2Params->tmpPeerPubkey, sm2Params->tmpPeerPubKeyLen);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }
    ret = CRYPT_EAL_PkeyCtrl(peerCtx, CRYPT_CTRL_SET_SM2_USER_ID, (void *)g_SM2DefaultUserid, SM2_DEFAULT_USERID_LEN);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }
    ret = CRYPT_EAL_PkeyComputeShareKey(selfCtx, peerCtx, sharedSecret, sharedSecretLen);
Exit:
    CRYPT_EAL_PkeyFreeCtx(peerCtx);
    return ret;
#else
    (void)sm2Params;
    (void)sharedSecret;
    (void)sharedSecretLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

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
        return ret;
    }

    CRYPT_EAL_PkeyCtx *peerPk = CRYPT_EAL_PkeyNewCtx(id);
    if (peerPk == NULL) {
        return HITLS_CRYPT_ERR_CALC_SHARED_KEY;
    }

    if (id == CRYPT_PKEY_ECDH) {
        CRYPT_PKEY_ParaId paraId = CRYPT_EAL_PkeyGetParaId(key);
        if (paraId == CRYPT_PKEY_PARAID_MAX) {
            ret = CRYPT_EAL_ERR_ALGID;
            goto Exit;
        }
        ret = CRYPT_EAL_PkeySetParaById(peerPk, paraId);
        if (ret != CRYPT_SUCCESS) {
            goto Exit;
        }
    }

    ret = CRYPT_EAL_PkeySetPub(peerPk, &pub);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    ret = CRYPT_EAL_PkeyComputeShareKey(key, peerPk, sharedSecret, sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    ret = HITLS_SUCCESS;
Exit:
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
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }

    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
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

    int32_t ret = CRYPT_EAL_PkeyGetPara(key, &para);
    if (ret != CRYPT_SUCCESS) {
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

int32_t CRYPT_DEFAULT_HkdfExtract(const HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen)
{
#ifdef HITLS_CRYPTO_HKDF
    int32_t ret;
    uint32_t tmpLen = *prkLen;
    CRYPT_MAC_AlgId id = GetHmacAlgId(input->hashAlgo);
    if (id == CRYPT_MAC_MAX) {
        return HITLS_CRYPT_ERR_HMAC;
    }

    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (kdfCtx == NULL) {
        return HITLS_CRYPT_ERR_HKDF_EXTRACT;
    }

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &id, sizeof(id)};
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, &macAlgIdParam);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXTRACT;
    CRYPT_Param modeParam = {CRYPT_KDF_PARAM_MODE, &mode, sizeof(mode)};
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, &modeParam);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    CRYPT_Param keyParam = {CRYPT_KDF_PARAM_KEY, (void *)input->ikm, input->ikmLen};
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, &keyParam);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    CRYPT_Param saltParam = {CRYPT_KDF_PARAM_SALT, (void *)input->salt, input->saltLen};
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, &saltParam);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    CRYPT_Param outLenParam = {CRYPT_KDF_PARAM_OUTLEN,  &tmpLen, 0};
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, &outLenParam);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    ret = CRYPT_EAL_KdfDerive(kdfCtx, prk, tmpLen);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    *prkLen = tmpLen;
    ret = HITLS_SUCCESS;
Exit:
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

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &id, sizeof(id)};
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, &macAlgIdParam);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXPAND;
    CRYPT_Param modeParam = {CRYPT_KDF_PARAM_MODE, &mode, sizeof(mode)};
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, &modeParam);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    CRYPT_Param prkParam = {CRYPT_KDF_PARAM_PRK, (void *)input->prk, input->prkLen};
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, &prkParam);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    CRYPT_Param infoParam = {CRYPT_KDF_PARAM_INFO, (void *)input->info, input->infoLen};
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, &infoParam);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    ret = CRYPT_EAL_KdfDerive(kdfCtx, okm, okmLen);
    if (ret != CRYPT_SUCCESS) {
        goto Exit;
    }

    ret = HITLS_SUCCESS;
Exit:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    return ret;
#else
    (void)input;
    (void)okm;
    (void)okmLen;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}