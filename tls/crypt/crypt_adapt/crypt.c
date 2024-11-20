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
#include <stddef.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "hitls_crypt_reg.h"
#include "crypt.h"

HITLS_CRYPT_BaseMethod g_cryptBaseMethod = {0};
HITLS_CRYPT_EcdhMethod g_cryptEcdhMethod = {0};
HITLS_CRYPT_DhMethod g_cryptDhMethod = {0};
#ifdef HITLS_TLS_PROTO_TLS13
#define TLS13_MAX_LABEL_LEN 255
#define TLS13_MAX_CTX_LEN 255

#define TLS13_HKDF_LABEL_LEN(labelLen, ctxLen) \
    (sizeof(uint16_t) + sizeof(uint8_t) + (labelLen) + sizeof(uint8_t) + (ctxLen))

#define TLS13_MAX_HKDF_LABEL_LEN TLS13_HKDF_LABEL_LEN(TLS13_MAX_LABEL_LEN, TLS13_MAX_CTX_LEN)

HITLS_CRYPT_KdfMethod g_cryptKdfMethod = {0};

typedef struct {
    uint16_t length;        /* Length of the derived key */
    uint8_t labelLen;       /* Label length */
    uint8_t ctxLen;         /* Length of the context information */
    const uint8_t *label;   /* Label */
    const uint8_t *ctx;     /* Context information */
} HkdfLabel;
#endif

const char *g_cryptCallBackStr[] = {
    [HITLS_CRYPT_CALLBACK_RAND_BYTES] = "random bytes",
    [HITLS_CRYPT_CALLBACK_HMAC_SIZE] = "hmac size",
    [HITLS_CRYPT_CALLBACK_HMAC_INIT] = "hmac init",
    [HITLS_CRYPT_CALLBACK_HMAC_FREE] = "hmac free",
    [HITLS_CRYPT_CALLBACK_HMAC_UPDATE] = "hmac update",
    [HITLS_CRYPT_CALLBACK_HMAC_FINAL] = "hmac final",
    [HITLS_CRYPT_CALLBACK_HMAC] = "hmac calc",
    [HITLS_CRYPT_CALLBACK_DIGEST_SIZE] = "digest size",
    [HITLS_CRYPT_CALLBACK_DIGEST_INIT] = "digest init",
    [HITLS_CRYPT_CALLBACK_DIGEST_COPY] = "digest copy",
    [HITLS_CRYPT_CALLBACK_DIGEST_FREE] = "digest free",
    [HITLS_CRYPT_CALLBACK_DIGEST_UPDATE] = "digest update",
    [HITLS_CRYPT_CALLBACK_DIGEST_FINAL] = "digest final",
    [HITLS_CRYPT_CALLBACK_DIGEST] = "digest calc",
    [HITLS_CRYPT_CALLBACK_ENCRYPT] = "encrypt",
    [HITLS_CRYPT_CALLBACK_DECRYPT] = "decrpt",

    [HITLS_CRYPT_CALLBACK_GENERATE_ECDH_KEY_PAIR] = "generate ecdh key",
    [HITLS_CRYPT_CALLBACK_FREE_ECDH_KEY] = "free ecdh key",
    [HITLS_CRYPT_CALLBACK_GET_ECDH_ENCODED_PUBKEY] = "get ecdh public key",
    [HITLS_CRYPT_CALLBACK_CALC_ECDH_SHARED_SECRET] = "calculate ecdh shared secret",
    [HITLS_CRYPT_CALLBACK_SM2_CALC_ECDH_SHARED_SECRET] = "calculate sm2 ecdh shared secret",

    [HITLS_CRYPT_CALLBACK_GENERATE_DH_KEY_BY_SECBITS] = "generate Dh key by secbits",
    [HITLS_CRYPT_CALLBACK_GENERATE_DH_KEY_BY_PARAMS] = "generate Dh key by params",
    [HITLS_CRYPT_CALLBACK_DUP_DH_KEY] = "dup Dh key",
    [HITLS_CRYPT_CALLBACK_FREE_DH_KEY] = "free Dh key",
    [HITLS_CRYPT_CALLBACK_DH_GET_PARAMETERS] = "get dh params",
    [HITLS_CRYPT_CALLBACK_GET_DH_ENCODED_PUBKEY] = "get dh public key",
    [HITLS_CRYPT_CALLBACK_CALC_DH_SHARED_SECRET] = "calculate dh shared secret",

    [HITLS_CRYPT_CALLBACK_HKDF_EXTRACT] = "HKDF-Extract",
    [HITLS_CRYPT_CALLBACK_HKDF_EXPAND] = "HKDF-Expand",
};

int32_t HITLS_CRYPT_RegisterBaseMethod(HITLS_CRYPT_BaseMethod *userCryptCallBack)
{
    if (userCryptCallBack == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15063, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Register base crypt method error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    g_cryptBaseMethod.randBytes = userCryptCallBack->randBytes;
    g_cryptBaseMethod.hmacSize = userCryptCallBack->hmacSize;
    g_cryptBaseMethod.hmacInit = userCryptCallBack->hmacInit;
    g_cryptBaseMethod.hmacReinit = userCryptCallBack->hmacReinit;
    g_cryptBaseMethod.hmacFree = userCryptCallBack->hmacFree;
    g_cryptBaseMethod.hmacUpdate = userCryptCallBack->hmacUpdate;
    g_cryptBaseMethod.hmacFinal = userCryptCallBack->hmacFinal;
    g_cryptBaseMethod.hmac = userCryptCallBack->hmac;
    g_cryptBaseMethod.digestSize = userCryptCallBack->digestSize;
    g_cryptBaseMethod.digestInit = userCryptCallBack->digestInit;
    g_cryptBaseMethod.digestCopy = userCryptCallBack->digestCopy;
    g_cryptBaseMethod.digestFree = userCryptCallBack->digestFree;
    g_cryptBaseMethod.digestUpdate = userCryptCallBack->digestUpdate;
    g_cryptBaseMethod.digestFinal = userCryptCallBack->digestFinal;
    g_cryptBaseMethod.digest = userCryptCallBack->digest;
    g_cryptBaseMethod.encrypt = userCryptCallBack->encrypt;
    g_cryptBaseMethod.decrypt = userCryptCallBack->decrypt;
    g_cryptBaseMethod.cipherFree = userCryptCallBack->cipherFree;
    return HITLS_SUCCESS;
}

int32_t HITLS_CRYPT_RegisterEcdhMethod(HITLS_CRYPT_EcdhMethod *userCryptCallBack)
{
    if (userCryptCallBack == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15064, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Register ECDH crypt method error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    g_cryptEcdhMethod.generateEcdhKeyPair = userCryptCallBack->generateEcdhKeyPair;
    g_cryptEcdhMethod.freeEcdhKey = userCryptCallBack->freeEcdhKey;
    g_cryptEcdhMethod.getEcdhPubKey = userCryptCallBack->getEcdhPubKey;
    g_cryptEcdhMethod.calcEcdhSharedSecret = userCryptCallBack->calcEcdhSharedSecret;
#ifdef HITLS_TLS_PROTO_TLCP11
    g_cryptEcdhMethod.sm2CalEcdhSharedSecret = userCryptCallBack->sm2CalEcdhSharedSecret;
#endif /* HITLS_TLS_PROTO_TLCP11 */
    return HITLS_SUCCESS;
}

int32_t HITLS_CRYPT_RegisterDhMethod(const HITLS_CRYPT_DhMethod *userCryptCallBack)
{
    if (userCryptCallBack == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Register Dh crypt method error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    g_cryptDhMethod.getDhParameters = userCryptCallBack->getDhParameters;
    g_cryptDhMethod.generateDhKeyBySecbits = userCryptCallBack->generateDhKeyBySecbits;
    g_cryptDhMethod.generateDhKeyByParams = userCryptCallBack->generateDhKeyByParams;
    g_cryptDhMethod.freeDhKey = userCryptCallBack->freeDhKey;
    g_cryptDhMethod.getDhPubKey = userCryptCallBack->getDhPubKey;
    g_cryptDhMethod.calcDhSharedSecret = userCryptCallBack->calcDhSharedSecret;
#ifdef HITLS_TLS_CONFIG_MANUAL_DH
    g_cryptDhMethod.dupDhKey = userCryptCallBack->dupDhKey;
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_TLS13
int32_t HITLS_CRYPT_RegisterHkdfMethod(HITLS_CRYPT_KdfMethod *userCryptCallBack)
{
    if (userCryptCallBack == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15066, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Register HKDF crypt method error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    g_cryptKdfMethod.hkdfExtract = userCryptCallBack->hkdfExtract;
    g_cryptKdfMethod.hkdfExpand = userCryptCallBack->hkdfExpand;
    return HITLS_SUCCESS;
}
#endif

int32_t CheckCallBackRetVal(int32_t cmd, int32_t callBackRet, uint32_t bingLogId, uint32_t hitlsRet)
{
    if (callBackRet != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(bingLogId, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "%s error: callback ret = 0x%x.", g_cryptCallBackStr[cmd], callBackRet, 0, 0);
        BSL_ERR_PUSH_ERROR((int32_t)hitlsRet);
        return (int32_t)hitlsRet;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_Rand(uint8_t *buf, uint32_t len)
{
    int32_t ret = g_cryptBaseMethod.randBytes(buf, len);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_RAND_BYTES, ret, BINLOG_ID15068,
        HITLS_CRYPT_ERR_GENERATE_RANDOM);
}

uint32_t SAL_CRYPT_HmacSize(HITLS_HashAlgo hashAlgo)
{
    return g_cryptBaseMethod.hmacSize(hashAlgo);
}

#ifdef HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES
HITLS_HMAC_Ctx *SAL_CRYPT_HmacInit(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len)
{
    return g_cryptBaseMethod.hmacInit(hashAlgo, key, len);
}

void SAL_CRYPT_HmacFree(HITLS_HMAC_Ctx *hmac)
{
    if (hmac != NULL) {
        g_cryptBaseMethod.hmacFree(hmac);
    }
    return;
}

int32_t SAL_CRYPT_HmacReInit(HITLS_HMAC_Ctx *ctx)
{
    return g_cryptBaseMethod.hmacReinit(ctx);
}

int32_t SAL_CRYPT_HmacUpdate(HITLS_HMAC_Ctx *hmac, const uint8_t *data, uint32_t len)
{
    int32_t ret = g_cryptBaseMethod.hmacUpdate(hmac, data, len);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_HMAC_UPDATE, ret, BINLOG_ID15073, HITLS_CRYPT_ERR_HMAC);
}

int32_t SAL_CRYPT_HmacFinal(HITLS_HMAC_Ctx *hmac, uint8_t *out, uint32_t *len)
{
    int32_t ret = g_cryptBaseMethod.hmacFinal(hmac, out, len);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_HMAC_FINAL, ret, BINLOG_ID15075, HITLS_CRYPT_ERR_HMAC);
}
#endif /* HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES */

int32_t SAL_CRYPT_Hmac(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = g_cryptBaseMethod.hmac(hashAlgo, key, keyLen, in, inLen, out, outLen);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_HMAC, ret, BINLOG_ID15077, HITLS_CRYPT_ERR_HMAC);
}

static int32_t IteratorInit(CRYPT_KeyDeriveParameters *input, uint32_t hmacSize,
    uint8_t **iterator, uint32_t *iteratorSize)
{
    uint8_t *seed = BSL_SAL_Calloc(1u, hmacSize + input->labelLen + input->seedLen);
    if (seed == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15078, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "P_Hash error: out of memory.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    (void)memcpy_s(&seed[hmacSize], input->labelLen, input->label, input->labelLen);
    (void)memcpy_s(&seed[hmacSize + input->labelLen], input->seedLen, input->seed, input->seedLen);

    int32_t ret = SAL_CRYPT_Hmac(input->hashAlgo, input->secret, input->secretLen,
        &seed[hmacSize], input->labelLen + input->seedLen, seed, &hmacSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15079, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "P_Hash error: iterator init fail, HMAC ret = 0x%x.", ret, 0, 0, 0);
        BSL_SAL_FREE(seed);
        return ret;
    }
    *iterator = seed;
    *iteratorSize = hmacSize + input->labelLen + input->seedLen;
    return HITLS_SUCCESS;
}

static int32_t PHashPre(uint32_t *hmacSize, uint32_t *alignLen, uint32_t outLen, HITLS_HashAlgo hashAlgo)
{
    if (hmacSize == NULL || alignLen == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16611, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    *alignLen = outLen;
    *hmacSize = SAL_CRYPT_HmacSize(hashAlgo);
    if (*hmacSize == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15080, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "P_Hash error: hmac size is zero.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_HMAC);
        return HITLS_CRYPT_ERR_HMAC;
    }
    if ((outLen % *hmacSize) != 0) {
        /* Padded based on the HMAC length. */
        *alignLen += *hmacSize - (outLen % *hmacSize);
    }
    return HITLS_SUCCESS;
}

int32_t P_Hash(CRYPT_KeyDeriveParameters *input, uint8_t *out, uint32_t outLen)
{
    uint8_t *iterator = NULL;
    uint32_t iteratorSize = 0;
    uint8_t *data = NULL;
    uint32_t alignLen;
    uint32_t srcLen = outLen;
    uint32_t offset = 0;
    uint32_t hmacSize;
    int32_t ret = PHashPre(&hmacSize, &alignLen, outLen, input->hashAlgo);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16612, "PHashPre fail");
    }
    data = BSL_SAL_Calloc(1u, alignLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID15081, "Calloc fail");
    }

    uint32_t tmpLen = hmacSize;
    ret = IteratorInit(input, hmacSize, &iterator, &iteratorSize);
    if (ret != HITLS_SUCCESS) {
        (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16613, "IteratorInit fail");
        goto PHASH_END;
    }

    while (alignLen > 0) {
        ret = SAL_CRYPT_Hmac(input->hashAlgo, input->secret, input->secretLen,
            iterator, iteratorSize, data + offset, &tmpLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15082, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "P_Hash error: produce output data fail, HMAC ret = 0x%x.", ret, 0, 0, 0);
            goto PHASH_END;
        }

        alignLen -= tmpLen;
        offset += tmpLen;

        ret = SAL_CRYPT_Hmac(input->hashAlgo, input->secret, input->secretLen, iterator, tmpLen, iterator, &tmpLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15083, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "P_Hash error: iterator update fail, HMAC ret = 0x%x.", ret, 0, 0, 0);
            goto PHASH_END;
        }
    }

    if (memcpy_s(out, outLen, data, srcLen) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16614, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        ret = HITLS_MEMCPY_FAIL;
    }
PHASH_END:
    BSL_SAL_FREE(iterator);
    BSL_SAL_FREE(data);
    return ret;
}

#if defined(HITLS_CRYPTO_MD5) && defined(HITLS_CRYPTO_SHA1)
int32_t PRF_MD5_SHA1(CRYPT_KeyDeriveParameters *input, uint8_t *out, uint32_t outLen)
{
    uint32_t secretLen = input->secretLen;
    const uint8_t *secret = input->secret;
    int32_t ret;
    uint32_t i;

    /* The key is divided into two parts. The first part is the MD5 key, and the second part is the SHA1 key.
       If the value is an odd number, for example, 7, the first half of the key is [1, 4]
       and the second half of the key is [4, 7]. Both keys have the fourth byte. */
    input->secretLen = ((secretLen + 1) >> 1);
    input->hashAlgo = HITLS_HASH_MD5;
    ret = P_Hash(input, out, outLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16615, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "P_Hash fail", 0, 0, 0, 0);
        return ret;
    }

    uint8_t *sha1data = BSL_SAL_Calloc(1u, outLen);
    if (sha1data == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15084, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PRF_MD5_SHA1 error: out of memory.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    input->secret += (secretLen >> 1);
    input->hashAlgo = HITLS_HASH_SHA1;
    ret = P_Hash(input, sha1data, outLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16616, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "P_Hash fail", 0, 0, 0, 0);
        BSL_SAL_FREE(sha1data);
        return ret;
    }

    for (i = 0; i < outLen; i++) {
        out[i] ^= sha1data[i];
    }

    input->secret = secret;
    input->secretLen = secretLen;

    BSL_SAL_FREE(sha1data);
    return HITLS_SUCCESS;
}
#endif /* HITLS_CRYPTO_MD5 && HITLS_CRYPTO_SHA1 */

int32_t SAL_CRYPT_PRF(CRYPT_KeyDeriveParameters *input, uint8_t *out, uint32_t outLen)
{
#if defined(HITLS_CRYPTO_MD5) && defined(HITLS_CRYPTO_SHA1)
    // TLS1.0、TLS1.1
    if (input->hashAlgo == HITLS_HASH_MD5_SHA1) {
        return PRF_MD5_SHA1(input, out, outLen);
    }
#endif

    // Other versions
    if (input->hashAlgo < HITLS_HASH_SHA_256) {
        /* The PRF function must use the digest algorithm with SHA-256 or higher strength. */
        input->hashAlgo = HITLS_HASH_SHA_256;
    }

    return P_Hash(input, out, outLen);
}


HITLS_HASH_Ctx *SAL_CRYPT_DigestInit(HITLS_HashAlgo hashAlgo)
{
    return g_cryptBaseMethod.digestInit(hashAlgo);
}

HITLS_HASH_Ctx *SAL_CRYPT_DigestCopy(HITLS_HASH_Ctx *ctx)
{
    return g_cryptBaseMethod.digestCopy(ctx);
}

void SAL_CRYPT_DigestFree(HITLS_HASH_Ctx *ctx)
{
    if (ctx != NULL) {
        g_cryptBaseMethod.digestFree(ctx);
    }
    return;
}

int32_t SAL_CRYPT_DigestUpdate(HITLS_HASH_Ctx *ctx, const uint8_t *data, uint32_t len)
{
    int32_t ret = g_cryptBaseMethod.digestUpdate(ctx, data, len);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_DIGEST_UPDATE, ret, BINLOG_ID15090,
        HITLS_CRYPT_ERR_DIGEST);
}

int32_t SAL_CRYPT_DigestFinal(HITLS_HASH_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    int32_t ret = g_cryptBaseMethod.digestFinal(ctx, out, len);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_DIGEST_FINAL, ret, BINLOG_ID15092,
        HITLS_CRYPT_ERR_DIGEST);
}

#ifdef HITLS_TLS_PROTO_TLS13
uint32_t SAL_CRYPT_DigestSize(HITLS_HashAlgo hashAlgo)
{
    return g_cryptBaseMethod.digestSize(hashAlgo);
}

int32_t SAL_CRYPT_Digest(HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = g_cryptBaseMethod.digest(hashAlgo, in, inLen, out, outLen);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_DIGEST, ret, BINLOG_ID15094, HITLS_CRYPT_ERR_DIGEST);
}
#endif

int32_t SAL_CRYPT_Encrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    int32_t ret = g_cryptBaseMethod.encrypt(cipher, in, inLen, out, outLen);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_ENCRYPT, ret, BINLOG_ID15096, HITLS_CRYPT_ERR_ENCRYPT);
}

int32_t SAL_CRYPT_Decrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    int32_t ret = g_cryptBaseMethod.decrypt(cipher, in, inLen, out, outLen);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_DECRYPT, ret, BINLOG_ID15098, HITLS_CRYPT_ERR_DECRYPT);
}

void SAL_CRYPT_CipherFree(HITLS_Cipher_Ctx *ctx)
{
    if (g_cryptBaseMethod.cipherFree != NULL) {
        g_cryptBaseMethod.cipherFree(ctx);
    }
}

HITLS_CRYPT_Key *SAL_CRYPT_GenEcdhKeyPair(const HITLS_ECParameters *curveParams)
{
    return g_cryptEcdhMethod.generateEcdhKeyPair(curveParams);
}

void SAL_CRYPT_FreeEcdhKey(HITLS_CRYPT_Key *key)
{
    if (key != NULL) {
        g_cryptEcdhMethod.freeEcdhKey(key);
    }
    return;
}

int32_t SAL_CRYPT_EncodeEcdhPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = g_cryptEcdhMethod.getEcdhPubKey(key, pubKeyBuf, bufLen, usedLen);
    return CheckCallBackRetVal(
        HITLS_CRYPT_CALLBACK_GET_ECDH_ENCODED_PUBKEY, ret, BINLOG_ID15102, HITLS_CRYPT_ERR_ENCODE_ECDH_KEY);
}

int32_t SAL_CRYPT_CalcEcdhSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    int32_t ret = g_cryptEcdhMethod.calcEcdhSharedSecret(key, peerPubkey, pubKeyLen, sharedSecret, sharedSecretLen);
    return CheckCallBackRetVal(
        HITLS_CRYPT_CALLBACK_CALC_ECDH_SHARED_SECRET, ret, BINLOG_ID15104, HITLS_CRYPT_ERR_CALC_SHARED_KEY);
}

#ifdef HITLS_TLS_PROTO_TLCP11
int32_t SAL_CRYPT_CalcSm2dhSharedSecret(HITLS_Sm2GenShareKeyParameters *sm2ShareKeyParam, uint8_t *sharedSecret,
                                        uint32_t *sharedSecretLen)
{
    int32_t ret = g_cryptEcdhMethod.sm2CalEcdhSharedSecret(sm2ShareKeyParam, sharedSecret, sharedSecretLen);
    return CheckCallBackRetVal(
        HITLS_CRYPT_CALLBACK_SM2_CALC_ECDH_SHARED_SECRET, ret, BINLOG_ID16212,
        HITLS_CRYPT_ERR_ENCODE_ECDH_KEY);
}
#endif /* HITLS_TLS_PROTO_TLCP11 */

HITLS_CRYPT_Key *SAL_CRYPT_GenerateDhKeyByParams(uint8_t *p, uint16_t plen, uint8_t *g, uint16_t glen)
{
    return g_cryptDhMethod.generateDhKeyByParams(p, plen, g, glen);
}

HITLS_CRYPT_Key *SAL_CRYPT_GenerateDhKeyBySecbits(int32_t secbits)
{
    return g_cryptDhMethod.generateDhKeyBySecbits(secbits);
}

#ifdef HITLS_TLS_CONFIG_MANUAL_DH
HITLS_CRYPT_Key *SAL_CRYPT_DupDhKey(HITLS_CRYPT_Key *key)
{
    return g_cryptDhMethod.dupDhKey(key);
}
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */

void SAL_CRYPT_FreeDhKey(HITLS_CRYPT_Key *key)
{
    if (key != NULL) {
        g_cryptDhMethod.freeDhKey(key);
    }
    return;
}

int32_t SAL_CRYPT_GetDhParameters(HITLS_CRYPT_Key *key, uint8_t *p, uint16_t *plen, uint8_t *g, uint16_t *glen)
{
    return g_cryptDhMethod.getDhParameters(key, p, plen, g, glen);
}

int32_t SAL_CRYPT_EncodeDhPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = g_cryptDhMethod.getDhPubKey(key, pubKeyBuf, bufLen, usedLen);
    return CheckCallBackRetVal(
        HITLS_CRYPT_CALLBACK_GET_DH_ENCODED_PUBKEY, ret, BINLOG_ID15110, HITLS_CRYPT_ERR_ENCODE_DH_KEY);
}

int32_t SAL_CRYPT_CalcDhSharedSecret(
    HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen, uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    int32_t ret = g_cryptDhMethod.calcDhSharedSecret(key, peerPubkey, pubKeyLen, sharedSecret, sharedSecretLen);
    return CheckCallBackRetVal(
        HITLS_CRYPT_CALLBACK_CALC_DH_SHARED_SECRET, ret, BINLOG_ID15112, HITLS_CRYPT_ERR_CALC_SHARED_KEY);
}

#ifdef HITLS_TLS_PROTO_TLS13
int32_t SAL_CRYPT_HkdfExtract(HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen)
{
    int32_t ret = g_cryptKdfMethod.hkdfExtract(input, prk, prkLen);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_HKDF_EXTRACT, ret, BINLOG_ID15114,
        HITLS_CRYPT_ERR_HKDF_EXTRACT);
}

int32_t SAL_CRYPT_HkdfExpand(HITLS_CRYPT_HkdfExpandInput *input, uint8_t *okm, uint32_t okmLen)
{
    int32_t ret = g_cryptKdfMethod.hkdfExpand(input, okm, okmLen);
    return CheckCallBackRetVal(HITLS_CRYPT_CALLBACK_HKDF_EXPAND, ret, BINLOG_ID15116,
        HITLS_CRYPT_ERR_HKDF_EXPAND);
}

/*
 * 2 bytes for length of derived secret + 1 byte for length of combined
 * prefix and label + bytes for the label itself + 1 byte length of hash
 * + bytes for the hash itself
 */
static int32_t SAL_CRYPT_EncodeHkdfLabel(HkdfLabel *hkdfLabel, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    char labelPrefix[] = "tls13 ";
    size_t labelPrefixLen = strlen(labelPrefix);
    uint32_t offset = 0;

    BSL_Uint16ToByte(hkdfLabel->length, buf);
    offset += sizeof(uint16_t);
    /* The truncation won't happen, as the label length will not be greater than 64, all possible labels are as follows:
     * "ext binder", "res binder", "finished", "c e traffic", "e exp master", "derived", "c hs traffic", "s hs traffic"
     * "finished", "derived", "c ap traffic", "s ap traffic", "exp master", "finished", "res master",
     * "TLS 1.3,serverCertificateVerify", "TLS 1.3,clientCertificateVerify".
     */
    buf[offset] = (uint8_t)(hkdfLabel->labelLen + labelPrefixLen);
    offset += sizeof(uint8_t);

    if (memcpy_s(&buf[offset], bufLen - offset, labelPrefix, labelPrefixLen) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15117, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Encode HkdfLabel error: memcpy fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }
    offset += (uint32_t)labelPrefixLen;
    if (hkdfLabel->labelLen != 0 &&
        memcpy_s(&buf[offset], bufLen - offset, hkdfLabel->label, hkdfLabel->labelLen) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15118, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Encode HkdfLabel error: memcpy fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }
    offset += hkdfLabel->labelLen;

    buf[offset] = hkdfLabel->ctxLen;
    offset += sizeof(uint8_t);
    if (hkdfLabel->ctxLen != 0) {
        if (memcpy_s(&buf[offset], bufLen - offset, hkdfLabel->ctx, hkdfLabel->ctxLen) != EOK) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15119, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Encode HkdfLabel error: memcpy fail", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            return HITLS_MEMCPY_FAIL;
        }
        offset += hkdfLabel->ctxLen;
    }
    *usedLen = offset;
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_HkdfExpandLabel(CRYPT_KeyDeriveParameters *deriveInfo, uint8_t *outSecret, uint32_t outLen)
{
    uint8_t hkdfLabel[TLS13_MAX_HKDF_LABEL_LEN] = {0};
    uint32_t hkdfLabelLen = 0;

    HkdfLabel info = {0};
    info.length = (uint16_t)outLen;
    info.labelLen = (uint8_t)deriveInfo->labelLen;
    info.ctxLen = (uint8_t)deriveInfo->seedLen;
    info.label = deriveInfo->label;
    info.ctx = deriveInfo->seed;
    int32_t ret = SAL_CRYPT_EncodeHkdfLabel(&info, hkdfLabel, TLS13_MAX_HKDF_LABEL_LEN, &hkdfLabelLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16617, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "EncodeHkdfLabel fail", 0, 0, 0, 0);
        return ret;
    }

    HITLS_CRYPT_HkdfExpandInput expandInput = {0};
    expandInput.hashAlgo = deriveInfo->hashAlgo;
    expandInput.prk = deriveInfo->secret;
    expandInput.prkLen = deriveInfo->secretLen;
    expandInput.info = hkdfLabel;
    expandInput.infoLen = hkdfLabelLen;
    return SAL_CRYPT_HkdfExpand(&expandInput, outSecret, outLen);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
