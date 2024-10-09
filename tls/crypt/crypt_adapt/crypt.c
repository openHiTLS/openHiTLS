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

#define TLS13_MAX_LABEL_LEN 255
#define TLS13_MAX_CTX_LEN 255

#define TLS13_HKDF_LABEL_LEN(labelLen, ctxLen) \
    (sizeof(uint16_t) + sizeof(uint8_t) + (labelLen) + sizeof(uint8_t) + (ctxLen))

#define TLS13_MAX_HKDF_LABEL_LEN TLS13_HKDF_LABEL_LEN(TLS13_MAX_LABEL_LEN, TLS13_MAX_CTX_LEN)

HITLS_CRYPT_BaseMethod g_cryptBaseMethod = {0};
HITLS_CRYPT_EcdhMethod g_cryptEcdhMethod = {0};
HITLS_CRYPT_DhMethod g_cryptDhMethod = {0};
HITLS_CRYPT_KdfMethod g_cryptKdfMethod = {0};

typedef struct {
    uint16_t length;        /* Length of the derived key */
    uint8_t labelLen;       /* Label length */
    uint8_t ctxLen;         /* Length of the context information */
    const uint8_t *label;   /* Label */
    const uint8_t *ctx;     /* Context information */
} HkdfLabel;

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
    g_cryptEcdhMethod.dupEcdhKey = userCryptCallBack->dupEcdhKey;
    g_cryptEcdhMethod.freeEcdhKey = userCryptCallBack->freeEcdhKey;
    g_cryptEcdhMethod.getEcdhPubKey = userCryptCallBack->getEcdhPubKey;
    g_cryptEcdhMethod.calcEcdhSharedSecret = userCryptCallBack->calcEcdhSharedSecret;
    g_cryptEcdhMethod.sm2CalEcdhSharedSecret = userCryptCallBack->sm2CalEcdhSharedSecret;
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
    g_cryptDhMethod.dupDhKey = userCryptCallBack->dupDhKey;
    return HITLS_SUCCESS;
}

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

int32_t SAL_CRYPT_Rand(uint8_t *buf, uint32_t len)
{
    if (g_cryptBaseMethod.randBytes == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15067, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "generate %u bytes random error: callback unregistered.", len, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = g_cryptBaseMethod.randBytes(buf, len);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15068, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "generate %u bytes random error: callback ret = 0x%x.", len, ret, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_GENERATE_RANDOM);
        return HITLS_CRYPT_ERR_GENERATE_RANDOM;
    }
    return HITLS_SUCCESS;
}

uint32_t SAL_CRYPT_HmacSize(HITLS_HashAlgo hashAlgo)
{
    if (g_cryptBaseMethod.hmacSize == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15069, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "hmac size error: callback unregistered.", 0, 0, 0, 0);
        return 0;
    }
    return g_cryptBaseMethod.hmacSize(hashAlgo);
}

HITLS_HMAC_Ctx *SAL_CRYPT_HmacInit(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len)
{
    if (g_cryptBaseMethod.hmacInit == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15070, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "hmac init error: callback unregistered.", 0, 0, 0, 0);
        return NULL;
    }

    return g_cryptBaseMethod.hmacInit(hashAlgo, key, len);
}

void SAL_CRYPT_HmacFree(HITLS_HMAC_Ctx *hmac)
{
    if (g_cryptBaseMethod.hmacFree == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15071, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "hmac free error: callback unregistered.", 0, 0, 0, 0);
        return;
    }
    if (hmac != NULL) {
        g_cryptBaseMethod.hmacFree(hmac);
    }
    return;
}

int32_t SAL_CRYPT_HmacUpdate(HITLS_HMAC_Ctx *hmac, const uint8_t *data, uint32_t len)
{
    if (g_cryptBaseMethod.hmacUpdate == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15072, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "hmac update error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptBaseMethod.hmacUpdate(hmac, data, len);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15073, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "hmac update error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_HMAC);
        return HITLS_CRYPT_ERR_HMAC;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_HmacFinal(HITLS_HMAC_Ctx *hmac, uint8_t *out, uint32_t *len)
{
    if (g_cryptBaseMethod.hmacFinal == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15074, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "hmac final error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptBaseMethod.hmacFinal(hmac, out, len);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15075, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "hmac final error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_HMAC);
        return HITLS_CRYPT_ERR_HMAC;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_Hmac(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (g_cryptBaseMethod.hmac == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15076, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "hmac error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptBaseMethod.hmac(hashAlgo, key, keyLen, in, inLen, out, outLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15077, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "hmac error: callback ret = 0x%x, hashAlgo = %u, keyLen = %u, inLen = %u, .",
            ret, hashAlgo, keyLen, inLen);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15207, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "outLen = %u", *outLen, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_HMAC);
        return HITLS_CRYPT_ERR_HMAC;
    }
    return HITLS_SUCCESS;
}

static int32_t IteratorInit(CRYPT_KeyDeriveParameters *input, uint32_t hmacSize,
    uint8_t **iterator, uint32_t *iteratorSize)
{
    uint8_t *seed = BSL_SAL_Calloc(1u, hmacSize + input->labelLen + input->seedLen);
    if (seed == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15078, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "P_Hash error: malloc seed failed.", 0, 0, 0, 0);
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
        return ret;
    }
    data = BSL_SAL_Calloc(1u, alignLen);
    if (data == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15081, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "P_Hash error: malloc data failed.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    uint32_t tmpLen = hmacSize;
    ret = IteratorInit(input, hmacSize, &iterator, &iteratorSize);
    if (ret != HITLS_SUCCESS) {
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
        ret = HITLS_MEMCPY_FAIL;
    }
PHASH_END:
    BSL_SAL_FREE(iterator);
    BSL_SAL_FREE(data);
    return ret;
}

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
        return ret;
    }

    uint8_t *sha1data = BSL_SAL_Calloc(1u, outLen);
    if (sha1data == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15084, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PRF_MD5_SHA1 error: malloc sha1data failed.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    input->secret += (secretLen >> 1);
    input->hashAlgo = HITLS_HASH_SHA1;
    ret = P_Hash(input, sha1data, outLen);
    if (ret != HITLS_SUCCESS) {
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

int32_t SAL_CRYPT_PRF(CRYPT_KeyDeriveParameters *input, uint8_t *out, uint32_t outLen)
{
    // TLS1.0, TLS1.1
    if (input->hashAlgo == HITLS_HASH_MD5_SHA1) {
        return PRF_MD5_SHA1(input, out, outLen);
    }

    // Other versions
    if (input->hashAlgo < HITLS_HASH_SHA_256) {
        /* The PRF function must use the digest algorithm with SHA-256 or higher strength. */
        input->hashAlgo = HITLS_HASH_SHA_256;
    }

    return P_Hash(input, out, outLen);
}

uint32_t SAL_CRYPT_DigestSize(HITLS_HashAlgo hashAlgo)
{
    if (g_cryptBaseMethod.digestSize == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15085, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "digest size error: callback unregistered.", 0, 0, 0, 0);
        return 0;
    }
    return g_cryptBaseMethod.digestSize(hashAlgo);
}

HITLS_HASH_Ctx *SAL_CRYPT_DigestInit(HITLS_HashAlgo hashAlgo)
{
    if (g_cryptBaseMethod.digestInit == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15086, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "digest init error: callback unregistered.", 0, 0, 0, 0);
        return NULL;
    }
    return g_cryptBaseMethod.digestInit(hashAlgo);
}

HITLS_HASH_Ctx *SAL_CRYPT_DigestCopy(HITLS_HASH_Ctx *ctx)
{
    if (g_cryptBaseMethod.digestCopy == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15087, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "digest copy error: callback unregistered.", 0, 0, 0, 0);
        return NULL;
    }
    return g_cryptBaseMethod.digestCopy(ctx);
}

void SAL_CRYPT_DigestFree(HITLS_HASH_Ctx *ctx)
{
    if (g_cryptBaseMethod.digestFree == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15088, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "digest free error: callback unregistered.", 0, 0, 0, 0);
        return;
    }
    if (ctx != NULL) {
        g_cryptBaseMethod.digestFree(ctx);
    }
    return;
}

int32_t SAL_CRYPT_DigestUpdate(HITLS_HASH_Ctx *ctx, const uint8_t *data, uint32_t len)
{
    if (g_cryptBaseMethod.digestUpdate == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15089, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "digest update error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptBaseMethod.digestUpdate(ctx, data, len);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15090, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "digest update error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
        return HITLS_CRYPT_ERR_DIGEST;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_DigestFinal(HITLS_HASH_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    if (g_cryptBaseMethod.digestFinal == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15091, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "digest final error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptBaseMethod.digestFinal(ctx, out, len);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15092, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "digest final error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
        return HITLS_CRYPT_ERR_DIGEST;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_Digest(HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (g_cryptBaseMethod.digest == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15093, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "digest error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptBaseMethod.digest(hashAlgo, in, inLen, out, outLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15094, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "digest error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
        return HITLS_CRYPT_ERR_DIGEST;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_Encrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    if (g_cryptBaseMethod.encrypt == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15095, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encrypt error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptBaseMethod.encrypt(cipher, in, inLen, out, outLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15096, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encrypt error: cipher type = %u, algo = %u, keyLen = %u, ivLen = %u",
            cipher->type, cipher->algo, cipher->keyLen, cipher->ivLen);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15208, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "aadLen = %u, inTextLen = %u, outTextLen = %u.", cipher->aadLen, inLen, *outLen, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCRYPT);
        return HITLS_CRYPT_ERR_ENCRYPT;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_Decrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    if (g_cryptBaseMethod.decrypt == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15097, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decrypt error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptBaseMethod.decrypt(cipher, in, inLen, out, outLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15098, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decrypt error: cipher type = %u, algo = %u, keyLen = %u, ivLen = %u",
            cipher->type, cipher->algo, cipher->keyLen, cipher->ivLen);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15209, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "aadLen = %u, inTextLen = %u, outTextLen = %u.", cipher->aadLen, inLen, *outLen, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DECRYPT);
        return HITLS_CRYPT_ERR_DECRYPT;
    }
    return HITLS_SUCCESS;
}

HITLS_CRYPT_Key *SAL_CRYPT_GenEcdhKeyPair(const HITLS_ECParameters *curveParams)
{
    if (g_cryptEcdhMethod.generateEcdhKeyPair == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15099, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "generate ecdh key error: callback unregistered.", 0, 0, 0, 0);
        return NULL;
    }
    return g_cryptEcdhMethod.generateEcdhKeyPair(curveParams);
}

HITLS_CRYPT_Key *SAL_CRYPT_DupEcdhKey(HITLS_CRYPT_Key *key)
{
    if (g_cryptEcdhMethod.dupEcdhKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16011, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dup ecdh key error: callback unregistered.", 0, 0, 0, 0);
        return NULL;
    }
    return g_cryptEcdhMethod.dupEcdhKey(key);
}

void SAL_CRYPT_FreeEcdhKey(HITLS_CRYPT_Key *key)
{
    if (g_cryptEcdhMethod.freeEcdhKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15100, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "free ecdh key error: callback unregistered.", 0, 0, 0, 0);
        return;
    }
    if (key != NULL) {
        g_cryptEcdhMethod.freeEcdhKey(key);
    }
    return;
}

int32_t SAL_CRYPT_EncodeEcdhPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *usedLen)
{
    if (g_cryptEcdhMethod.getEcdhPubKey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15101, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get ecdh public key error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptEcdhMethod.getEcdhPubKey(key, pubKeyBuf, bufLen, usedLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15102, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get ecdh public key error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_ECDH_KEY);
        return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_CalcEcdhSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    if (g_cryptEcdhMethod.calcEcdhSharedSecret == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15103, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "calculate ecdh shared secret error: callback unregistered.", 0, 0, 0, 0);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptEcdhMethod.calcEcdhSharedSecret(key, peerPubkey, pubKeyLen, sharedSecret, sharedSecretLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15104, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "calculate ecdh shared secret error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_CALC_SHARED_KEY);
        return HITLS_CRYPT_ERR_CALC_SHARED_KEY;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_CalcSm2dhSharedSecret(HITLS_Sm2GenShareKeyParameters *sm2ShareKeyParam, uint8_t *sharedSecret,
                                        uint32_t *sharedSecretLen)
{
    if (g_cryptEcdhMethod.sm2CalEcdhSharedSecret == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15241, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get sm2 ecdh public key error: callback unregistered", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptEcdhMethod.sm2CalEcdhSharedSecret(sm2ShareKeyParam, sharedSecret, sharedSecretLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15242, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get sm2 ecdh public key error: callback ret = 0x%x", (uint32_t)ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_ECDH_KEY);
        return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
    }
    return HITLS_SUCCESS;
}

HITLS_CRYPT_Key *SAL_CRYPT_GenerateDhKeyByParams(uint8_t *p, uint16_t plen, uint8_t *g, uint16_t glen)
{
    if (g_cryptDhMethod.generateDhKeyByParams == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15105, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "generate Dh key error: callback unregistered.", 0, 0, 0, 0);
        return NULL;
    }
    return g_cryptDhMethod.generateDhKeyByParams(p, plen, g, glen);
}

HITLS_CRYPT_Key *SAL_CRYPT_GenerateDhKeyBySecbits(int32_t secbits)
{
    if (g_cryptDhMethod.generateDhKeyBySecbits == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15106, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "generate Dh key error: callback unregistered.", 0, 0, 0, 0);
        return NULL;
    }
    return g_cryptDhMethod.generateDhKeyBySecbits(secbits);
}

HITLS_CRYPT_Key *SAL_CRYPT_DupDhKey(HITLS_CRYPT_Key *key)
{
    if (g_cryptDhMethod.dupDhKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16010, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dup Dh key error: callback unregistered.", 0, 0, 0, 0);
        return NULL;
    }
    return g_cryptDhMethod.dupDhKey(key);
}

void SAL_CRYPT_FreeDhKey(HITLS_CRYPT_Key *key)
{
    if (g_cryptDhMethod.freeDhKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15107, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "free Dh key error: callback unregistered.", 0, 0, 0, 0);
        return;
    }
    if (key != NULL) {
        g_cryptDhMethod.freeDhKey(key);
    }
    return;
}

int32_t SAL_CRYPT_GetDhParameters(HITLS_CRYPT_Key *key, uint8_t *p, uint16_t *plen, uint8_t *g, uint16_t *glen)
{
    if (g_cryptDhMethod.getDhParameters == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15108, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get dh params error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    return g_cryptDhMethod.getDhParameters(key, p, plen, g, glen);
}

int32_t SAL_CRYPT_EncodeDhPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *usedLen)
{
    if (g_cryptDhMethod.getDhPubKey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15109, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get dh public key error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptDhMethod.getDhPubKey(key, pubKeyBuf, bufLen, usedLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15110, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get dh public key error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_DH_KEY);
        return HITLS_CRYPT_ERR_ENCODE_DH_KEY;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_CalcDhSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    if (g_cryptDhMethod.calcDhSharedSecret == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15111, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "calculate dh shared secret error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptDhMethod.calcDhSharedSecret(key, peerPubkey, pubKeyLen, sharedSecret, sharedSecretLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15112, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "calculate dh shared secret error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_CALC_SHARED_KEY);
        return HITLS_CRYPT_ERR_CALC_SHARED_KEY;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_HkdfExtract(HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen)
{
    if (g_cryptKdfMethod.hkdfExtract == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15113, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HKDF-Extract error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptKdfMethod.hkdfExtract(input, prk, prkLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15114, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HKDF-Extract error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_HKDF_EXTRACT);
        return HITLS_CRYPT_ERR_HKDF_EXTRACT;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CRYPT_HkdfExpand(HITLS_CRYPT_HkdfExpandInput *input, uint8_t *okm, uint32_t okmLen)
{
    if (g_cryptKdfMethod.hkdfExpand == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15115, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HKDF-Expand error: callback unregistered.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t ret = g_cryptKdfMethod.hkdfExpand(input, okm, okmLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15116, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HKDF-Expand error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_HKDF_EXPAND);
        return HITLS_CRYPT_ERR_HKDF_EXPAND;
    }
    return HITLS_SUCCESS;
}

/**
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
    buf[offset] = hkdfLabel->labelLen + (uint8_t)labelPrefixLen;
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
        return ret;
    }

    HITLS_CRYPT_HkdfExpandInput expandInput = {0};
    expandInput.hashAlgo = deriveInfo->hashAlgo;
    expandInput.prk = deriveInfo->secret;
    expandInput.prkLen = deriveInfo->secretLen;
    expandInput.info = hkdfLabel;
    expandInput.infoLen = hkdfLabelLen;
    ret = SAL_CRYPT_HkdfExpand(&expandInput, outSecret, outLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}
