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

#include <stdint.h>
#include <stddef.h>
#include "hitls_build.h"
#include "securec.h"
#include "bsl_sal.h"
#include "hitls_crypt_reg.h"
#include "hitls_error.h"
#include "hs_common.h"
#include "config_type.h"
#include "stub_replace.h"
#include "crypt_default.h"
#ifdef HITLS_TLS_FEATURE_PROVIDER
#include "hitls_crypt.h"
#include "crypt_eal_rand.h"
#endif

#define MD5_DIGEST_LENGTH 16
#define SHA1_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64
#define SM3_DIGEST_LENGTH 32
#define AEAD_TAG_LENGTH 16

typedef struct {
    HITLS_HashAlgo algo;
    uint8_t *key;
    uint32_t keyLen;
} FRAME_HmacCtx;

typedef struct {
    HITLS_HashAlgo algo;
} FRAME_HashCtx;

typedef struct {
    uint8_t *pubKey;
    uint32_t pubKeyLen;
    uint8_t *privateKey;
    uint32_t privateKeyLen;
} FRAME_EcdhKey;

typedef struct {
    uint8_t *p;
    uint8_t *g;
    uint16_t plen;
    uint16_t glen;
    uint8_t *pubKey;
    uint32_t pubKeyLen;
    uint8_t *privateKey;
    uint32_t privateKeyLen;
} FRAME_DhKey;

/**
 * @ingroup hitls_crypt_reg
 * @brief   Obtain the random number
 *
 * @param   buf [OUT] random number
 * @param   len [IN] random number length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_RandBytesCallback(uint8_t *buf, uint32_t len)
{
    if (memset_s(buf, len, 1, len) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    return HITLS_SUCCESS;
}

int32_t STUB_CRYPT_RandBytesCallbackLibCtx(void *libCtx, uint8_t *buf, uint32_t len)
{
    (void)libCtx;
    if (memset_s(buf, len, 1, len) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    return HITLS_SUCCESS;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Generate a key pair based on the elliptic curve parameters
 *
 * @param   curveParams [IN] Elliptic curve parameters
 *
 * @return  Key handle
 */
HITLS_CRYPT_Key *STUB_CRYPT_GenerateEcdhKeyPairCallback(HITLS_Ctx *ctx, const HITLS_ECParameters *curveParams)
{
    uint32_t keyLen = 0u;
    if (curveParams == NULL) {
        return NULL;
    }

    FRAME_EcdhKey *ecdhKey = (FRAME_EcdhKey *)BSL_SAL_Calloc(1u, sizeof(FRAME_EcdhKey));
    if (ecdhKey == NULL) {
        return NULL;
    }
    const TLS_GroupInfo *groupInfo = NULL;
    switch (curveParams->type) {
        case HITLS_EC_CURVE_TYPE_NAMED_CURVE:
            groupInfo = ConfigGetGroupInfo(&ctx->config.tlsConfig, curveParams->param.namedcurve);
            if (groupInfo == NULL) {
                BSL_SAL_FREE(ecdhKey);
                return NULL;
            }
            keyLen = groupInfo->pubkeyLen;
            break;
        default:
            break;
    }

    uint8_t *pubKey = (uint8_t *)BSL_SAL_Malloc(keyLen);
    if (pubKey == NULL) {
        BSL_SAL_FREE(ecdhKey);
        return NULL;
    }
    memset_s(pubKey, keyLen, 1u, keyLen);

    uint8_t *privateKey = (uint8_t *)BSL_SAL_Malloc(keyLen);
    if (privateKey == NULL) {
        BSL_SAL_FREE(pubKey);
        BSL_SAL_FREE(ecdhKey);
        return NULL;
    }
    memset_s(privateKey, keyLen, 2u, keyLen);

    ecdhKey->pubKey = pubKey;
    ecdhKey->pubKeyLen = keyLen;
    ecdhKey->privateKey = privateKey;
    ecdhKey->privateKeyLen = keyLen;
    return ecdhKey;
}

HITLS_CRYPT_Key *STUB_CRYPT_GenerateEcdhKeyPairCallbackLibCtx(void *libCtx, 
    const char *attrName, const HITLS_Config *config, const HITLS_ECParameters *curveParams)
{
    (void)libCtx;
    (void)attrName;
    (void)config;
    return STUB_CRYPT_GenerateEcdhKeyPairCallback(NULL, curveParams);
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Release the key
 *
 * @param   key [IN] Key handle
 */
void STUB_CRYPT_FreeEcdhKeyCallback(HITLS_CRYPT_Key *key)
{
    FRAME_EcdhKey *ecdhKey = (FRAME_EcdhKey *)key;
    if (ecdhKey != NULL) {
        BSL_SAL_FREE(ecdhKey->pubKey);
        BSL_SAL_FREE(ecdhKey->privateKey);
        BSL_SAL_FREE(ecdhKey);
    }
    return;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Extract the public key data
 *
 * @param   key [IN] Key handle
 * @param   pubKeyBuf [OUT] Public key data
 * @param   bufLen [IN] buffer length
 * @param   pubKeyLen [OUT] Public key data length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_GetEcdhEncodedPubKeyCallback(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen,
    uint32_t *pubKeyLen)
{
    FRAME_EcdhKey *ecdhKey = (FRAME_EcdhKey *)key;
    if ((ecdhKey == NULL) ||
        (pubKeyBuf == NULL) ||
        (pubKeyLen == NULL) ||
        (bufLen < ecdhKey->pubKeyLen)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memcpy_s(pubKeyBuf, bufLen, ecdhKey->pubKey, ecdhKey->pubKeyLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    *pubKeyLen = ecdhKey->pubKeyLen;
    return HITLS_SUCCESS;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Calculate the shared key based on the local key and peer public key
 *
 * @param   key [IN] Key handle
 * @param   pubKeyBuf [IN] Public key data
 * @param   pubKeyLen [IN] Public key data length
 * @param   sharedSecret [OUT] Shared key
 * @param   sharedSecretLen [IN/OUT] IN: Maximum length of the key padding OUT: Key length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_CalcEcdhSharedSecretCallback(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    FRAME_EcdhKey *ecdhKey = (FRAME_EcdhKey *)key;

    if ((ecdhKey == NULL) ||
        (peerPubkey == NULL) ||
        (sharedSecret == NULL) ||
        (sharedSecretLen == NULL) ||
        (ecdhKey->privateKeyLen > pubKeyLen) ||
        (*sharedSecretLen < pubKeyLen)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memset_s(sharedSecret, *sharedSecretLen, 3u, pubKeyLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    *sharedSecretLen = pubKeyLen;
    return HITLS_SUCCESS;
}

int32_t STUB_CRYPT_CalcEcdhSharedSecretCallbackLibCtx(void *libCtx, const char *attrName,
    HITLS_CRYPT_Key *key, uint8_t *peerPubkey,
    uint32_t pubKeyLen, uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    (void)libCtx;
    (void)attrName;
    return STUB_CRYPT_CalcEcdhSharedSecretCallback(key, peerPubkey, pubKeyLen, sharedSecret, sharedSecretLen);
}

void STUB_CRYPT_FreeDhKeyCallback(HITLS_CRYPT_Key *key)
{
    FRAME_DhKey *dhKey = (FRAME_DhKey *)key;
    if (dhKey != NULL) {
        BSL_SAL_FREE(dhKey->p);
        BSL_SAL_FREE(dhKey->g);
        BSL_SAL_FREE(dhKey->privateKey);
        BSL_SAL_FREE(dhKey->pubKey);
        BSL_SAL_FREE(dhKey);
    }
    return;
}

HITLS_CRYPT_Key *STUB_CRYPT_GenerateDhKeyBySecbitsCallback(int32_t secbits)
{
    uint16_t plen;
    if (secbits >= 192) {
        plen = 1024;
    } else if (secbits >= 152) {
        plen = 512;
    } else if (secbits >= 128) {
        plen = 384;
    } else if (secbits >= 112) {
        plen = 256;
    } else {
        plen = 128;
    }

    FRAME_DhKey *dhKey = (FRAME_DhKey *)BSL_SAL_Calloc(1u, sizeof(FRAME_DhKey));
    if (dhKey == NULL) {
        return NULL;
    }

    dhKey->p = BSL_SAL_Calloc(1u, plen);
    if (dhKey->p == NULL) {
        BSL_SAL_FREE(dhKey);
        return NULL;
    }
    memset_s(dhKey->p, plen, 1u, plen);
    dhKey->plen = plen;

    dhKey->g = BSL_SAL_Calloc(1u, plen);
    if (dhKey->g == NULL) {
        STUB_CRYPT_FreeDhKeyCallback(dhKey);
        return NULL;
    }
    memset_s(dhKey->g, plen, 2u, plen);
    dhKey->glen = plen;

    dhKey->pubKey = BSL_SAL_Calloc(1u, plen);
    if (dhKey->pubKey == NULL) {
        STUB_CRYPT_FreeDhKeyCallback(dhKey);
        return NULL;
    }
    memset_s(dhKey->pubKey, plen, 3u, plen);
    dhKey->pubKeyLen = plen;

    dhKey->privateKey = BSL_SAL_Calloc(1u, plen);
    if (dhKey->privateKey == NULL) {
        STUB_CRYPT_FreeDhKeyCallback(dhKey);
        return NULL;
    }
    memset_s(dhKey->privateKey, plen, 4u, plen);
    dhKey->privateKeyLen = plen;

    return dhKey;
}

HITLS_CRYPT_Key *STUB_CRYPT_GenerateDhKeyBySecbitsCallbackLibCtx(void *libCtx, const char *attrName, int32_t secbits)
{
    (void)libCtx;
    (void)attrName;
    return STUB_CRYPT_GenerateDhKeyBySecbitsCallback(secbits);
}

HITLS_CRYPT_Key *STUB_CRYPT_GenerateDhKeyByParamsCallback(uint8_t *p, uint16_t plen, uint8_t *g, uint16_t glen)
{
    if ((p == NULL) || (plen == 0) || (g == NULL) || (glen == 0)) {
        return NULL;
    }

    FRAME_DhKey *dhKey = (FRAME_DhKey *)BSL_SAL_Calloc(1u, sizeof(FRAME_DhKey));
    if (dhKey == NULL) {
        return NULL;
    }

    dhKey->p = BSL_SAL_Dump(p, plen);
    if (dhKey->p == NULL) {
        BSL_SAL_FREE(dhKey);
        return NULL;
    }
    dhKey->plen = plen;

    dhKey->g = BSL_SAL_Dump(g, glen);
    if (dhKey->g == NULL) {
        STUB_CRYPT_FreeDhKeyCallback(dhKey);
        return NULL;
    }
    dhKey->glen = glen;

    dhKey->pubKey = BSL_SAL_Calloc(1u, plen);
    if (dhKey->pubKey == NULL) {
        STUB_CRYPT_FreeDhKeyCallback(dhKey);
        return NULL;
    }
    if (memset_s(dhKey->pubKey, plen, 3u, plen) != EOK) {
        STUB_CRYPT_FreeDhKeyCallback(dhKey);
        return NULL;
    }
    dhKey->pubKeyLen = plen;

    dhKey->privateKey = BSL_SAL_Calloc(1u, plen);
    if (dhKey->privateKey == NULL) {
        STUB_CRYPT_FreeDhKeyCallback(dhKey);
        return NULL;
    }
    if (memset_s(dhKey->privateKey, plen, 4u, plen) != EOK) {
        STUB_CRYPT_FreeDhKeyCallback(dhKey);
        return NULL;
    }
    dhKey->privateKeyLen = plen;

    return dhKey;
}

HITLS_CRYPT_Key *STUB_CRYPT_GenerateDhKeyByParamsCallbackLibCtx(void *libCtx, const char *attrName,
    uint8_t *p, uint16_t plen, uint8_t *g, uint16_t glen)
{
    (void)libCtx;
    (void)attrName;
    return STUB_CRYPT_GenerateDhKeyByParamsCallback(p, plen, g, glen);
}

int32_t STUB_CRYPT_DHGetParametersCallback(HITLS_CRYPT_Key *key, uint8_t *p, uint16_t *plen, uint8_t *g, uint16_t *glen)
{
    if ((key == NULL) || (plen == NULL) || (glen == NULL)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    FRAME_DhKey *dhKey = (FRAME_DhKey *)key;

    if (p != NULL) {
        if (memcpy_s(p, *plen, dhKey->p, dhKey->plen) != EOK) {
            return HITLS_MEMCPY_FAIL;
        }
    }

    if (g != NULL) {
        if (memcpy_s(g, *glen, dhKey->g, dhKey->glen) != EOK) {
            return HITLS_MEMCPY_FAIL;
        }
    }

    *plen = dhKey->plen;
    *glen = dhKey->glen;
    return HITLS_SUCCESS;
}

int32_t STUB_CRYPT_GetDhEncodedPubKeyCallback(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen,
    uint32_t *pubKeyLen)
{
    if ((key == NULL) || (pubKeyBuf == NULL) || (pubKeyLen == NULL)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    FRAME_DhKey *dhKey = (FRAME_DhKey *)key;

    if (memcpy_s(pubKeyBuf, bufLen, dhKey->pubKey, dhKey->pubKeyLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }

    *pubKeyLen = dhKey->pubKeyLen;
    return HITLS_SUCCESS;
}

int32_t STUB_CRYPT_CalcDhSharedSecretCallback(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    FRAME_DhKey *dhKey = (FRAME_DhKey *)key;

    if ((dhKey == NULL) ||
        (peerPubkey == NULL) ||
        (sharedSecret == NULL) ||
        (sharedSecretLen == NULL) ||
        (dhKey->plen < pubKeyLen)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memset_s(sharedSecret, *sharedSecretLen, 1u, dhKey->plen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    *sharedSecretLen = dhKey->plen;
    return HITLS_SUCCESS;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Obtain the HMAC length
 *
 * @param   hashAlgo [IN] Hash algorithm
 *
 * @return  HMAC length
 */
uint32_t STUB_CRYPT_HmacSizeCallback(HITLS_HashAlgo hashAlgo)
{
    switch (hashAlgo) {
        case HITLS_HASH_MD5:
            return MD5_DIGEST_LENGTH;
        case HITLS_HASH_SHA1:
            return SHA1_DIGEST_LENGTH;
        case HITLS_HASH_SHA_256:
            return SHA256_DIGEST_LENGTH;
        case HITLS_HASH_SHA_384:
            return SHA384_DIGEST_LENGTH;
        case HITLS_HASH_SHA_512:
            return SHA512_DIGEST_LENGTH;
        default:
            break;
    }
    return 0u;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Initialize the HMAC context
 *
 * @param   hashAlgo [IN] Hash algorithm
 * @param   key [IN] Key
 * @param   len [IN] Key length
 *
 * @return  HMAC context
 */
HITLS_HMAC_Ctx *STUB_CRYPT_HmacInitCallback(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len)
{
    FRAME_HmacCtx *ctx = BSL_SAL_Calloc(1u, sizeof(FRAME_HmacCtx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->algo = hashAlgo;
    ctx->key = BSL_SAL_Dump(key, len);
    if (ctx->key == NULL) {
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->keyLen = len;
    return ctx;
}

HITLS_HMAC_Ctx *STUB_CRYPT_HmacInitCallbackLibCtx(void *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len)
{
    (void)libCtx;
    (void)attrName;
    return STUB_CRYPT_HmacInitCallback(hashAlgo, key, len);
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Release the HMAC context
 *
 * @param   ctx [IN] HMAC context
 */
void STUB_CRYPT_HmacFreeCallback(HITLS_HMAC_Ctx *ctx)
{
    FRAME_HmacCtx *hmacCtx = (FRAME_HmacCtx *)ctx;
    if (hmacCtx != NULL) {
        BSL_SAL_FREE(hmacCtx->key);
        BSL_SAL_FREE(hmacCtx);
    }
    return;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Add the input data
 *
 * @param   ctx [IN] HMAC context
 * @param   data [IN] Input data
 * @param   len [IN] Data length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_HmacUpdateCallback(HITLS_HMAC_Ctx *ctx, const uint8_t *data, uint32_t len)
{
    if ((ctx == NULL) || (data == NULL) || len == 0) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SUCCESS;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Output the HMAC result
 *
 * @param   ctx [IN] HMAC context
 * @param   out [OUT] Output data
 * @param   len [IN/OUT] IN: Maximum buffer length OUT: Output data length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_HmacFinalCallback(HITLS_HMAC_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    FRAME_HmacCtx *hmacCtx = (FRAME_HmacCtx *)ctx;
    if ((hmacCtx == NULL) || (out == NULL) || (len == NULL)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t hmacSize = STUB_CRYPT_HmacSizeCallback(hmacCtx->algo);
    if ((hmacSize == 0u) || (hmacSize > *len)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memset_s(out, *len, 4u, hmacSize) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    *len = hmacSize;
    return HITLS_SUCCESS;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   HMAC function
 *
 * @param   hashAlgo [IN] Hash algorithm
 * @param   key [IN] Key
 * @param   keyLen [IN] Key length
 * @param   in [IN] Input data
 * @param   inLen [IN] Input data length
 * @param   out [OUT] Output data
 * @param   outLen [IN/OUT] IN: Maximum buffer length OUT: Output data length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_HmacCallback(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if ((key == NULL) || (keyLen == 0) || (in == NULL) || (inLen == 0) ||
        (out == NULL) || (outLen == NULL)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t hmacSize = STUB_CRYPT_HmacSizeCallback(hashAlgo);
    if ((hmacSize == 0u) || (hmacSize > *outLen)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memset_s(out, *outLen, 4u, hmacSize) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    *outLen = hmacSize;
    return HITLS_SUCCESS;
}

int32_t STUB_CRYPT_HmacCallbackLibCtx(void *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    (void)libCtx;
    (void)attrName;
    return STUB_CRYPT_HmacCallback(hashAlgo, key, keyLen, in, inLen, out, outLen);
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Obtain the hash length
 *
 * @param   hashAlgo [IN] Hash algorithm
 *
 * @return  Hash length
 */
uint32_t STUB_CRYPT_DigestSizeCallback(HITLS_HashAlgo hashAlgo)
{
    return STUB_CRYPT_HmacSizeCallback(hashAlgo);
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Initialize the hash context
 *
 * @param   hashAlgo [IN] Hash algorithm
 *
 * @return  hash context
 */
HITLS_HASH_Ctx *STUB_CRYPT_DigestInitCallback(HITLS_HashAlgo hashAlgo)
{
    FRAME_HashCtx *ctx = BSL_SAL_Calloc(1u, sizeof(FRAME_HashCtx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->algo = hashAlgo;
    return ctx;
}

HITLS_HASH_Ctx *STUB_CRYPT_DigestInitCallbackLibCtx(void *libCtx, const char *attrName, HITLS_HashAlgo hashAlgo)
{
    (void)libCtx;
    (void)attrName;
    return STUB_CRYPT_DigestInitCallback(hashAlgo);
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Copy hash Context
 *
 * @param   ctx [IN] hash Context
 *
 * @return  hash Context
 */
HITLS_HASH_Ctx *STUB_CRYPT_DigestCopyCallback(HITLS_HASH_Ctx *ctx)
{
    FRAME_HashCtx *srcCtx = (FRAME_HashCtx *)ctx;
    if (srcCtx == NULL) {
        return NULL;
    }

    FRAME_HashCtx *newCtx = BSL_SAL_Calloc(1u, sizeof(FRAME_HashCtx));
    if (newCtx == NULL) {
        return NULL;
    }
    newCtx->algo = srcCtx->algo;
    return newCtx;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Release the hash context
 *
 * @param   ctx [IN] hash Context
 */
void STUB_CRYPT_DigestFreeCallback(HITLS_HASH_Ctx *ctx)
{
    BSL_SAL_FREE(ctx);
    return;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Add the input data
 *
 * @param   ctx [IN] hash Context
 * @param   data [IN] Input data
 * @param   len [IN] Input data length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_DigestUpdateCallback(HITLS_HASH_Ctx *ctx, const uint8_t *data, uint32_t len)
{
    if ((ctx == NULL) || (data == NULL) || (len == 0u)) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SUCCESS;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Output the hash result
 *
 * @param   ctx [IN] hash Context
 * @param   out [IN] Output data
 * @param   len [IN/OUT] IN: Maximum buffer length OUT: Output data length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_DigestFinalCallback(HITLS_HASH_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    FRAME_HashCtx *hashCtx = (FRAME_HashCtx *)ctx;
    if ((hashCtx == NULL) || (out == NULL) || (len == NULL)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t digestSize = STUB_CRYPT_DigestSizeCallback(hashCtx->algo);
    if ((digestSize == 0) || (digestSize > *len)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memset_s(out, *len, 5u, digestSize) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    *len = digestSize;
    return HITLS_SUCCESS;
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   hash function
 *
 * @param   hashAlgo [IN] Hash algorithm
 * @param   in [IN] Input data
 * @param   inLen [IN] Input data length
 * @param   out [OUT] Output data
 * @param   outLen [IN/OUT] IN: Maximum buffer length OUT: Output data length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_DigestCallback(HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    if ((in == NULL) ||
        (out == NULL) ||
        (outLen == NULL) ||
        (inLen == 0)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t digestSize = STUB_CRYPT_DigestSizeCallback(hashAlgo);
    if ((digestSize == 0) || (digestSize > *outLen)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memset_s(out, *outLen, 5u, digestSize) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    *outLen = digestSize;
    return HITLS_SUCCESS;
}

int32_t STUB_CRYPT_DigestCallbackLibCtx(void *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    (void)libCtx;
    (void)attrName;
    return STUB_CRYPT_DigestCallback(hashAlgo, in, inLen, out, outLen);
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Encryption
 *
 * @param   cipher [IN] Key parameters
 * @param   in [IN] Plaintext data
 * @param   inLen [IN] Plaintext data length
 * @param   out [OUT] Ciphertext data
 * @param   outLen [IN/OUT] IN: maximum buffer length OUT: ciphertext data length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_EncryptCallback(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    if (cipher->type == HITLS_AEAD_CIPHER) {
        if (*outLen < inLen + AEAD_TAG_LENGTH) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        (void)memset_s(out, *outLen, 0, *outLen);
        if (inLen != 0 && memcpy_s(out, *outLen, in, inLen) != EOK) {
            return HITLS_MEMCPY_FAIL;
        }
        *outLen = inLen + AEAD_TAG_LENGTH;
    } else {
        *outLen = 0;
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t STUB_CRYPT_EncryptCallbackLibCtx(void *libCtx, const char *attrName, 
    const HITLS_CipherParameters *cipher, const uint8_t *in,
    uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    (void)libCtx;
    (void)attrName;
    return STUB_CRYPT_EncryptCallback(cipher, in, inLen, out, outLen);
}

/**
 * @ingroup hitls_crypt_reg
 * @brief   Decrypt
 *
 * @param   cipher [IN] Key parameters
 * @param   in [IN] Ciphertext data
 * @param   inLen [IN] Ciphertext data length
 * @param   out [OUT] Plaintext data
 * @param   outLen [IN/OUT] IN: Maximum buffer length OUT: Plaintext data length
 *
 * @return 0 indicates success. Other values indicate failure
 */
int32_t STUB_CRYPT_DecryptCallback(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    if (cipher->type == HITLS_AEAD_CIPHER) {
        if (inLen < AEAD_TAG_LENGTH) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        (void)memset_s(out, *outLen, 0, *outLen);
        if (memcpy_s(out, *outLen, in, inLen - AEAD_TAG_LENGTH) != EOK) {
            return HITLS_MEMCPY_FAIL;
        }
        *outLen = inLen - AEAD_TAG_LENGTH;
    } else {
        *outLen = 0;
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t STUB_CRYPT_DecryptCallbackLibCtx(void *libCtx, const char *attrName,
    const HITLS_CipherParameters *cipher, const uint8_t *in,
    uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    (void)libCtx;
    (void)attrName;
    return STUB_CRYPT_DecryptCallback(cipher, in, inLen, out, outLen);
}

FuncStubInfo g_tmpRpInfo[16] = {0};
void FRAME_RegCryptMethod(void)
{
#ifndef HITLS_TLS_FEATURE_PROVIDER
    HITLS_CRYPT_BaseMethod cryptMethod = { 0 };
    cryptMethod.randBytes = (CRYPT_RandBytesCallback)STUB_CRYPT_RandBytesCallback;
    cryptMethod.hmacSize = (CRYPT_HmacSizeCallback)STUB_CRYPT_HmacSizeCallback;
    cryptMethod.hmacInit = (CRYPT_HmacInitCallback)STUB_CRYPT_HmacInitCallback;
    cryptMethod.hmacFree = (CRYPT_HmacFreeCallback)STUB_CRYPT_HmacFreeCallback;
    cryptMethod.hmacUpdate = (CRYPT_HmacUpdateCallback)STUB_CRYPT_HmacUpdateCallback;
    cryptMethod.hmacFinal = (CRYPT_HmacFinalCallback)STUB_CRYPT_HmacFinalCallback;
    cryptMethod.hmac = (CRYPT_HmacCallback)STUB_CRYPT_HmacCallback;
    cryptMethod.digestSize = (CRYPT_DigestSizeCallback)STUB_CRYPT_DigestSizeCallback;
    cryptMethod.digestInit = (CRYPT_DigestInitCallback)STUB_CRYPT_DigestInitCallback;
    cryptMethod.digestCopy = (CRYPT_DigestCopyCallback)STUB_CRYPT_DigestCopyCallback;
    cryptMethod.digestFree = (CRYPT_DigestFreeCallback)CRYPT_DEFAULT_DigestFree;
    cryptMethod.digestUpdate = (CRYPT_DigestUpdateCallback)STUB_CRYPT_DigestUpdateCallback;
    cryptMethod.digestFinal = (CRYPT_DigestFinalCallback)STUB_CRYPT_DigestFinalCallback;
    cryptMethod.digest = (CRYPT_DigestCallback)STUB_CRYPT_DigestCallback;
    cryptMethod.encrypt = (CRYPT_EncryptCallback)STUB_CRYPT_EncryptCallback;
    cryptMethod.decrypt = (CRYPT_DecryptCallback)STUB_CRYPT_DecryptCallback;
    cryptMethod.cipherFree = (CRYPT_CipherFreeCallback)CRYPT_DEFAULT_CipherFree;
    HITLS_CRYPT_RegisterBaseMethod(&cryptMethod);

    HITLS_CRYPT_EcdhMethod ecdhMethod = { 0 };
    ecdhMethod.generateEcdhKeyPair = (CRYPT_GenerateEcdhKeyPairCallback)STUB_CRYPT_GenerateEcdhKeyPairCallback;
    ecdhMethod.freeEcdhKey = (CRYPT_FreeEcdhKeyCallback)CRYPT_DEFAULT_FreeKey;
    ecdhMethod.getEcdhPubKey = (CRYPT_GetEcdhEncodedPubKeyCallback)STUB_CRYPT_GetEcdhEncodedPubKeyCallback;
    ecdhMethod.calcEcdhSharedSecret = (CRYPT_CalcEcdhSharedSecretCallback)STUB_CRYPT_CalcEcdhSharedSecretCallback;
    HITLS_CRYPT_RegisterEcdhMethod(&ecdhMethod);

    HITLS_CRYPT_DhMethod dhMethod = { 0 };
    dhMethod.generateDhKeyBySecbits = (CRYPT_GenerateDhKeyBySecbitsCallback)STUB_CRYPT_GenerateDhKeyBySecbitsCallback;
    dhMethod.generateDhKeyByParams = (CRYPT_GenerateDhKeyByParamsCallback)STUB_CRYPT_GenerateDhKeyByParamsCallback;
    dhMethod.freeDhKey = (CRYPT_FreeDhKeyCallback)CRYPT_DEFAULT_FreeKey;
    dhMethod.getDhParameters = (CRYPT_DHGetParametersCallback)STUB_CRYPT_DHGetParametersCallback;
    dhMethod.getDhPubKey = (CRYPT_GetDhEncodedPubKeyCallback)STUB_CRYPT_GetDhEncodedPubKeyCallback;
    dhMethod.calcDhSharedSecret = (CRYPT_CalcDhSharedSecretCallback)STUB_CRYPT_CalcDhSharedSecretCallback;
    HITLS_CRYPT_RegisterDhMethod(&dhMethod);
#else
    STUB_Init();
    STUB_Replace(&g_tmpRpInfo[0], CRYPT_EAL_RandbytesEx, STUB_CRYPT_RandBytesCallbackLibCtx);
    STUB_Replace(&g_tmpRpInfo[1], HITLS_CRYPT_HMAC_Init, STUB_CRYPT_HmacInitCallbackLibCtx);
    STUB_Replace(&g_tmpRpInfo[2], HITLS_CRYPT_HMAC, STUB_CRYPT_HmacCallbackLibCtx);
    STUB_Replace(&g_tmpRpInfo[3], HITLS_CRYPT_DigestInit, STUB_CRYPT_DigestInitCallbackLibCtx);
    STUB_Replace(&g_tmpRpInfo[4], HITLS_CRYPT_Digest, STUB_CRYPT_DigestCallbackLibCtx);
    STUB_Replace(&g_tmpRpInfo[5], HITLS_CRYPT_Encrypt, STUB_CRYPT_EncryptCallbackLibCtx);
    STUB_Replace(&g_tmpRpInfo[6], HITLS_CRYPT_Decrypt, STUB_CRYPT_DecryptCallbackLibCtx);
    STUB_Replace(&g_tmpRpInfo[7], HITLS_CRYPT_GenerateEcdhKey, STUB_CRYPT_GenerateEcdhKeyPairCallbackLibCtx);
    STUB_Replace(&g_tmpRpInfo[8], HITLS_CRYPT_EcdhCalcSharedSecret, STUB_CRYPT_CalcEcdhSharedSecretCallbackLibCtx);
    STUB_Replace(&g_tmpRpInfo[9], HITLS_CRYPT_GenerateDhKeyByParameters, STUB_CRYPT_GenerateDhKeyByParamsCallbackLibCtx);
    STUB_Replace(&g_tmpRpInfo[10], HITLS_CRYPT_GenerateDhKeyBySecbits, STUB_CRYPT_GenerateDhKeyBySecbitsCallbackLibCtx);
#endif
    return;
}

void FRAME_DeRegCryptMethod(void)
{
#ifndef HITLS_TLS_FEATURE_PROVIDER
    HITLS_CRYPT_BaseMethod cryptMethod = { 0 };
    HITLS_CRYPT_RegisterBaseMethod(&cryptMethod);

    HITLS_CRYPT_EcdhMethod ecdhMethod = { 0 };
    HITLS_CRYPT_RegisterEcdhMethod(&ecdhMethod);

    HITLS_CRYPT_DhMethod dhMethod = { 0 };
    HITLS_CRYPT_RegisterDhMethod(&dhMethod);
#else
    STUB_Reset(&g_tmpRpInfo[0]);
    STUB_Reset(&g_tmpRpInfo[1]);
    STUB_Reset(&g_tmpRpInfo[2]);
    STUB_Reset(&g_tmpRpInfo[3]);
    STUB_Reset(&g_tmpRpInfo[4]);
    STUB_Reset(&g_tmpRpInfo[5]);
    STUB_Reset(&g_tmpRpInfo[6]);
    STUB_Reset(&g_tmpRpInfo[7]);
    STUB_Reset(&g_tmpRpInfo[8]);
    STUB_Reset(&g_tmpRpInfo[9]);
    STUB_Reset(&g_tmpRpInfo[10]);
#endif
    return;
}