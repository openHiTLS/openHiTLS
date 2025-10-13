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

#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_HPKE)

#include <string.h>
#include "securec.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_bn.h"
#include "crypt_params_key.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"

#include "crypt_eal_hpke.h"

// Data from RFC9180
#define HPKE_HKDF_MAX_EXTRACT_KEY_LEN 64
#define HPKE_KEM_MAX_SHARED_KEY_LEN  64
#define HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN  133
#define HPKE_KEM_MAX_PUBLIC_KEY_LEN  133
#define HPKE_KEM_MAX_PRIVATE_KEY_LEN  66
#define HPKE_KEM_DH_MAX_SHARED_KEY_LEN 66 // p521 key length
#define MAX_ECC_PARAM_LEN 66

#define HPKE_AEAD_NONCE_LEN  12
#define HPKE_AEAD_TAG_LEN  16

#define HPKE_KEM_SUITEID_LEN 5
#define HPKE_HPKE_SUITEID_LEN 10

typedef struct {
    // PSK mode
    uint8_t *psk;
    uint32_t pskLen;
    uint8_t *pskId;
    uint32_t pskIdLen;
    // AUTH mode, Sender's private key held by the sender, Sender's public key held by the recipient
    CRYPT_EAL_PkeyCtx *authPkey;
} AuthInfo;

struct CRYPT_EAL_HpkeCtx {
    uint8_t role;                    // Sender or Recipient
    uint8_t mode;                    // HPKE mode
    uint8_t kemIndex;
    uint8_t kdfIndex;
    uint8_t aeadIndex;
    uint8_t *symKey;
    uint8_t *baseNonce;
    uint32_t symKeyLen;
    uint32_t baseNonceLen;
    uint8_t *exporterSecret;
    uint8_t *sharedSecret;
    uint32_t exporterSecretLen;
    uint32_t sharedSecretLen;
    uint64_t seq;                   // Message sequence number
    CRYPT_EAL_KdfCTX *kdfCtx;
    CRYPT_EAL_CipherCtx *cipherCtx;
    CRYPT_EAL_LibCtx *libCtx;
    char *attrName;
    AuthInfo *authInfo;
};

typedef struct {
    uint16_t hpkeKemId;
    CRYPT_PKEY_AlgId pkeyId;
    CRYPT_PKEY_ParaId curveId;
    CRYPT_MAC_AlgId macId;
    uint16_t privateKeyLen;
    uint16_t sharedKeyLen;
    uint16_t encapsulatedKeyLen;
    uint16_t hkdfExtractKeyLen;
} HPKE_KemAlgInfo;

typedef struct {
    uint16_t hpkeKdfId;
    uint16_t hkdfExtractKeyLen;
    CRYPT_MAC_AlgId macId;
} HPKE_KdfAlgInfo;

typedef struct {
    uint16_t hpkeAeadId;
    uint16_t keyLen;
    CRYPT_CIPHER_AlgId cipherId;
} HPKE_AeadAlgInfo;

#define HPKE_INVALID_ALG_INDEX 0xFF

static HPKE_KemAlgInfo g_hpkeKemAlgInfo[] = {
    {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_PKEY_ECDH, CRYPT_ECC_NISTP256, CRYPT_MAC_HMAC_SHA256, 32, 32, 65, 32},
    {CRYPT_KEM_DHKEM_P384_HKDF_SHA384, CRYPT_PKEY_ECDH, CRYPT_ECC_NISTP384, CRYPT_MAC_HMAC_SHA384, 48, 48, 97, 48},
    {CRYPT_KEM_DHKEM_P521_HKDF_SHA512, CRYPT_PKEY_ECDH, CRYPT_ECC_NISTP521, CRYPT_MAC_HMAC_SHA512, 66, 64, 133, 64},
    {CRYPT_KEM_DHKEM_X25519_HKDF_SHA256, CRYPT_PKEY_X25519, CRYPT_PKEY_PARAID_MAX, CRYPT_MAC_HMAC_SHA256, 32, 32, 32,
     32},
};

static HPKE_KdfAlgInfo g_hpkeKdfAlgInfo[] = {
    {CRYPT_KDF_HKDF_SHA256, 32, CRYPT_MAC_HMAC_SHA256},
    {CRYPT_KDF_HKDF_SHA384, 48, CRYPT_MAC_HMAC_SHA384},
    {CRYPT_KDF_HKDF_SHA512, 64, CRYPT_MAC_HMAC_SHA512},
};

static HPKE_AeadAlgInfo g_hpkeAeadAlgInfo[] = {
    {CRYPT_AEAD_AES_128_GCM, 16, CRYPT_CIPHER_AES128_GCM},
    {CRYPT_AEAD_AES_256_GCM, 32, CRYPT_CIPHER_AES256_GCM},
    {CRYPT_AEAD_CHACHA20_POLY1305, 32, CRYPT_CIPHER_CHACHA20_POLY1305},
    {CRYPT_AEAD_EXPORT_ONLY, 0, CRYPT_CIPHER_MAX},
};

static int32_t HpkeCheckCipherSuite(const CRYPT_HPKE_CipherSuite *cipherSuite, uint8_t *kemIndex, uint8_t *kdfIndex,
    uint8_t *aeadIndex)
{
    uint8_t kemPosition = HPKE_INVALID_ALG_INDEX;
    uint8_t kdfPosition = HPKE_INVALID_ALG_INDEX;
    uint8_t aeadPosition = HPKE_INVALID_ALG_INDEX;
    uint8_t i;

    for (i = 0; i < sizeof(g_hpkeKemAlgInfo) / sizeof(HPKE_KemAlgInfo); i++) {
        if (cipherSuite->kemId == g_hpkeKemAlgInfo[i].hpkeKemId) {
            kemPosition = i;
            break;
        }
    }

    for (i = 0; i < sizeof(g_hpkeKdfAlgInfo) / sizeof(HPKE_KdfAlgInfo); i++) {
        if (cipherSuite->kdfId == g_hpkeKdfAlgInfo[i].hpkeKdfId) {
            kdfPosition = i;
            break;
        }
    }

    for (i = 0; i < sizeof(g_hpkeAeadAlgInfo) / sizeof(HPKE_AeadAlgInfo); i++) {
        if (cipherSuite->aeadId == g_hpkeAeadAlgInfo[i].hpkeAeadId) {
            aeadPosition = i;
            break;
        }
    }

    if (kemPosition == HPKE_INVALID_ALG_INDEX || kdfPosition == HPKE_INVALID_ALG_INDEX ||
        aeadPosition == HPKE_INVALID_ALG_INDEX) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    if (kemIndex != NULL) {
        *kemIndex = kemPosition;
    }
    if (kdfIndex != NULL) {
        *kdfIndex = kdfPosition;
    }
    if (aeadIndex != NULL) {
        *aeadIndex = aeadPosition;
    }
    return CRYPT_SUCCESS;
}

static int32_t InitCipherSuiteCtx(CRYPT_EAL_HpkeCtx *ctx, uint8_t aeadIndex, CRYPT_EAL_LibCtx *libCtx,
    const char *attrName)
{
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    CRYPT_EAL_CipherCtx *cipherCtx = NULL;
    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_HKDF, attrName);
    if (kdfCtx == NULL) {
        return CRYPT_HPKE_FAILED_FETCH_KDF;
    }

    if (g_hpkeAeadAlgInfo[aeadIndex].hpkeAeadId != CRYPT_AEAD_EXPORT_ONLY) {
        cipherCtx = CRYPT_EAL_ProviderCipherNewCtx(libCtx, g_hpkeAeadAlgInfo[aeadIndex].cipherId, attrName);
        if (cipherCtx == NULL) {
            CRYPT_EAL_KdfFreeCtx(kdfCtx);
            return CRYPT_HPKE_FAILED_FETCH_CIPHER;
        }
    }

    ctx->kdfCtx = kdfCtx;
    ctx->cipherCtx = cipherCtx;
    return CRYPT_SUCCESS;
}

static int32_t HpkeInitCipherSuite(CRYPT_EAL_HpkeCtx *ctx, CRYPT_HPKE_CipherSuite *cipherSuite,
    CRYPT_EAL_LibCtx *libCtx, const char *attrName)
{
    uint8_t kemIndex;
    uint8_t kdfIndex;
    uint8_t aeadIndex;
    int32_t ret = HpkeCheckCipherSuite(cipherSuite, &kemIndex, &kdfIndex, &aeadIndex);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = InitCipherSuiteCtx(ctx, aeadIndex, libCtx, attrName);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ctx->kemIndex = kemIndex;
    ctx->aeadIndex = aeadIndex;
    ctx->kdfIndex = kdfIndex;
    return CRYPT_SUCCESS;
}

CRYPT_EAL_HpkeCtx *CRYPT_EAL_HpkeNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_HPKE_Role role,
    CRYPT_HPKE_Mode mode, CRYPT_HPKE_CipherSuite cipherSuite)
{
    if (role != CRYPT_HPKE_SENDER && role != CRYPT_HPKE_RECIPIENT) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }

    if (mode != CRYPT_HPKE_MODE_BASE && mode != CRYPT_HPKE_MODE_PSK && mode != CRYPT_HPKE_MODE_AUTH &&
        mode != CRYPT_HPKE_MODE_AUTH_PSK) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }

    CRYPT_EAL_HpkeCtx *ctx = (CRYPT_EAL_HpkeCtx*)BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_HpkeCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    int32_t ret = HpkeInitCipherSuite(ctx, &cipherSuite, libCtx, attrName);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_HpkeFreeCtx(ctx);
        return NULL;
    }

    if (attrName != NULL && strlen(attrName) > 0) {
        ctx->attrName = BSL_SAL_Dump(attrName, (uint32_t)strlen(attrName) + 1);
        if (ctx->attrName == NULL) {
            CRYPT_EAL_HpkeFreeCtx(ctx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
    }

    if (mode == CRYPT_HPKE_MODE_PSK || mode == CRYPT_HPKE_MODE_AUTH || mode == CRYPT_HPKE_MODE_AUTH_PSK) {
        AuthInfo *authInfo = (AuthInfo *)BSL_SAL_Calloc(1, sizeof(AuthInfo));
        if (authInfo == NULL) {
            CRYPT_EAL_HpkeFreeCtx(ctx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
        ctx->authInfo = authInfo;
    }

    ctx->mode = mode;
    ctx->role = role;
    ctx->libCtx = libCtx;
    return ctx;
}

int32_t CRYPT_EAL_HpkeGetEncapKeyLen(CRYPT_HPKE_CipherSuite cipherSuite, uint32_t *encapKeyLen)
{
    if (encapKeyLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint8_t kemIndex;
    int32_t ret = HpkeCheckCipherSuite(&cipherSuite, &kemIndex, NULL, NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    *encapKeyLen = g_hpkeKemAlgInfo[kemIndex].encapsulatedKeyLen;
    return CRYPT_SUCCESS;
}

static int32_t HpkeCreatePkeyCtx(uint8_t kemIdex, CRYPT_EAL_PkeyCtx **pkeyCtx, CRYPT_EAL_LibCtx *libCtx,
    const char *attrName)
{
    CRYPT_PKEY_AlgId algId = g_hpkeKemAlgInfo[kemIdex].pkeyId;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    pkey = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, algId, CRYPT_EAL_PKEY_EXCH_OPERATE, attrName);
#else
    (void)libCtx;
    (void)attrName;
    pkey = CRYPT_EAL_PkeyNewCtx(algId);
#endif
    if (pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_FAILED_FETCH_PKEY);
        return CRYPT_HPKE_FAILED_FETCH_PKEY;
    }

    if (algId == CRYPT_PKEY_ECDH) {
        CRYPT_PKEY_ParaId curveId = g_hpkeKemAlgInfo[kemIdex].curveId;
        int32_t ret = CRYPT_EAL_PkeySetParaById(pkey, curveId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            return ret;
        }
    }

    *pkeyCtx = pkey;
    return CRYPT_SUCCESS;
}

static int32_t HpkeCreatePubKey(uint8_t kemIdex, uint8_t *pubKey, uint32_t pubKeyLen, CRYPT_EAL_PkeyCtx **pkey,
    CRYPT_EAL_LibCtx *libCtx, const char *attrName)
{
    CRYPT_EAL_PkeyCtx *tmpPkey = NULL;
    int32_t ret = HpkeCreatePkeyCtx(kemIdex, &tmpPkey, libCtx, attrName);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = CRYPT_EAL_PkeyGetId(tmpPkey);
    pub.key.eccPub.data = pubKey; // compatible curve25519Pub
    pub.key.eccPub.len = pubKeyLen;

    ret = CRYPT_EAL_PkeySetPub(tmpPkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmpPkey);
        return ret;
    }

    *pkey = tmpPkey;
    return CRYPT_SUCCESS;
}

static int32_t HpkeCreatePriKey(uint8_t kemIdex, uint8_t *priKey, uint32_t priKeyLen, CRYPT_EAL_PkeyCtx **pkey,
    CRYPT_EAL_LibCtx *libCtx, const char *attrName)
{
    CRYPT_EAL_PkeyCtx *tmpPkey = *pkey;
    int32_t ret;

    if (tmpPkey == NULL) {
        ret = HpkeCreatePkeyCtx(kemIdex, &tmpPkey, libCtx, attrName);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    CRYPT_EAL_PkeyPrv prv = {0};
    prv.id = CRYPT_EAL_PkeyGetId(tmpPkey);
    prv.key.eccPrv.data = priKey;
    prv.key.eccPrv.len = priKeyLen;

    ret = CRYPT_EAL_PkeySetPrv(tmpPkey, &prv);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    if (g_hpkeKemAlgInfo[kemIdex].hpkeKemId == CRYPT_KEM_DHKEM_X25519_HKDF_SHA256) {
        ret = CRYPT_EAL_PkeyCtrl(tmpPkey, CRYPT_CTRL_GEN_X25519_PUBLICKEY, NULL, 0);
    } else {
        ret = CRYPT_EAL_PkeyCtrl(tmpPkey, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0);
    }

    if (ret == CRYPT_SUCCESS) {
        *pkey = tmpPkey;
        return CRYPT_SUCCESS;
    }

EXIT:
    if (*pkey == NULL) {
        CRYPT_EAL_PkeyFreeCtx(tmpPkey);
    }
    return ret;
}

static inline void HpkeGenerateHpkeSuiteId(uint8_t kemIndex, uint8_t kdfIndex, uint8_t aeadIndex, uint8_t *suiteId,
    uint32_t suiteIdLen)
{
    (void)memcpy_s(suiteId, suiteIdLen, "HPKE", strlen("HPKE"));
    uint32_t offset = strlen("HPKE");

    BSL_Uint16ToByte(g_hpkeKemAlgInfo[kemIndex].hpkeKemId, suiteId + offset);
    offset += sizeof(uint16_t);

    BSL_Uint16ToByte(g_hpkeKdfAlgInfo[kdfIndex].hpkeKdfId, suiteId + offset);
    offset += sizeof(uint16_t);

    BSL_Uint16ToByte(g_hpkeAeadAlgInfo[aeadIndex].hpkeAeadId, suiteId + offset);
}

static inline void HpkeGenerateKemSuiteId(uint8_t kemIdex, uint8_t *suiteId, uint32_t suiteIdLen)
{
    uint16_t kemId = g_hpkeKemAlgInfo[kemIdex].hpkeKemId;
    (void)memcpy_s(suiteId, suiteIdLen, "KEM", strlen("KEM"));
    uint32_t offset = strlen("KEM");

    BSL_Uint16ToByte(kemId, suiteId + offset);
}

typedef struct {
    int32_t macId;
    uint8_t *key;
    uint32_t keyLen;
    uint8_t *salt;
    uint32_t saltLen;
} HPKE_HkdfExtractParams;

typedef struct {
    int32_t macId;
    uint8_t *prk;
    uint32_t prkLen;
    uint8_t *info;
    uint32_t infoLen;
} HPKE_HkdfExpandParam;

static int32_t HpkeHkdfExtract(CRYPT_EAL_KdfCTX *hkdfCtx, HPKE_HkdfExtractParams *extractParams, uint8_t *out,
    uint32_t outLen)
{
    int32_t ret;
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXTRACT;

    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END}; // 6 parameters
    ret = BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, (void *)&extractParams->macId,
        sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, (void *)&mode, sizeof(mode));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, // param index 2
        (void *)extractParams->key, extractParams->keyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, // param index 3
        (void *)extractParams->salt, extractParams->saltLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_EXLEN, BSL_PARAM_TYPE_UINT32_PTR, // param index 4
        (void *)&outLen, sizeof(outLen));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CRYPT_EAL_KdfSetParam(hkdfCtx, params);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CRYPT_EAL_KdfDerive(hkdfCtx, out, outLen);
    CRYPT_EAL_KdfDeInitCtx(hkdfCtx);
    return ret;
}

static int32_t HpkeHkdfExpand(CRYPT_EAL_KdfCTX *hkdfCtx, HPKE_HkdfExpandParam *expandParams, uint8_t *out,
    uint32_t outLen)
{
    int32_t ret;
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXPAND;

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END}; // 5 parameters
    ret = BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, (void *)&expandParams->macId,
        sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, (void *)&mode, sizeof(mode));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_PRK, BSL_PARAM_TYPE_OCTETS, // param index 2
        (void *)expandParams->prk, expandParams->prkLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, // param index 3
        (void *)expandParams->info, expandParams->infoLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CRYPT_EAL_KdfSetParam(hkdfCtx, params);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CRYPT_EAL_KdfDerive(hkdfCtx, out, outLen);
    CRYPT_EAL_KdfDeInitCtx(hkdfCtx);
    return ret;
}

typedef struct {
    int32_t macId;
    uint8_t *salt;
    uint32_t saltLen;
    uint8_t *label;
    uint32_t labelLen;
    uint8_t *ikm;
    uint32_t ikmLen;
    uint8_t *suiteId;
    uint32_t suiteIdLen;
} HPKE_LabeledExtractParams;

typedef struct {
    int32_t macId;
    uint8_t *prk;
    uint32_t prkLen;
    uint8_t *label;
    uint32_t labelLen;
    uint8_t *info;
    uint32_t infoLen;
    uint8_t *suiteId;
    uint32_t suiteIdLen;
} HPKE_LabeledExpandParams;

static int32_t HpkeLabeledExtract(CRYPT_EAL_KdfCTX *hkdfCtx, HPKE_LabeledExtractParams *params, uint8_t *out,
    uint32_t outLen)
{
    // labeled_ikm = "HPKE-v1" || suite_id || label || ikm
    const uint8_t *version = (const uint8_t *)"HPKE-v1";
    uint32_t versionLen = strlen("HPKE-v1");
    uint32_t partialLen = versionLen + params->suiteIdLen + params->labelLen;
    if (params->ikmLen > (UINT32_MAX - partialLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t labeledIkmLen = partialLen + params->ikmLen;
    uint8_t *labeledIkm = (uint8_t *)BSL_SAL_Malloc(labeledIkmLen);
    if (labeledIkm == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    (void)memcpy_s(labeledIkm + offset, labeledIkmLen - offset, version, versionLen);
    offset += versionLen;
    (void)memcpy_s(labeledIkm + offset, labeledIkmLen - offset, params->suiteId, params->suiteIdLen);
    offset += params->suiteIdLen;
    (void)memcpy_s(labeledIkm + offset, labeledIkmLen - offset, params->label, params->labelLen);
    offset += params->labelLen;
    (void)memcpy_s(labeledIkm + offset, labeledIkmLen - offset, params->ikm, params->ikmLen);

    HPKE_HkdfExtractParams extractParams = {params->macId, labeledIkm, labeledIkmLen, params->salt, params->saltLen};
    int32_t ret = HpkeHkdfExtract(hkdfCtx, &extractParams, out, outLen);
    BSL_SAL_ClearFree(labeledIkm, labeledIkmLen);
    return ret;
}

static int32_t HpkeLabeledExpand(CRYPT_EAL_KdfCTX *hkdfCtx, HPKE_LabeledExpandParams *params, uint8_t *out,
    uint32_t outLen)
{
    // labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
    const uint8_t *version = (const uint8_t *)"HPKE-v1";
    uint32_t versionLen = strlen("HPKE-v1");
    uint32_t partialLen = sizeof(uint16_t) + versionLen + params->suiteIdLen + params->labelLen;

    if (params->infoLen > (UINT32_MAX - partialLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t labeledInfoLen = partialLen + params->infoLen;
    uint8_t *labeledInfo = (uint8_t *)BSL_SAL_Malloc(labeledInfoLen);
    if (labeledInfo == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    BSL_Uint16ToByte((uint16_t)outLen, labeledInfo);
    uint32_t offset = sizeof(uint16_t);
    (void)memcpy_s(labeledInfo + offset, labeledInfoLen - offset, version, versionLen);
    offset += versionLen;
    (void)memcpy_s(labeledInfo + offset, labeledInfoLen - offset, params->suiteId, params->suiteIdLen);
    offset += params->suiteIdLen;
    (void)memcpy_s(labeledInfo + offset, labeledInfoLen - offset, params->label, params->labelLen);
    offset += params->labelLen;
    (void)memcpy_s(labeledInfo + offset, labeledInfoLen - offset, params->info, params->infoLen);

    HPKE_HkdfExpandParam expandParams = {params->macId, params->prk, params->prkLen, labeledInfo, labeledInfoLen};
    int32_t ret = HpkeHkdfExpand(hkdfCtx, &expandParams, out, outLen);
    BSL_SAL_FREE(labeledInfo);
    return ret;
}

static int32_t GetPubKeyData(CRYPT_EAL_PkeyCtx *pkey, uint8_t *out, uint32_t *outLen)
{
    CRYPT_EAL_PkeyPub ephemPub = { 0 };
    ephemPub.id = CRYPT_EAL_PkeyGetId(pkey);
    ephemPub.key.eccPub.data = out;
    ephemPub.key.eccPub.len = *outLen; // compatible curve25519Pub, CRYPT_Data type.

    int32_t ret = CRYPT_EAL_PkeyGetPub(pkey, &ephemPub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    *outLen = ephemPub.key.eccPub.len;
    return CRYPT_SUCCESS;
}

static int32_t HpkeComputeSharedSecret(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *priKey, CRYPT_EAL_PkeyCtx *pubKey,
    CRYPT_EAL_PkeyCtx *authKey, uint8_t *kemContext, uint32_t kemContextLen, uint8_t *sharedSecret,
    uint32_t sharedSecretLen)
{
    uint8_t dh[HPKE_KEM_DH_MAX_SHARED_KEY_LEN * 2];
    uint32_t dhLen = HPKE_KEM_DH_MAX_SHARED_KEY_LEN;

    int32_t ret = CRYPT_EAL_PkeyComputeShareKey(priKey, pubKey, dh, &dhLen);
    if (ret != CRYPT_SUCCESS) {
        memset_s(dh, dhLen, 0, dhLen);
        return ret;
    }

    if (ctx->mode == CRYPT_HPKE_MODE_AUTH || ctx->mode == CRYPT_HPKE_MODE_AUTH_PSK) {
        uint32_t dh0Len = HPKE_KEM_DH_MAX_SHARED_KEY_LEN;

        if (ctx->role == CRYPT_HPKE_SENDER) {
            ret = CRYPT_EAL_PkeyComputeShareKey(authKey, pubKey, dh + dhLen, &dh0Len);
        }
        if (ctx->role == CRYPT_HPKE_RECIPIENT) {
            ret = CRYPT_EAL_PkeyComputeShareKey(priKey, authKey, dh + dhLen, &dh0Len);
        }
        if (ret != CRYPT_SUCCESS) {
            memset_s(dh, dhLen + dh0Len, 0, dhLen + dh0Len);
            return ret;
        }
        dhLen = dhLen + dh0Len;
    }

    uint8_t suiteId[HPKE_KEM_SUITEID_LEN];
    HpkeGenerateKemSuiteId(ctx->kemIndex, suiteId, HPKE_KEM_SUITEID_LEN);

    CRYPT_MAC_AlgId macId = g_hpkeKemAlgInfo[ctx->kemIndex].macId;
    uint32_t eaePrkLen = g_hpkeKemAlgInfo[ctx->kemIndex].hkdfExtractKeyLen;
    uint8_t eaePrk[HPKE_HKDF_MAX_EXTRACT_KEY_LEN];

    HPKE_LabeledExtractParams extractParams = {macId, NULL, 0, (uint8_t *)"eae_prk", strlen("eae_prk"), dh, dhLen,
        suiteId, HPKE_KEM_SUITEID_LEN};
    ret = HpkeLabeledExtract(ctx->kdfCtx, &extractParams, eaePrk, eaePrkLen);
    BSL_SAL_CleanseData(dh, dhLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    HPKE_LabeledExpandParams expandParams = {macId, eaePrk, eaePrkLen, (uint8_t *)"shared_secret",
        strlen("shared_secret"), kemContext, kemContextLen, suiteId, HPKE_KEM_SUITEID_LEN};
    ret = HpkeLabeledExpand(ctx->kdfCtx, &expandParams, sharedSecret, sharedSecretLen);

    BSL_SAL_CleanseData(eaePrk, eaePrkLen);
    return ret;
}

static int32_t HpkeCreateKemContext(uint8_t *enc, uint32_t encLen, uint8_t *pkR, uint32_t pkRLen,
    CRYPT_EAL_PkeyCtx *authKey, uint8_t **out, uint32_t *outLen)
{
    uint8_t pkSm[HPKE_KEM_MAX_PUBLIC_KEY_LEN] = { 0 };
    uint32_t pkSmLen = HPKE_KEM_MAX_PUBLIC_KEY_LEN;

    if (authKey != NULL) {
        int32_t ret = GetPubKeyData(authKey, pkSm, &pkSmLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    } else {
        pkSmLen = 0;
    }

    // kemContext = enc || pkRm || pkSm
    uint32_t kemContextLen = encLen + pkRLen + pkSmLen;
    uint8_t *kemContext = (uint8_t *)BSL_SAL_Malloc(kemContextLen);
    if (kemContext == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    (void)memcpy_s(kemContext, encLen, enc, encLen);
    (void)memcpy_s(kemContext + encLen, pkRLen, pkR, pkRLen);

    if (authKey != NULL) {
        (void)memcpy_s(kemContext + encLen + pkRLen, pkSmLen, pkSm, pkSmLen);
    }

    *out = kemContext;
    *outLen = kemContextLen;
    return CRYPT_SUCCESS;
}

static int32_t HpkeEncap(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, uint8_t *pkR, uint32_t pkRLen,
    uint8_t *encapsulatedKey, uint32_t *encapsulatedKeyLen, uint8_t *sharedSecret, uint32_t sharedSecretLen)
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkeyS = pkey;
    if (pkeyS == NULL) {
        CRYPT_HPKE_CipherSuite cipherSuite = {g_hpkeKemAlgInfo[ctx->kemIndex].hpkeKemId,
            g_hpkeKdfAlgInfo[ctx->kdfIndex].hpkeKdfId, g_hpkeAeadAlgInfo[ctx->aeadIndex].hpkeAeadId};
        ret = CRYPT_EAL_HpkeGenerateKeyPair(ctx->libCtx, ctx->attrName, cipherSuite, NULL, 0, &pkeyS);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    uint8_t enc[HPKE_KEM_MAX_PUBLIC_KEY_LEN] = { 0 };
    uint32_t encLen = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    uint32_t kemContextLen = 0;
    uint8_t *kemContext = NULL;
    CRYPT_EAL_PkeyCtx *authKey = NULL;

    if (ctx->mode == CRYPT_HPKE_MODE_AUTH || ctx->mode == CRYPT_HPKE_MODE_AUTH_PSK) {
        authKey = ctx->authInfo->authPkey;
    }

    ret = GetPubKeyData(pkeyS, enc, &encLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = HpkeCreatePubKey(ctx->kemIndex, pkR, pkRLen, &pkeyR, ctx->libCtx, ctx->attrName);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = HpkeCreateKemContext(enc, encLen, pkR, pkRLen, authKey, &kemContext, &kemContextLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = HpkeComputeSharedSecret(ctx, pkeyS, pkeyR, authKey, kemContext, kemContextLen, sharedSecret, sharedSecretLen);
    if (ret == CRYPT_SUCCESS) {
        (void)memcpy_s(encapsulatedKey, *encapsulatedKeyLen, enc, encLen);
        *encapsulatedKeyLen = encLen;
    }
EXIT:
    BSL_SAL_FREE(kemContext);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
    if (pkey == NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkeyS);
    }
    return ret;
}

static int32_t HpkeGenKeyScheduleCtx(CRYPT_EAL_HpkeCtx *ctx, uint8_t *info, uint32_t infoLen, uint8_t *pskId,
    uint32_t pskIdLen, uint8_t *suiteId, uint32_t suiteIdLen, uint8_t **keyScheduleContext,
    uint32_t *keyScheduleContextLen)
{
    uint32_t extractKeyLen = g_hpkeKdfAlgInfo[ctx->kdfIndex].hkdfExtractKeyLen;
    uint32_t contextLen = sizeof(uint8_t) + extractKeyLen + extractKeyLen;
    uint8_t *context = (uint8_t *)BSL_SAL_Malloc(contextLen);
    if (context == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    context[0] = ctx->mode;
    uint32_t offset = sizeof(uint8_t);
    CRYPT_MAC_AlgId macId = g_hpkeKdfAlgInfo[ctx->kdfIndex].macId;
    HPKE_LabeledExtractParams params = {macId, NULL, 0, (uint8_t*)"psk_id_hash", strlen("psk_id_hash"), pskId, pskIdLen,
        suiteId, suiteIdLen};
    int32_t ret = HpkeLabeledExtract(ctx->kdfCtx, &params, context + offset, extractKeyLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    offset += extractKeyLen;
    params.label = (uint8_t*)"info_hash";
    params.labelLen = strlen("info_hash");
    params.ikm = info;
    params.ikmLen = infoLen;
    ret = HpkeLabeledExtract(ctx->kdfCtx, &params, context + offset, extractKeyLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    *keyScheduleContext = context;
    *keyScheduleContextLen = contextLen;
    return CRYPT_SUCCESS;
EXIT:
    BSL_SAL_ClearFree(context, contextLen);
    return ret;
}

static void HpkeFreeKeyInfo(CRYPT_EAL_HpkeCtx *ctx)
{
    BSL_SAL_ClearFree(ctx->symKey, ctx->symKeyLen);
    ctx->symKey = NULL;
    ctx->symKeyLen = 0;

    BSL_SAL_ClearFree(ctx->baseNonce, ctx->baseNonceLen);
    ctx->baseNonce = NULL;
    ctx->baseNonceLen = 0;

    BSL_SAL_ClearFree(ctx->exporterSecret, ctx->exporterSecretLen);
    ctx->exporterSecret = NULL;
    ctx->exporterSecretLen = 0;
}

static int32_t HpkeMallocKeyInfo(CRYPT_EAL_HpkeCtx *ctx)
{
    if (g_hpkeAeadAlgInfo[ctx->aeadIndex].hpkeAeadId != CRYPT_AEAD_EXPORT_ONLY) {
        ctx->symKeyLen = g_hpkeAeadAlgInfo[ctx->aeadIndex].keyLen;
        ctx->symKey = BSL_SAL_Malloc(ctx->symKeyLen);
        ctx->baseNonceLen = HPKE_AEAD_NONCE_LEN;
        ctx->baseNonce = BSL_SAL_Malloc(HPKE_AEAD_NONCE_LEN);
        if (ctx->symKey == NULL || ctx->baseNonce == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            HpkeFreeKeyInfo(ctx);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }

    ctx->exporterSecretLen = g_hpkeKdfAlgInfo[ctx->kdfIndex].hkdfExtractKeyLen;
    ctx->exporterSecret = BSL_SAL_Malloc(ctx->exporterSecretLen);
    if (ctx->exporterSecret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        HpkeFreeKeyInfo(ctx);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t HpkeDeriveKeyInfo(CRYPT_EAL_HpkeCtx *ctx, HPKE_LabeledExpandParams *expandParams)
{
    CRYPT_HPKE_AEAD_AlgId aeadId = g_hpkeAeadAlgInfo[ctx->aeadIndex].hpkeAeadId;
    if (aeadId != CRYPT_AEAD_EXPORT_ONLY) {
        int32_t ret = HpkeLabeledExpand(ctx->kdfCtx, expandParams, ctx->symKey, ctx->symKeyLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }

        expandParams->label = (uint8_t*)"base_nonce";
        expandParams->labelLen = strlen("base_nonce");
        ret = HpkeLabeledExpand(ctx->kdfCtx, expandParams, ctx->baseNonce, ctx->baseNonceLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    expandParams->label = (uint8_t*)"exp";
    expandParams->labelLen = strlen("exp");
    return HpkeLabeledExpand(ctx->kdfCtx, expandParams, ctx->exporterSecret, ctx->exporterSecretLen);
}

static int32_t HpkeKeySchedule(CRYPT_EAL_HpkeCtx *ctx, uint8_t *sharedSecret, uint32_t sharedSecretLen, uint8_t *info,
    uint32_t infoLen)
{
    uint8_t suiteId[HPKE_HPKE_SUITEID_LEN];
    uint8_t suiteIdLen = HPKE_HPKE_SUITEID_LEN;
    HpkeGenerateHpkeSuiteId(ctx->kemIndex, ctx->kdfIndex, ctx->aeadIndex, suiteId, HPKE_HPKE_SUITEID_LEN);

    uint32_t contextLen;
    uint8_t *context = NULL;
    uint8_t *pskId = (uint8_t *)"";
    uint32_t pskIdLen = 0;
    uint8_t *psk = (uint8_t *)"";
    uint32_t pskLen = 0;
    
    if (ctx->mode == CRYPT_HPKE_MODE_PSK || ctx->mode == CRYPT_HPKE_MODE_AUTH_PSK) {
        pskId = ctx->authInfo->pskId;
        pskIdLen = ctx->authInfo->pskIdLen;
        psk = ctx->authInfo->psk;
        pskLen = ctx->authInfo->pskLen;
    }

    int32_t ret = HpkeGenKeyScheduleCtx(ctx, info, infoLen, pskId, pskIdLen, suiteId, suiteIdLen, &context,
        &contextLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_MAC_AlgId macId = g_hpkeKdfAlgInfo[ctx->kdfIndex].macId;
    uint8_t secret[HPKE_KEM_MAX_SHARED_KEY_LEN] = {0};
    uint32_t secretLen = g_hpkeKdfAlgInfo[ctx->kdfIndex].hkdfExtractKeyLen;
    HPKE_LabeledExtractParams extractparams = {macId, sharedSecret, sharedSecretLen, (uint8_t*)"secret",
        strlen("secret"), psk, pskLen, suiteId, suiteIdLen};
    HPKE_LabeledExpandParams expandParams = {macId, secret, secretLen, (uint8_t*)"key", strlen("key"), context,
        contextLen, suiteId, suiteIdLen};

    ret = HpkeLabeledExtract(ctx->kdfCtx, &extractparams, secret, secretLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = HpkeMallocKeyInfo(ctx);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = HpkeDeriveKeyInfo(ctx, &expandParams);

EXIT:
    BSL_SAL_CleanseData(secret, HPKE_KEM_MAX_SHARED_KEY_LEN);
    BSL_SAL_ClearFree(context, contextLen);
    if (ret != CRYPT_SUCCESS) {
        HpkeFreeKeyInfo(ctx);
    }
    return ret;
}

static int32_t HpkeCheckAuthInfo(CRYPT_EAL_HpkeCtx *ctx)
{
    if (ctx->mode == CRYPT_HPKE_MODE_AUTH || ctx->mode == CRYPT_HPKE_MODE_AUTH_PSK) {
        if (ctx->authInfo == NULL || ctx->authInfo->authPkey == NULL) {
            return CRYPT_HPKE_ERR_CALL;
        }
    }

    if (ctx->mode == CRYPT_HPKE_MODE_PSK || ctx->mode == CRYPT_HPKE_MODE_AUTH_PSK) {
        if (ctx->authInfo == NULL || ctx->authInfo->psk == NULL || ctx->authInfo->pskId == NULL) {
            return CRYPT_HPKE_ERR_CALL;
        }
    }

    return CRYPT_SUCCESS;
}

static void HpkeFreeAuthInfo(CRYPT_EAL_HpkeCtx *ctx)
{
    if (ctx->authInfo == NULL) {
        return;
    }

    BSL_SAL_ClearFree(ctx->authInfo->psk, ctx->authInfo->pskLen);
    ctx->authInfo->psk = NULL;
    ctx->authInfo->pskLen = 0;

    BSL_SAL_ClearFree(ctx->authInfo->pskId, ctx->authInfo->pskIdLen);
    ctx->authInfo->pskId = NULL;
    ctx->authInfo->pskIdLen = 0;

    CRYPT_EAL_PkeyFreeCtx(ctx->authInfo->authPkey);
    ctx->authInfo->authPkey = NULL;

    BSL_SAL_FREE(ctx->authInfo);
}

static int32_t HpkeCheckSenderParams(CRYPT_EAL_HpkeCtx *ctx, uint8_t *info, uint32_t infoLen, const uint8_t *pkR,
    uint32_t pkRLen, uint8_t *encapsulatedKey, uint32_t *encapsulatedKeyLen)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->role != CRYPT_HPKE_SENDER) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->sharedSecret != NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (pkR == NULL || encapsulatedKey == NULL || encapsulatedKeyLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if ((info == NULL && infoLen != 0) || (info != NULL && infoLen == 0)) {
        return CRYPT_INVALID_ARG;
    }

    uint32_t encLen = g_hpkeKemAlgInfo[ctx->kemIndex].encapsulatedKeyLen;
    if (pkRLen != encLen) {
        return CRYPT_INVALID_ARG;
    }

    if (*encapsulatedKeyLen < encLen) {
        return CRYPT_INVALID_ARG;
    }

    return HpkeCheckAuthInfo(ctx);
}

int32_t CRYPT_EAL_HpkeSetupSender(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, uint8_t *info, uint32_t infoLen,
    uint8_t *pkR, uint32_t pkRLen, uint8_t *encapKey, uint32_t *encapKeyLen)
{
    int32_t ret = HpkeCheckSenderParams(ctx, info, infoLen, pkR, pkRLen, encapKey, encapKeyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t sharedSecretLen = g_hpkeKemAlgInfo[ctx->kemIndex].sharedKeyLen;
    uint8_t *sharedSecret = BSL_SAL_Malloc(sharedSecretLen);
    if (sharedSecret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = HpkeEncap(ctx, pkey, pkR, pkRLen, encapKey, encapKeyLen, sharedSecret, sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(sharedSecret, sharedSecretLen);
        return ret;
    }

    ret = HpkeKeySchedule(ctx, sharedSecret, sharedSecretLen, info, infoLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(sharedSecret, sharedSecretLen);
        return ret;
    }

    ctx->sharedSecret = sharedSecret;
    ctx->sharedSecretLen = sharedSecretLen;
    HpkeFreeAuthInfo(ctx); // Derived key successfully, no longer requires authinfo
    return ret;
}

static int32_t HpkeAeadEncrypt(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *nonce, uint32_t nonceLen, uint8_t *aad,
    uint32_t aadLen, const uint8_t *plainText, uint32_t plainTextLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    CRYPT_EAL_CipherCtx *cipherCtx = ctx->cipherCtx;
    uint32_t outLen = *cipherTextLen;
    int32_t ret = CRYPT_EAL_CipherInit(cipherCtx, ctx->symKey, ctx->symKeyLen, nonce, nonceLen, true);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    if (aad != NULL && aadLen > 0) {
        ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_SET_AAD, aad, aadLen);
        if (ret != CRYPT_SUCCESS) {
            goto EXIT;
        }
    }

    ret = CRYPT_EAL_CipherUpdate(cipherCtx, plainText, plainTextLen, cipherText, &outLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_GET_TAG, cipherText + outLen, HPKE_AEAD_TAG_LEN);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    *cipherTextLen = outLen + HPKE_AEAD_TAG_LEN;
EXIT:
    CRYPT_EAL_CipherDeinit(cipherCtx);
    return ret;
}

int32_t CRYPT_EAL_HpkeSetSeq(CRYPT_EAL_HpkeCtx *ctx, uint64_t seq)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (seq == UINT64_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    ctx->seq = seq;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeGetSeq(CRYPT_EAL_HpkeCtx *ctx, uint64_t *seq)
{
    if (ctx == NULL || seq == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    *seq = ctx->seq;
    return CRYPT_SUCCESS;
}

static void HpkeComputeNonce(CRYPT_EAL_HpkeCtx *ctx, uint8_t *nonce, uint32_t nonceLen)
{
    uint64_t seq = ctx->seq;
    for (uint32_t i = 0; i < sizeof(seq); i++) {
        nonce[nonceLen - i - 1] = seq & UINT8_MAX;
        seq = seq >> 8; // 8 bits
    }

    for (uint32_t i = 0; i < nonceLen; i++) {
        nonce[i] ^= ctx->baseNonce[i];
    }
}

static int32_t HpkeCheckSealParams(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *plainText, uint32_t plainTextLen,
    uint32_t *cipherTextLen)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->role != CRYPT_HPKE_SENDER) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (g_hpkeAeadAlgInfo[ctx->aeadIndex].hpkeAeadId == CRYPT_AEAD_EXPORT_ONLY) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->symKey == NULL || ctx->baseNonce == NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (plainText == NULL || plainTextLen == 0 || cipherTextLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (plainTextLen > (UINT32_MAX - HPKE_AEAD_TAG_LEN)) {
        return CRYPT_INVALID_ARG;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeSeal(CRYPT_EAL_HpkeCtx *ctx, uint8_t *aad, uint32_t aadLen, const uint8_t *plainText,
    uint32_t plainTextLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    int32_t ret = HpkeCheckSealParams(ctx, plainText, plainTextLen, cipherTextLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (ctx->seq + 1 == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (cipherText == NULL) {
        *cipherTextLen = plainTextLen + HPKE_AEAD_TAG_LEN;
        return CRYPT_SUCCESS;
    }

    if (*cipherTextLen < (plainTextLen + HPKE_AEAD_TAG_LEN)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint8_t nonce[HPKE_AEAD_NONCE_LEN] = { 0 };
    HpkeComputeNonce(ctx, nonce, HPKE_AEAD_NONCE_LEN);

    ret = HpkeAeadEncrypt(ctx, nonce, HPKE_AEAD_NONCE_LEN, aad, aadLen, plainText, plainTextLen, cipherText,
        cipherTextLen);
    if (ret == CRYPT_SUCCESS) {
        ctx->seq++;
    }
    return ret;
}

static int32_t HpkeDecap(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, uint8_t *encKey, uint32_t encKeyLen,
    uint8_t *sharedSecret, uint32_t sharedSecretLen)
{
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    int32_t ret = HpkeCreatePubKey(ctx->kemIndex, encKey, encKeyLen, &pkeyS, ctx->libCtx, ctx->attrName);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint8_t *kemContext = NULL;
    uint32_t kemContextLen;
    uint8_t pubKeyData[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    uint32_t pubKeyDataLen = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    CRYPT_EAL_PkeyCtx *authKey = NULL;

    if (ctx->mode == CRYPT_HPKE_MODE_AUTH || ctx->mode == CRYPT_HPKE_MODE_AUTH_PSK) {
        authKey = ctx->authInfo->authPkey;
    }

    ret = GetPubKeyData(pkey, pubKeyData, &pubKeyDataLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = HpkeCreateKemContext(encKey, encKeyLen, pubKeyData, pubKeyDataLen, authKey, &kemContext, &kemContextLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = HpkeComputeSharedSecret(ctx, pkey, pkeyS, authKey, kemContext, kemContextLen, sharedSecret, sharedSecretLen);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    BSL_SAL_FREE(kemContext);
    return ret;
}

static int32_t HpkeCheckRecipientParams(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, uint8_t *info,
    uint32_t infoLen, const uint8_t *encapsulatedKey, uint32_t encapsulatedKeyLen)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->role != CRYPT_HPKE_RECIPIENT) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->sharedSecret != NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if ((info == NULL && infoLen != 0) || (info != NULL && infoLen == 0)) {
        return CRYPT_INVALID_ARG;
    }

    if (pkey == NULL || encapsulatedKey == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (encapsulatedKeyLen != g_hpkeKemAlgInfo[ctx->kemIndex].encapsulatedKeyLen) {
        return CRYPT_INVALID_ARG;
    }

    return HpkeCheckAuthInfo(ctx);
}

int32_t CRYPT_EAL_HpkeSetupRecipient(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, uint8_t *info, uint32_t infoLen,
    uint8_t *encapKey, uint32_t encapKeyLen)
{
    int32_t ret = HpkeCheckRecipientParams(ctx, pkey, info, infoLen, encapKey, encapKeyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t sharedSecretLen = g_hpkeKemAlgInfo[ctx->kemIndex].sharedKeyLen;
    uint8_t *sharedSecret = BSL_SAL_Malloc(sharedSecretLen);
    if (sharedSecret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = HpkeDecap(ctx, pkey, encapKey, encapKeyLen, sharedSecret, sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(sharedSecret, sharedSecretLen);
        return ret;
    }

    ret = HpkeKeySchedule(ctx, sharedSecret, sharedSecretLen, info, infoLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(sharedSecret, sharedSecretLen);
        return ret;
    }

    ctx->sharedSecret = sharedSecret;
    ctx->sharedSecretLen = sharedSecretLen;
    HpkeFreeAuthInfo(ctx); // Derived key successfully, no longer requires authinfo
    return ret;
}

static int32_t HpkeAeadDecrypt(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *nonce, uint32_t nonceLen, uint8_t *aad,
    uint32_t aadLen, const uint8_t *cipherText, uint32_t cipherTextLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    CRYPT_EAL_CipherCtx *cipherCtx = ctx->cipherCtx;

    int32_t ret = CRYPT_EAL_CipherInit(cipherCtx, ctx->symKey, ctx->symKeyLen, nonce, nonceLen, false);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherDeinit(cipherCtx);
        return ret;
    }

    if (aad != NULL && aadLen > 0) {
        ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_SET_AAD, (void *)aad, aadLen);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherDeinit(cipherCtx);
            return ret;
        }
    }

    ret = CRYPT_EAL_CipherUpdate(cipherCtx, cipherText, cipherTextLen - HPKE_AEAD_TAG_LEN, plainText, plainTextLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherDeinit(cipherCtx);
        return ret;
    }

    uint8_t tag[HPKE_AEAD_TAG_LEN];
    ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_GET_TAG, (void *)tag, HPKE_AEAD_TAG_LEN);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    if (memcmp(tag, cipherText + (cipherTextLen - HPKE_AEAD_TAG_LEN), HPKE_AEAD_TAG_LEN) != 0) {
        ret = CRYPT_HPKE_ERR_AEAD_TAG;
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_AEAD_TAG);
    }

EXIT:
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(plainText, *plainTextLen);
    }

    CRYPT_EAL_CipherDeinit(cipherCtx);
    return ret;
}

static int32_t HpkeCheckOpenParams(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *cipherText, uint32_t cipherTextLen,
    uint32_t *plainTextLen)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->role != CRYPT_HPKE_RECIPIENT) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (g_hpkeAeadAlgInfo[ctx->aeadIndex].hpkeAeadId == CRYPT_AEAD_EXPORT_ONLY) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->symKey == NULL || ctx->baseNonce == NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (cipherText == NULL || cipherTextLen == 0 || plainTextLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeOpen(CRYPT_EAL_HpkeCtx *ctx, uint8_t *aad, uint32_t aadLen, const uint8_t *cipherText,
    uint32_t cipherTextLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    int32_t ret = HpkeCheckOpenParams(ctx, cipherText, cipherTextLen, plainTextLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (ctx->seq + 1 == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (cipherTextLen <= HPKE_AEAD_TAG_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    if (plainText == NULL) {
        *plainTextLen = cipherTextLen - HPKE_AEAD_TAG_LEN;
        return CRYPT_SUCCESS;
    }

    uint8_t nonce[HPKE_AEAD_NONCE_LEN] = { 0 };
    HpkeComputeNonce(ctx, nonce, HPKE_AEAD_NONCE_LEN);

    ret = HpkeAeadDecrypt(ctx, nonce, HPKE_AEAD_NONCE_LEN, aad, aadLen, cipherText, cipherTextLen, plainText,
        plainTextLen);
    if (ret == CRYPT_SUCCESS) {
        ctx->seq++;
    }
    return ret;
}

void CRYPT_EAL_HpkeFreeCtx(CRYPT_EAL_HpkeCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_ClearFree(ctx->sharedSecret, ctx->sharedSecretLen);
    HpkeFreeKeyInfo(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx->cipherCtx);
    CRYPT_EAL_KdfFreeCtx(ctx->kdfCtx);
    BSL_SAL_FREE(ctx->attrName);
    HpkeFreeAuthInfo(ctx);
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_EAL_HpkeCtx));
}

static int32_t HpkeGetEccOrder(CRYPT_EAL_PkeyCtx *pkey, BN_BigNum **order)
{
    uint8_t ecP[MAX_ECC_PARAM_LEN];
    uint8_t ecA[MAX_ECC_PARAM_LEN];
    uint8_t ecB[MAX_ECC_PARAM_LEN];
    uint8_t ecN[MAX_ECC_PARAM_LEN];
    uint8_t ecH[MAX_ECC_PARAM_LEN];
    uint8_t ecX[MAX_ECC_PARAM_LEN];
    uint8_t ecY[MAX_ECC_PARAM_LEN];

    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_EAL_PkeyGetId(pkey);
    para.para.eccPara.p = ecP;
    para.para.eccPara.a = ecA;
    para.para.eccPara.b = ecB;
    para.para.eccPara.n = ecN;
    para.para.eccPara.h = ecH;
    para.para.eccPara.x = ecX;
    para.para.eccPara.y = ecY;
    para.para.eccPara.pLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.aLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.bLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.nLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.hLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.xLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.yLen = MAX_ECC_PARAM_LEN;
    int32_t ret = CRYPT_EAL_PkeyGetPara(pkey, &para);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    BN_BigNum *bn = BN_Create(para.para.eccPara.nLen * 8);
    if (bn == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = BN_Bin2Bn(bn, para.para.eccPara.n, para.para.eccPara.nLen);
    if (ret != CRYPT_SUCCESS) {
        BN_Destroy(bn);
        return ret;
    }

    *order = bn;
    return CRYPT_SUCCESS;
}

static int32_t HpkeExpandEccPriKey(CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_KdfCTX *hkdfCtx, uint32_t kemIndex,
    HPKE_LabeledExpandParams *params, uint8_t *sk, uint32_t skLen)
{
    BN_BigNum *order = NULL;
    int32_t ret = HpkeGetEccOrder(pkey, &order);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    BN_BigNum *skBn = BN_Create(skLen * 8);
    if (skBn == NULL) {
        BN_Destroy(order);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint8_t counter = 0;
    uint8_t bitmask = 0xFF; // 0xFF for P256 P384
    if (g_hpkeKemAlgInfo[kemIndex].hpkeKemId == CRYPT_KEM_DHKEM_P521_HKDF_SHA512) {
        bitmask = 0x01;
    }
    do {
        if (counter == 255) { // RFC9180 7.1.3, up to 255 attempts.
            ret = CRYPT_HPKE_ERR_GEN_ASYM_KEY;
            BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_GEN_ASYM_KEY);
            break;
        }
        *(params->info) = counter;
        ret = HpkeLabeledExpand(hkdfCtx, params, sk, skLen);
        if (ret != CRYPT_SUCCESS) {
            break;
        }

        sk[0] = sk[0] & bitmask;
        ret = BN_Bin2Bn(skBn, sk, skLen);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        counter++;
    } while (BN_IsZero(skBn) || BN_Cmp(skBn, order) >= 0);
    BN_Destroy(skBn);
    BN_Destroy(order);

    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(sk, skLen);
    }
    return ret;
}

static int32_t DeriveSk(uint8_t kemIndex, CRYPT_EAL_KdfCTX *kdfCtx, CRYPT_EAL_PkeyCtx *pkey,
    HPKE_LabeledExpandParams *expandParams, uint8_t *sk, uint32_t skLen)
{
    if (g_hpkeKemAlgInfo[kemIndex].hpkeKemId == CRYPT_KEM_DHKEM_X25519_HKDF_SHA256) {
        return HpkeLabeledExpand(kdfCtx, expandParams, sk, skLen);
    } else {
        uint8_t counter = 0;
        expandParams->label = (uint8_t *)"candidate";
        expandParams->labelLen = strlen("candidate");
        expandParams->info = (uint8_t *)&counter;
        expandParams->infoLen = sizeof(uint8_t);
        return HpkeExpandEccPriKey(pkey, kdfCtx, kemIndex, expandParams, sk, skLen);
    }
}

static int32_t HpkeDeriveKeyPair(uint8_t kemIndex, uint8_t *ikm, uint32_t ikmLen,
    CRYPT_EAL_PkeyCtx **pctx, CRYPT_EAL_LibCtx *libCtx, const char *attrName)
{
    uint8_t suiteId[HPKE_KEM_SUITEID_LEN];
    HpkeGenerateKemSuiteId(kemIndex, suiteId, HPKE_KEM_SUITEID_LEN);

    uint8_t dkpPrk[HPKE_HKDF_MAX_EXTRACT_KEY_LEN];
    uint8_t sk[HPKE_KEM_MAX_PRIVATE_KEY_LEN] = { 0 };
    uint32_t dkpPrkLen = g_hpkeKemAlgInfo[kemIndex].hkdfExtractKeyLen;
    CRYPT_MAC_AlgId macId = g_hpkeKemAlgInfo[kemIndex].macId;
    uint32_t skLen = g_hpkeKemAlgInfo[kemIndex].privateKeyLen;

    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_HKDF, attrName);
    if (kdfCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_FAILED_FETCH_KDF);
        return CRYPT_HPKE_FAILED_FETCH_KDF;
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    int32_t ret = HpkeCreatePkeyCtx(kemIndex, &pkey, libCtx, attrName);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(kdfCtx);
        return ret;
    }

    HPKE_LabeledExtractParams extractParams = {macId, (uint8_t *)"", 0, (uint8_t *)"dkp_prk", strlen("dkp_prk"),
        ikm, ikmLen, suiteId, HPKE_KEM_SUITEID_LEN};
    HPKE_LabeledExpandParams expandParams = {macId, dkpPrk, dkpPrkLen, (uint8_t *)"sk", strlen("sk"), (uint8_t *)"", 0,
        suiteId, HPKE_KEM_SUITEID_LEN};
    ret = HpkeLabeledExtract(kdfCtx, &extractParams, dkpPrk, dkpPrkLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = DeriveSk(kemIndex, kdfCtx, pkey, &expandParams, sk, skLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = HpkeCreatePriKey(kemIndex, sk, skLen, &pkey, libCtx, attrName);

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    BSL_SAL_CleanseData(sk, skLen);
    BSL_SAL_CleanseData(dkpPrk, HPKE_HKDF_MAX_EXTRACT_KEY_LEN);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return ret;
    }
    *pctx = pkey;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeGenerateKeyPair(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    CRYPT_HPKE_CipherSuite cipherSuite, uint8_t *ikm, uint32_t ikmLen, CRYPT_EAL_PkeyCtx **pctx)
{
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (*pctx != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint8_t kemIndex;
    int32_t ret = HpkeCheckCipherSuite(&cipherSuite, &kemIndex, NULL, NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t ikmNewLen = g_hpkeKemAlgInfo[kemIndex].privateKeyLen;
    if (ikm != NULL && ikmLen != 0) {
        if (ikmLen < ikmNewLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        return HpkeDeriveKeyPair(kemIndex, ikm, ikmLen, pctx, libCtx, attrName);
    }

    uint8_t ikmNew[HPKE_KEM_MAX_PRIVATE_KEY_LEN];
    ret = CRYPT_EAL_RandbytesEx(libCtx, ikmNew, ikmNewLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = HpkeDeriveKeyPair(kemIndex, ikmNew, ikmNewLen, pctx, libCtx, attrName);
    BSL_SAL_CleanseData(ikmNew, ikmNewLen);
    return ret;
}

int32_t CRYPT_EAL_HpkeExportSecret(CRYPT_EAL_HpkeCtx *ctx, uint8_t *info, uint32_t infoLen, uint8_t *key,
    uint32_t keyLen)
{
    if (ctx == NULL || key == NULL || keyLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->exporterSecret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if ((info == NULL && infoLen != 0) || (info != NULL && infoLen == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    if (keyLen > 255 * g_hpkeKdfAlgInfo[ctx->kdfIndex].hkdfExtractKeyLen) { // RFC9180 5.3 max L is 255*Nh
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint8_t suiteId[HPKE_HPKE_SUITEID_LEN];
    HpkeGenerateHpkeSuiteId(ctx->kemIndex, ctx->kdfIndex, ctx->aeadIndex, suiteId, HPKE_HPKE_SUITEID_LEN);

    CRYPT_MAC_AlgId macId = g_hpkeKdfAlgInfo[ctx->kdfIndex].macId;
    HPKE_LabeledExpandParams params = {macId, ctx->exporterSecret, ctx->exporterSecretLen, (uint8_t *)"sec",
        strlen("sec"), info, infoLen, suiteId, HPKE_HPKE_SUITEID_LEN};
    return HpkeLabeledExpand(ctx->kdfCtx, &params, key, keyLen);
}

int32_t CRYPT_EAL_HpkeGetSharedSecret(CRYPT_EAL_HpkeCtx *ctx, uint8_t *buff, uint32_t *buffLen)
{
    if (ctx == NULL || buffLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->sharedSecret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (buff == NULL) {
        *buffLen = ctx->sharedSecretLen;
        return CRYPT_SUCCESS;
    }

    if (*buffLen < ctx->sharedSecretLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    (void)memcpy_s(buff, *buffLen, ctx->sharedSecret, ctx->sharedSecretLen);
    *buffLen = ctx->sharedSecretLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeSetSharedSecret(CRYPT_EAL_HpkeCtx *ctx, uint8_t *info, uint32_t infoLen,
    uint8_t *buff, uint32_t buffLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->sharedSecret != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (buff == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if ((info == NULL && infoLen != 0) || (info != NULL && infoLen == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    if (buffLen != g_hpkeKemAlgInfo[ctx->kemIndex].sharedKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    if (ctx->mode == CRYPT_HPKE_MODE_PSK || ctx->mode == CRYPT_HPKE_MODE_AUTH_PSK) {
        if (ctx->authInfo == NULL || ctx->authInfo->psk == NULL || ctx->authInfo->pskId == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
            return CRYPT_HPKE_ERR_CALL;
        }
    }

    int32_t ret = HpkeKeySchedule(ctx, buff, buffLen, info, infoLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ctx->sharedSecret = BSL_SAL_Dump(buff, buffLen);
    if (ctx->sharedSecret == NULL) {
        HpkeFreeKeyInfo(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->sharedSecretLen = buffLen;
    HpkeFreeAuthInfo(ctx); // Derived key successfully, no longer requires authinfo
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeSetPsk(CRYPT_EAL_HpkeCtx *ctx, uint8_t *psk, uint32_t pskLen, uint8_t *pskId, uint32_t pskIdLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->mode != CRYPT_HPKE_MODE_PSK && ctx->mode != CRYPT_HPKE_MODE_AUTH_PSK) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->authInfo == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->authInfo->psk != NULL || ctx->authInfo->pskId != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    // psk and pskId must appear together
    if (psk == NULL || pskIdLen == 0 || pskId == NULL || pskLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->authInfo->psk = BSL_SAL_Dump(psk, pskLen);
    if (ctx->authInfo->psk == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->authInfo->pskLen = pskLen;

    ctx->authInfo->pskId = BSL_SAL_Dump(pskId, pskIdLen);
    if (ctx->authInfo->pskId == NULL) {
        BSL_SAL_ClearFree(ctx->authInfo->psk, ctx->authInfo->pskLen);
        ctx->authInfo->psk = NULL;
        ctx->authInfo->pskLen = 0;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->authInfo->pskIdLen = pskIdLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeSetAuthPriKey(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey)
{
    if (ctx == NULL || pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->mode != CRYPT_HPKE_MODE_AUTH && ctx->mode != CRYPT_HPKE_MODE_AUTH_PSK) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->role != CRYPT_HPKE_SENDER) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->authInfo == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->authInfo->authPkey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    CRYPT_EAL_PkeyCtx *skS = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    skS = CRYPT_EAL_ProviderPkeyNewCtx(ctx->libCtx, g_hpkeKemAlgInfo[ctx->kemIndex].pkeyId,
        CRYPT_EAL_PKEY_EXCH_OPERATE, ctx->attrName);
#else
    skS = CRYPT_EAL_PkeyNewCtx(g_hpkeKemAlgInfo[ctx->kemIndex].pkeyId);
#endif
    if (skS == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_FAILED_FETCH_PKEY);
        return CRYPT_HPKE_FAILED_FETCH_PKEY;
    }

    int32_t ret = CRYPT_EAL_PkeyCopyCtx(skS, pkey);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(skS);
        return ret;
    }

    ctx->authInfo->authPkey = skS;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeSetAuthPubKey(CRYPT_EAL_HpkeCtx *ctx, uint8_t *pub, uint32_t pubLen)
{
    if (ctx == NULL || pub == NULL || pubLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->mode != CRYPT_HPKE_MODE_AUTH && ctx->mode != CRYPT_HPKE_MODE_AUTH_PSK) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->role != CRYPT_HPKE_RECIPIENT) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->authInfo == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->authInfo->authPkey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HPKE_ERR_CALL);
        return CRYPT_HPKE_ERR_CALL;
    }

    CRYPT_EAL_PkeyCtx *pkS = NULL;
    int32_t ret = HpkeCreatePubKey(ctx->kemIndex, pub, pubLen, &pkS, ctx->libCtx, ctx->attrName);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ctx->authInfo->authPkey = pkS;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_HPKE
