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
#include "hitls_build.h"
#include "config_type.h"
#include "hitls_cert_type.h"
#include "tls_config.h"
#include "crypt_algid.h"
#include "hitls_error.h"
#include "cipher_suite.h"
#include "config.h"

#ifdef HITLS_TLS_FEATURE_PROVIDER
#include "securec.h"
#include "crypt_eal_provider.h"
#include "crypt_params_key.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_pkey.h"
#endif

static const uint16_t DEFAULT_SIGSCHEME_ID[] = {
    CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
    CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
    CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512,
    CERT_SIG_SCHEME_ED25519,
    CERT_SIG_SCHEME_SM2_SM3,
    CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256,
    CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384,
    CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512,
    CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256,
    CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384,
    CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512,
    CERT_SIG_SCHEME_RSA_PKCS1_SHA256,
    CERT_SIG_SCHEME_RSA_PKCS1_SHA384,
    CERT_SIG_SCHEME_RSA_PKCS1_SHA512,
    CERT_SIG_SCHEME_ECDSA_SHA224,
    CERT_SIG_SCHEME_ECDSA_SHA1,
    CERT_SIG_SCHEME_RSA_PKCS1_SHA224,
    CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
    CERT_SIG_SCHEME_DSA_SHA224,
    CERT_SIG_SCHEME_DSA_SHA256,
    CERT_SIG_SCHEME_DSA_SHA384,
    CERT_SIG_SCHEME_DSA_SHA512,
    CERT_SIG_SCHEME_DSA_SHA1,
};

static int32_t UpdateSignAlgorithmsArray(TLS_Config *config)
{
    if (config == NULL) {
        return HITLS_INVALID_INPUT;
    }
    uint16_t *tempItems = BSL_SAL_Calloc(sizeof(DEFAULT_SIGSCHEME_ID), sizeof(uint8_t));
    if (tempItems == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    uint32_t size = 0;
    for (uint32_t i = 0; i < sizeof(DEFAULT_SIGSCHEME_ID) / sizeof(DEFAULT_SIGSCHEME_ID[0]); i++) {
        const TLS_SigSchemeInfo *info = ConfigGetSignatureSchemeInfo(config, DEFAULT_SIGSCHEME_ID[i]);
        if (info == NULL || (config->version & info->chainVersionBits) == 0) {
            continue;
        }
        tempItems[size] = DEFAULT_SIGSCHEME_ID[i];
        size++;
    }
    if (size == 0) {
        BSL_SAL_Free(tempItems);
        return HITLS_INVALID_INPUT;
    }
    BSL_SAL_FREE(config->signAlgorithms);
    config->signAlgorithms = tempItems;
    config->signAlgorithmsSize = size;
    return HITLS_SUCCESS;
}

#ifndef HITLS_TLS_FEATURE_PROVIDER
#ifndef HITLS_TLS_CAP_NO_STR
#define CONST_CAST(str) ((char *)(uintptr_t)(str))
#else
#define CONST_CAST(str) NULL
#endif
static const TLS_SigSchemeInfo SIGNATURE_SCHEME_INFO[] = {
    {
        CONST_CAST("ecdsa_secp521r1_sha512"),
        CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_ECC_NISTP521,
        BSL_CID_ECDSAWITHSHA512,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA_512,
        256,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("ecdsa_secp384r1_sha384"),
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_ECC_NISTP384,
        BSL_CID_ECDSAWITHSHA384,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA_384,
        192,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("ed25519"),
        CERT_SIG_SCHEME_ED25519,
        TLS_CERT_KEY_TYPE_ED25519,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_ED25519,
        HITLS_SIGN_ED25519,
        HITLS_HASH_SHA_512,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("ecdsa_secp256r1_sha256"),
        CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_ECC_NISTP256,
        BSL_CID_ECDSAWITHSHA256,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA_256,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("sm2_sm3"),
        CERT_SIG_SCHEME_SM2_SM3,
        TLS_CERT_KEY_TYPE_SM2,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SM2DSAWITHSM3,
        HITLS_SIGN_SM2,
        HITLS_HASH_SM3,
        128,
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT | TLS13_VERSION_BIT,
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT | TLS13_VERSION_BIT,
    },
    {
        CONST_CAST("rsa_pss_pss_sha512"),
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_512,
        256,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pss_pss_sha384"),
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_384,
        192,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pss_pss_sha256"),
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_256,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pss_rsae_sha512"),
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_512,
        256,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pss_rsae_sha384"),
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_384,
        192,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pss_rsae_sha256"),
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_256,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pkcs1_sha512"),
        CERT_SIG_SCHEME_RSA_PKCS1_SHA512,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA512WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_512,
        256,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("dsa_sha512"),
        CERT_SIG_SCHEME_DSA_SHA512,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA512,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_512,
        256,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        CONST_CAST("rsa_pkcs1_sha384"),
        CERT_SIG_SCHEME_RSA_PKCS1_SHA384,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA384WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_384,
        192,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("dsa_sha384"),
        CERT_SIG_SCHEME_DSA_SHA384,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA384,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_384,
        192,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        CONST_CAST("rsa_pkcs1_sha256"),
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA256WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_256,
        128,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("dsa_sha256"),
        CERT_SIG_SCHEME_DSA_SHA256,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA256,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_256,
        128,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        CONST_CAST("ecdsa_sha224"),
        CERT_SIG_SCHEME_ECDSA_SHA224,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_ECDSAWITHSHA224,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        CONST_CAST("rsa_pkcs1_sha224"),
        CERT_SIG_SCHEME_RSA_PKCS1_SHA224,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA224WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        CONST_CAST("dsa_sha224"),
        CERT_SIG_SCHEME_DSA_SHA224,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA224,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        CONST_CAST("ecdsa_sha1"),
        CERT_SIG_SCHEME_ECDSA_SHA1,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_ECDSAWITHSHA1,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA1,
        -1,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        CONST_CAST("rsa_pkcs1_sha1"),
        CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA1WITHRSA,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA1,
        -1,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        CONST_CAST("dsa_sha1"),
        CERT_SIG_SCHEME_DSA_SHA1,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA1,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA1,
        -1,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
};

int32_t ConfigLoadSignatureSchemeInfo(HITLS_Config *config)
{
    return UpdateSignAlgorithmsArray(config);
}

const TLS_SigSchemeInfo *ConfigGetSignatureSchemeInfo(const HITLS_Config *config, uint16_t signatureScheme)
{
    (void)config;
    for (uint32_t i = 0; i < sizeof(SIGNATURE_SCHEME_INFO) / sizeof(TLS_SigSchemeInfo); i++) {
        if (SIGNATURE_SCHEME_INFO[i].signatureScheme == signatureScheme) {
            return &SIGNATURE_SCHEME_INFO[i];
        }
    }
    return NULL;
}

const TLS_SigSchemeInfo *ConfigGetSignatureSchemeInfoList(const HITLS_Config *config, uint32_t *size)
{
    (void)config;
    *size = sizeof(SIGNATURE_SCHEME_INFO) / sizeof(SIGNATURE_SCHEME_INFO[0]);
    return SIGNATURE_SCHEME_INFO;
}

#else // HITLS_TLS_FEATURE_PROVIDER

static int32_t PrepareSignSchemeStorage(TLS_Config *config, TLS_SigSchemeInfo **scheme)
{
    if (config->sigSchemeInfolen == config->sigSchemeInfoSize) {
        void *ptr = BSL_SAL_Realloc(config->sigSchemeInfo,
            (config->sigSchemeInfoSize + TLS_CAPABILITY_LIST_MALLOC_SIZE) * sizeof(TLS_SigSchemeInfo),
            config->sigSchemeInfoSize * sizeof(TLS_SigSchemeInfo));
        if (ptr == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        config->sigSchemeInfo = ptr;
        (void)memset_s(config->sigSchemeInfo + config->sigSchemeInfoSize,
            TLS_CAPABILITY_LIST_MALLOC_SIZE * sizeof(TLS_SigSchemeInfo),
            0,
            TLS_CAPABILITY_LIST_MALLOC_SIZE * sizeof(TLS_SigSchemeInfo));
        config->sigSchemeInfoSize += TLS_CAPABILITY_LIST_MALLOC_SIZE;
    }
    *scheme = config->sigSchemeInfo + config->sigSchemeInfolen;
    return HITLS_SUCCESS;
}

typedef struct {
    BslOidString oidStr;
    const char *oidName;
} BslOidInfo;

#ifdef HITLS_BSL_OBJ_CUSTOM
static int32_t ProcessOids(TLS_SigSchemeInfo *scheme, BslOidInfo *keyTypeOidInfo, BslOidInfo *paraOidInfo,
                         BslOidInfo *signHashAlgOidInfo, BslOidInfo *hashOidInfo)
{
    int32_t ret = HITLS_SUCCESS;
    if (keyTypeOidInfo != NULL && keyTypeOidInfo->oidStr.octs != NULL) {
        ret = BSL_OBJ_Create(keyTypeOidInfo->oidStr.octs, keyTypeOidInfo->oidStr.octetLen,
            keyTypeOidInfo->oidName, scheme->keyType);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    if (paraOidInfo != NULL && paraOidInfo->oidStr.octs != NULL) {
        ret = BSL_OBJ_Create(paraOidInfo->oidStr.octs, paraOidInfo->oidStr.octetLen,
            paraOidInfo->oidName, scheme->paraId);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    if (hashOidInfo != NULL && hashOidInfo->oidStr.octs != NULL) {
        ret = BSL_OBJ_Create(hashOidInfo->oidStr.octs, hashOidInfo->oidStr.octetLen,
            hashOidInfo->oidName, scheme->hashAlgId);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    if (signHashAlgOidInfo != NULL && signHashAlgOidInfo->oidStr.octs != NULL) {
        ret = BSL_OBJ_Create(signHashAlgOidInfo->oidStr.octs, signHashAlgOidInfo->oidStr.octetLen,
            signHashAlgOidInfo->oidName, scheme->signHashAlgId);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    return BSL_OBJ_CreateSignId(scheme->signHashAlgId, scheme->signAlgId, scheme->hashAlgId);
}
#endif

static int32_t ProviderAddSignatureSchemeInfo(const BSL_Param *params, void *args)
{
    if (params == NULL || args == NULL) {
        return HITLS_INVALID_INPUT;
    }
    
    TLS_CapabilityData *data = (TLS_CapabilityData *)args;
    TLS_Config *config = data->config;
    TLS_SigSchemeInfo *scheme = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BSL_Param *param = NULL;
#ifdef HITLS_BSL_OBJ_CUSTOM
    const char *keyTypeOid = NULL, *keyTypeName = NULL, *paraOid = NULL, *paraName = NULL;
    const char *signHashAlgOid = NULL, *signHashAlgName = NULL, *hashOid = NULL, *hashName = NULL;
    uint32_t keyTypeOidLen = 0, paraOidLen = 0, signHashAlgOidLen = 0, hashOidLen = 0;
#endif

    int32_t ret = PrepareSignSchemeStorage(config, &scheme);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = HITLS_CONFIG_ERR_LOAD_SIGN_SCHEME_INFO;
#ifndef HITLS_TLS_CAP_NO_STR
    PROCESS_STRING_PARAM(param, scheme, params, CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME, name);
#endif
    PROCESS_PARAM_UINT16(param, scheme, params, CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_ID, signatureScheme);
    PROCESS_PARAM_INT32(param, scheme, params, CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE, keyType);
    PROCESS_PARAM_INT32(param, scheme, params, CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID, paraId);
    PROCESS_PARAM_INT32(param, scheme, params, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_ID, signHashAlgId);
    PROCESS_PARAM_INT32(param, scheme, params, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGN_ID, signAlgId);
    PROCESS_PARAM_INT32(param, scheme, params, CRYPT_PARAM_CAP_TLS_SIGNALG_MD_ID, hashAlgId);
    PROCESS_PARAM_INT32(param, scheme, params, CRYPT_PARAM_CAP_TLS_SIGNALG_SEC_BITS, secBits);
    PROCESS_PARAM_UINT32(param, scheme, params, CRYPT_PARAM_CAP_TLS_SIGNALG_CHAIN_VERSION_BITS, chainVersionBits);
    PROCESS_PARAM_UINT32(param, scheme, params, CRYPT_PARAM_CAP_TLS_SIGNALG_CERT_VERSION_BITS, certVersionBits);
#ifdef HITLS_BSL_OBJ_CUSTOM
    PROCESS_OPTIONAL_STRING_PARAM(param, params, CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_OID, keyTypeOid, keyTypeOidLen,
        CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_NAME, keyTypeName);
    PROCESS_OPTIONAL_STRING_PARAM(param, params, CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_OID, paraOid, paraOidLen,
        CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_NAME, paraName);
    PROCESS_OPTIONAL_STRING_PARAM(param, params, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_OID, signHashAlgOid,
        signHashAlgOidLen, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_NAME, signHashAlgName);
    PROCESS_OPTIONAL_STRING_PARAM(param, params, CRYPT_PARAM_CAP_TLS_SIGNALG_MD_OID, hashOid, hashOidLen,
        CRYPT_PARAM_CAP_TLS_SIGNALG_MD_NAME, hashName);
#endif

    if (scheme->keyType == TLS_CERT_KEY_TYPE_RSA_PSS) {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(LIBCTX_FROM_CONFIG(config), TLS_CERT_KEY_TYPE_RSA,
            CRYPT_EAL_PKEY_SIGN_OPERATE, ATTRIBUTE_FROM_CONFIG(config));
    } else {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(LIBCTX_FROM_CONFIG(config), scheme->keyType,
            CRYPT_EAL_PKEY_SIGN_OPERATE, ATTRIBUTE_FROM_CONFIG(config));
    }
    if (pkey == NULL) {
        goto ERR;
    }

#ifdef HITLS_BSL_OBJ_CUSTOM
    BslOidInfo keyTypeOidInfo = { { keyTypeOidLen, (char *)(uintptr_t)keyTypeOid, 0 }, keyTypeName };
    BslOidInfo paraOidInfo = { { paraOidLen, (char *)(uintptr_t)paraOid, 0 }, paraName };
    BslOidInfo signHashAlgOidInfo = { { signHashAlgOidLen, (char *)(uintptr_t)signHashAlgOid, 0 }, signHashAlgName };
    BslOidInfo hashOidInfo = { { hashOidLen, (char *)(uintptr_t)hashOid, 0 }, hashName };
    ret = ProcessOids(scheme, &keyTypeOidInfo, &paraOidInfo, &signHashAlgOidInfo, &hashOidInfo);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
#endif
    config->sigSchemeInfolen++;
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return HITLS_SUCCESS;

ERR:
    if (pkey != NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
    if (scheme != NULL) {
        BSL_SAL_Free(scheme->name);
        (void)memset_s(scheme, sizeof(TLS_SigSchemeInfo), 0, sizeof(TLS_SigSchemeInfo));
    }
    return ret != HITLS_SUCCESS ? ret : HITLS_CONFIG_ERR_LOAD_SIGN_SCHEME_INFO;
}

static int32_t ProviderLoadSignSchemeInfo(CRYPT_EAL_ProvMgrCtx *ctx, void *args)
{
    if (ctx == NULL || args == NULL) {
        return HITLS_INVALID_INPUT;
    }
    TLS_CapabilityData data = {
        .config = (TLS_Config *)args,
        .provMgrCtx = ctx,
    };
    return CRYPT_EAL_ProviderGetCaps(ctx, CRYPT_EAL_GET_SIGALG_CAP, ProviderAddSignatureSchemeInfo, &data);
}

int32_t ConfigLoadSignatureSchemeInfo(HITLS_Config *config)
{
    HITLS_Lib_Ctx *libCtx = LIBCTX_FROM_CONFIG(config);
    int32_t ret = CRYPT_EAL_ProviderProcessAll(libCtx, ProviderLoadSignSchemeInfo, config);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return UpdateSignAlgorithmsArray(config);
}

const TLS_SigSchemeInfo *ConfigGetSignatureSchemeInfo(const HITLS_Config *config, uint16_t signatureScheme)
{
    for (uint32_t i = 0; i < config->sigSchemeInfolen; i++) {
        if (config->sigSchemeInfo[i].signatureScheme == signatureScheme) {
            return &config->sigSchemeInfo[i];
        }
    }
    return NULL;
}

const TLS_SigSchemeInfo *ConfigGetSignatureSchemeInfoList(const HITLS_Config *config, uint32_t *size)
{
    *size = config->sigSchemeInfolen;
    return config->sigSchemeInfo;
}

#endif
