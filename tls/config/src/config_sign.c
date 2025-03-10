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

#ifdef HITLS_TLS_FEATURE_PROVIDER
#include "securec.h"
#include "crypt_eal_provider.h"
#include "crypt_params_key.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_pkey.h"
#endif
static int32_t UpdateSignAlgorithmsArray(TLS_Config *config, const TLS_SigSchemeInfo *sigSchemes, uint32_t sigSchemeLen)
{
    if (config == NULL || sigSchemes == NULL || sigSchemeLen == 0) {
        return HITLS_INVALID_INPUT;
    }

    uint32_t size = 0;
    uint16_t *tempSignSchemes = BSL_SAL_Calloc(sigSchemeLen, sizeof(uint16_t));
    if (tempSignSchemes == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    for (uint32_t i = 0; i < sigSchemeLen; i++) {
        if ((config->version & sigSchemes[i].chainVersionBits) != 0) {
            bool isDuplicate = false;
            // Check if this signScheme already exists
            for (uint32_t j = 0; j < size; j++) {
                if (tempSignSchemes[j] == sigSchemes[i].signatureScheme) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                tempSignSchemes[size] = sigSchemes[i].signatureScheme;
                size++;
            }
        }
    }

    if (size == 0) {
        BSL_SAL_Free(tempSignSchemes);
        return HITLS_INVALID_INPUT;
    }

    BSL_SAL_FREE(config->signAlgorithms);
    config->signAlgorithms = tempSignSchemes;
    config->signAlgorithmsSize = size;
    return HITLS_SUCCESS;
}


#ifndef HITLS_TLS_FEATURE_PROVIDER
static const TLS_SigSchemeInfo SIGNATURE_SCHEME_INFO[] = {
    {
        "ecdsa_secp521r1_sha512",
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
        "ecdsa_secp384r1_sha384",
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
        "ed25519",
        CERT_SIG_SCHEME_ED25519,
        TLS_CERT_KEY_TYPE_ED25519,
        0,
        BSL_CID_ED25519,
        HITLS_SIGN_ED25519,
        HITLS_HASH_SHA_512,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "ecdsa_secp256r1_sha256",
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
        "sm2_sm3",
        CERT_SIG_SCHEME_SM2_SM3,
        TLS_CERT_KEY_TYPE_SM2,
        0,
        BSL_CID_SM2DSAWITHSM3,
        HITLS_SIGN_SM2,
        HITLS_HASH_SM3,
        128,
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT,
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT,
    },
    {
        "rsa_pss_pss_sha512",
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        0,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_512,
        256,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pss_pss_sha384",
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        0,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_384,
        192,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pss_pss_sha256",
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        0,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_256,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pss_rsae_sha512",
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512,
        TLS_CERT_KEY_TYPE_RSA,
        0,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_512,
        256,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pss_rsae_sha384",
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384,
        TLS_CERT_KEY_TYPE_RSA,
        0,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_384,
        192,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pss_rsae_sha256",
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256,
        TLS_CERT_KEY_TYPE_RSA,
        0,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_256,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pkcs1_sha512",
        CERT_SIG_SCHEME_RSA_PKCS1_SHA512,
        TLS_CERT_KEY_TYPE_RSA,
        0,
        BSL_CID_SHA512WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_512,
        256,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "dsa_sha512",
        CERT_SIG_SCHEME_DSA_SHA512,
        TLS_CERT_KEY_TYPE_DSA,
        0,
        BSL_CID_DSAWITHSHA512,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_512,
        256,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "rsa_pkcs1_sha384",
        CERT_SIG_SCHEME_RSA_PKCS1_SHA384,
        TLS_CERT_KEY_TYPE_RSA,
        0,
        BSL_CID_SHA384WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_384,
        192,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "dsa_sha384",
        CERT_SIG_SCHEME_DSA_SHA384,
        TLS_CERT_KEY_TYPE_DSA,
        0,
        BSL_CID_DSAWITHSHA384,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_384,
        192,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "rsa_pkcs1_sha256",
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256,
        TLS_CERT_KEY_TYPE_RSA,
        0,
        BSL_CID_SHA256WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_256,
        128,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "dsa_sha256",
        CERT_SIG_SCHEME_DSA_SHA256,
        TLS_CERT_KEY_TYPE_DSA,
        0,
        BSL_CID_DSAWITHSHA256,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_256,
        128,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "ecdsa_sha224",
        CERT_SIG_SCHEME_ECDSA_SHA224,
        TLS_CERT_KEY_TYPE_ECDSA,
        0,
        BSL_CID_ECDSAWITHSHA224,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "rsa_pkcs1_sha224",
        CERT_SIG_SCHEME_RSA_PKCS1_SHA224,
        TLS_CERT_KEY_TYPE_RSA,
        0,
        BSL_CID_SHA224WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "dsa_sha224",
        CERT_SIG_SCHEME_DSA_SHA224,
        TLS_CERT_KEY_TYPE_DSA,
        0,
        BSL_CID_DSAWITHSHA224,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "ecdsa_sha1",
        CERT_SIG_SCHEME_ECDSA_SHA1,
        TLS_CERT_KEY_TYPE_ECDSA,
        0,
        BSL_CID_ECDSAWITHSHA1,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA1,
        -1,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "rsa_pkcs1_sha1",
        CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        TLS_CERT_KEY_TYPE_RSA,
        0,
        BSL_CID_SHA1WITHRSA,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA1,
        -1,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "dsa_sha1",
        CERT_SIG_SCHEME_DSA_SHA1,
        TLS_CERT_KEY_TYPE_DSA,
        0,
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
    return UpdateSignAlgorithmsArray(config, SIGNATURE_SCHEME_INFO, sizeof(SIGNATURE_SCHEME_INFO) / sizeof(TLS_SigSchemeInfo));
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
#else

typedef struct {
    uint32_t octetLen;
    char *octs;
    uint32_t flags;
} BslOidString;

int32_t BSL_OBJ_Create(const BslOidString *oid, const char *oidName, int32_t cid);
int32_t BSL_OBJ_CreateSignId(int32_t signId, int32_t asymId, int32_t hashId);

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

    BslOidString oidStr = { 0 };
    const char *keyTypeOid = NULL;
    const char *keyTypeName = NULL;
    uint32_t keyTypeOidLen = 0;
    const char *paraOid = NULL;
    const char *paraName = NULL;
    uint32_t paraOidLen = 0;
    const char *signHashAlgOid = NULL;
    const char *signHashAlgName = NULL;
    uint32_t signHashAlgOidLen = 0;
    const char *hashOid = NULL;
    const char *hashName = NULL;
    uint32_t hashOidLen = 0;

    int32_t ret = HITLS_CONFIG_ERR_LOAD_SIGN_SCHEME_INFO;
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
    scheme = config->sigSchemeInfo + config->sigSchemeInfolen;
    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
        goto ERR;
    }
    scheme->name = BSL_SAL_Calloc(param->valueLen + 1, sizeof(char));
    if (scheme->name == NULL) {
        goto ERR;
    }
    (void)memcpy_s(scheme->name, param->valueLen + 1, param->value, param->valueLen);

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_ID);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_UINT16) {
        goto ERR;
    }
    scheme->signatureScheme = *(uint16_t *)param->value;
    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_INT32) {
        goto ERR;
    }
    scheme->keyType = *(int32_t *)param->value;

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_INT32) {
        goto ERR;
    }
    scheme->paraId = *(int32_t *)param->value;

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_ID);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_INT32) {
        goto ERR;
    }
    scheme->signHashAlgId = *(int32_t *)param->value;

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGN_ID);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_INT32) {
        goto ERR;
    }
    scheme->signAlgId = *(int32_t *)param->value;

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_MD_ID);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_INT32) {
        goto ERR;
    }
    scheme->hashAlgId = *(int32_t *)param->value;

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_SEC_BITS);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_INT32) {
        goto ERR;
    }
    scheme->secBits = *(int32_t *)param->value;

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_CHAIN_VERSION_BITS);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_UINT32) {
        goto ERR;
    }
    scheme->chainVersionBits = *(uint32_t *)param->value;

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_CERT_VERSION_BITS);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_UINT32) {
        goto ERR;
    }
    scheme->certVersionBits = *(uint32_t *)param->value;

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_OID);
    if (param == NULL) {
        keyTypeOid = NULL;
    } else if (param->valueType == BSL_PARAM_TYPE_OCTETS_PTR) {
        keyTypeOid = (const char *)param->value;
        keyTypeOidLen = param->valueLen;
        param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_NAME);
        if (param == NULL || param->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
            goto ERR;
        }
        keyTypeName = param->value;
    } else {
        goto ERR;
    }

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_OID);
    if (param == NULL) {
        paraOid = NULL;
    } else if (param->valueType == BSL_PARAM_TYPE_OCTETS_PTR) {
        paraOid = (const char *)param->value;
        paraOidLen = param->valueLen;
        param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_NAME);
        if (param == NULL || param->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
            goto ERR;
        }
        paraName = param->value;
    } else {
        goto ERR;
    }

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_OID);
    if (param == NULL) {
        signHashAlgOid = NULL;
    } else if (param->valueType == BSL_PARAM_TYPE_OCTETS_PTR) {
        signHashAlgOid = (const char *)param->value;
        signHashAlgOidLen = param->valueLen;
        param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_NAME);
        if (param == NULL || param->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
            goto ERR;
        }
        signHashAlgName = param->value;
    } else {
        goto ERR;
    }

    param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_MD_OID);
    if (param == NULL) {
        hashOid = NULL;
    } else if (param->valueType == BSL_PARAM_TYPE_OCTETS_PTR) {
        hashOid = (const char *)param->value;
        hashOidLen = param->valueLen;
        param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, CRYPT_PARAM_CAP_TLS_SIGNALG_MD_NAME);
        if (param == NULL || param->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
            goto ERR;
        }
        hashName = param->value;
    } else {
        goto ERR;
    }

    ret = HITLS_SUCCESS;
    if (scheme->keyType == TLS_CERT_KEY_TYPE_RSA_PSS) {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(LIBCTX_FROM_CONFIG(config), TLS_CERT_KEY_TYPE_RSA, CRYPT_EAL_PKEY_SIGN_OPERATE, ATTRIBUTE_FROM_CONFIG(config));
    } else {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(LIBCTX_FROM_CONFIG(config), scheme->keyType, CRYPT_EAL_PKEY_SIGN_OPERATE, ATTRIBUTE_FROM_CONFIG(config));
    }
    if (pkey != NULL) {
        if (keyTypeOid != NULL) {
            oidStr.octs = (char *)(uintptr_t)keyTypeOid;
            oidStr.octetLen = keyTypeOidLen;
            ret = BSL_OBJ_Create(&oidStr, keyTypeName, scheme->keyType);
            if (ret != HITLS_SUCCESS) {
                goto ERR;
            }
        }
        if (paraOid != NULL) {
            oidStr.octs = (char *)(uintptr_t)paraOid;
            oidStr.octetLen = paraOidLen;
            ret = BSL_OBJ_Create(&oidStr, paraName, scheme->paraId);
            if (ret != HITLS_SUCCESS) {
                goto ERR;
            }
        }
        if (hashOid != NULL) {
            oidStr.octs = (char *)(uintptr_t)hashOid;
            oidStr.octetLen = hashOidLen;
            ret = BSL_OBJ_Create(&oidStr, hashName, scheme->hashAlgId);
            if (ret != HITLS_SUCCESS) {
                goto ERR;
            }
        }
        if (signHashAlgOid != NULL) {
            oidStr.octs = (char *)(uintptr_t)signHashAlgOid;
            oidStr.octetLen = signHashAlgOidLen;
            ret = BSL_OBJ_Create(&oidStr, signHashAlgName, scheme->signHashAlgId);
            if (ret != HITLS_SUCCESS) {
                goto ERR;
            }
        }
        ret = BSL_OBJ_CreateSignId(scheme->signHashAlgId, scheme->signAlgId, scheme->hashAlgId);
        if (ret != HITLS_SUCCESS) {
            goto ERR;
        }
        config->sigSchemeInfolen++;
        scheme = NULL;
    } else {
        goto ERR;
    }
    if (pkey != NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        pkey = NULL;
    }
    if (scheme != NULL) {
        BSL_SAL_Free(scheme->name);
        (void)memset_s(scheme, sizeof(TLS_SigSchemeInfo), 0, sizeof(TLS_SigSchemeInfo));
    }
    return ret;

ERR:
    if (pkey != NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        pkey = NULL;
    }
    if (scheme != NULL) {
        BSL_SAL_Free(scheme->name);
        (void)memset_s(scheme, sizeof(TLS_SigSchemeInfo), 0, sizeof(TLS_SigSchemeInfo));
    }
    return ret;
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
    int32_t ret = CRYPT_EAL_ProviderProcAll(libCtx, ProviderLoadSignSchemeInfo, config);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return UpdateSignAlgorithmsArray(config, config->sigSchemeInfo, config->sigSchemeInfolen);
}

const TLS_SigSchemeInfo *ConfigGetSignatureSchemeInfo(const HITLS_Config *config, uint16_t signScheme)
{
    for (uint32_t i = 0; i < config->sigSchemeInfolen; i++) {
        if (config->sigSchemeInfo[i].signatureScheme == signScheme) {
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
