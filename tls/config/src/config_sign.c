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
#include "config_type.h"
#include "hitls_cert_type.h"
#include "tls_config.h"
#include "crypt_algid.h"
#include "hitls_error.h"
#include "cipher_suite.h"

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
        TLCP11_VERSION_BIT,
        TLCP11_VERSION_BIT,
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

#ifndef HITLS_TLS_FEATURE_PROVIDER
int32_t ConfigLoadSignatureSchemeInfo(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_INVALID_INPUT;
    }
    uint32_t size = 0;
    for (uint32_t i = 0; i < sizeof(SIGNATURE_SCHEME_INFO) / sizeof(TLS_SigSchemeInfo); i++) {
        if ((config->version & SIGNATURE_SCHEME_INFO[i].chainVersionBits) != 0) {
            size++;
        }
    }
    if (size == 0) {
        return HITLS_INVALID_INPUT;
    }
    BSL_SAL_FREE(config->signAlgorithms);
    config->signAlgorithms = BSL_SAL_Calloc(size, sizeof(uint16_t));
    if (config->signAlgorithms == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    uint32_t index = 0;
    for (uint32_t i = 0; i < sizeof(SIGNATURE_SCHEME_INFO) / sizeof(TLS_SigSchemeInfo); i++) {
        if ((config->version & SIGNATURE_SCHEME_INFO[i].chainVersionBits) != 0) {
            config->signAlgorithms[index] = SIGNATURE_SCHEME_INFO[i].signatureScheme;
            index++;
        }
    }
    config->signAlgorithmsSize = size;
    return HITLS_SUCCESS;
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

#endif
