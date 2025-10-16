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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "tls_config.h"
#include "cipher_suite.h"
#include "config_type.h"

#ifndef HITLS_TLS_CONFIG_CIPHER_SUITE
#define CIPHER_NAME(name) NULL
#else
#define CIPHER_NAME(name) name
#endif
#define KEY_BLOCK_PARTITON_LENGTH(fixedIvLth, encKeyLth, macKeyLth, blockLth, recordIvLth, macLth) \
    .fixedIvLength = (fixedIvLth),          \
    .encKeyLen = (encKeyLth),                \
    .macKeyLen = (macKeyLth),                \
    .blockLength = (blockLth),              \
    .recordIvLength = (recordIvLth),        \
    .macLen = (macLth)                      \

#define VERSION_SCOPE(minV, maxV, minDtlsV, maxDtlsV) \
    .minVersion = (minV), \
    .maxVersion = (maxV), \
    .minDtlsVersion = (minDtlsV),    \
    .maxDtlsVersion = (maxDtlsV)

#ifdef HITLS_TLS_CONFIG_CIPHER_SUITE
#define CIPHERSUITE_DESCRIPTION_MAXLEN 128
#endif

/* If cipher suites need to be added in the future, you need to consider whether the cipher suites are suitable for DTLS
in terms of design. If DTLS is not supported, perform related operations. For example, the RC4 stream encryption
algorithm is not applicable to DTLS. */
static const CipherSuiteInfo g_cipherSuiteList[] = {
#ifdef HITLS_TLS_SUITE_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_NULL,
        .authAlg = HITLS_AUTH_ANY,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(12u, 16u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0u, 0u),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_NULL,
        .authAlg = HITLS_AUTH_ANY,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(12u, 32u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0u, 0u),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_CHACHA20_POLY1305_SHA256"),
        .stdName = CIPHER_NAME("TLS_CHACHA20_POLY1305_SHA256"),
        .cipherSuite = HITLS_CHACHA20_POLY1305_SHA256,
        .cipherAlg = HITLS_CIPHER_CHACHA20_POLY1305,
        .kxAlg = HITLS_KEY_EXCH_NULL,
        .authAlg = HITLS_AUTH_ANY,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(12u, 32u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0u, 0u),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_AES_128_CCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_AES_128_CCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_AES_128_CCM_SHA256"),
        .cipherSuite = HITLS_AES_128_CCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CCM,
        .kxAlg = HITLS_KEY_EXCH_NULL,
        .authAlg = HITLS_AUTH_ANY,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(12u, 16u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0u, 0u),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_AES_128_CCM_8_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_AES_128_CCM_8_SHA256"),
        .stdName = CIPHER_NAME("TLS_AES_128_CCM_8_SHA256"),
        .cipherSuite = HITLS_AES_128_CCM_8_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CCM8,
        .kxAlg = HITLS_KEY_EXCH_NULL,
        .authAlg = HITLS_AUTH_ANY,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(12u, 16u, 0u, 0u, 0u, 8u),
        VERSION_SCOPE(HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0u, 0u),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_FEATURE_SM_TLS13
#ifdef HITLS_TLS_SUITE_SM4_GCM_SM3
    {.enable = true,
        .name = CIPHER_NAME("HITLS_SM4_GCM_SM3"),
        .stdName = CIPHER_NAME("HITLS_SM4_GCM_SM3"),
        .cipherSuite = HITLS_SM4_GCM_SM3,
        .cipherAlg = HITLS_CIPHER_SM4_GCM,
        .kxAlg = HITLS_KEY_EXCH_NULL,
        .authAlg = HITLS_AUTH_ANY,
        .macAlg = HITLS_MAC_SM3,
        .hashAlg = HITLS_HASH_SM3,
        .signScheme = CERT_SIG_SCHEME_SM2_SM3,
        KEY_BLOCK_PARTITON_LENGTH(12u, 16u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0, 0),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_SM4_CCM_SM3
    {.enable = true,
        .name = CIPHER_NAME("HITLS_SM4_CCM_SM3"),
        .stdName = CIPHER_NAME("TLS_SM4_CCM_SM3"),
        .cipherSuite = HITLS_SM4_CCM_SM3,
        .cipherAlg = HITLS_CIPHER_SM4_CCM,
        .kxAlg = HITLS_KEY_EXCH_NULL,
        .authAlg = HITLS_AUTH_ANY,
        .macAlg = HITLS_MAC_SM3,
        .hashAlg = HITLS_HASH_SM3,
        .signScheme = CERT_SIG_SCHEME_SM2_SM3,
        KEY_BLOCK_PARTITON_LENGTH(12u, 16u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0, 0),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_RSA_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_RSA_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_RSA,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_RSA_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_RSA_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_RSA,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_WITH_AES_128_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_RSA_WITH_AES_128_CBC_SHA256"),
        .cipherSuite = HITLS_RSA_WITH_AES_128_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_RSA,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_WITH_AES_256_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_RSA_WITH_AES_256_CBC_SHA256"),
        .cipherSuite = HITLS_RSA_WITH_AES_256_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_RSA,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_WITH_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_RSA_WITH_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_RSA_WITH_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_RSA,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_WITH_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_RSA_WITH_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_RSA_WITH_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_RSA,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_ECDSA,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_ECDSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_ECDSA,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_ECDSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
        .cipherSuite = HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_ECDSA,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_ECDSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
        .stdName = CIPHER_NAME("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
        .cipherSuite = HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_ECDSA,
        .macAlg = HITLS_MAC_384,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_ECDSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 48u, 16u, 16u, 48u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_ECDSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_ECDSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_ECDSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_ECDSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
        .cipherSuite = HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
        .stdName = CIPHER_NAME("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
        .cipherSuite = HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_384,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 48u, 16u, 16u, 48u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        .stdName = CIPHER_NAME("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        .cipherSuite = HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .cipherAlg = HITLS_CIPHER_CHACHA20_POLY1305,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(12u, 32u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
        .stdName = CIPHER_NAME("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
        .cipherSuite = HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        .cipherAlg = HITLS_CIPHER_CHACHA20_POLY1305,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_ECDSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_ECDSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(12u, 32u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        .stdName = CIPHER_NAME("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        .cipherSuite = HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .cipherAlg = HITLS_CIPHER_CHACHA20_POLY1305,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(12u, 32u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_DSS,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_DSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_DSS,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_DSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_DSS_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_DHE_DSS_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_DSS,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_DSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_DSS,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_DSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_DSS_WITH_AES_128_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"),
        .cipherSuite = HITLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_DSS,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_DSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_DSS_WITH_AES_256_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"),
        .cipherSuite = HITLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_DSS,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_DSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
        .cipherSuite = HITLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
        .cipherSuite = HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
// psk nego
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_PSK_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_PSK_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_PSK_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_PSK_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_PSK_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_PSK_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_PSK_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_DHE_PSK_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_DHE_PSK_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_PSK_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_DHE_PSK_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_DHE_PSK_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_PSK_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_RSA_PSK_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_RSA_PSK_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_RSA_PSK,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_PSK_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_RSA_PSK_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_RSA_PSK_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_RSA_PSK,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_PSK_WITH_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_PSK_WITH_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_PSK_WITH_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_PSK_WITH_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_PSK_WITH_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_PSK_WITH_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_256_CCM
    {.enable = true,
        .name = CIPHER_NAME("HITLS_PSK_WITH_AES_256_CCM"),
        .stdName = CIPHER_NAME("TLS_PSK_WITH_AES_256_CCM"),
        .cipherSuite = HITLS_PSK_WITH_AES_256_CCM,
        .cipherAlg = HITLS_CIPHER_AES_256_CCM,
        .kxAlg = HITLS_KEY_EXCH_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_PSK_WITH_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_DHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_PSK_WITH_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_DHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CCM
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_PSK_WITH_AES_128_CCM"),
        .stdName = CIPHER_NAME("TLS_DHE_PSK_WITH_AES_128_CCM"),
        .cipherSuite = HITLS_DHE_PSK_WITH_AES_128_CCM,
        .cipherAlg = HITLS_CIPHER_AES_128_CCM,
        .kxAlg = HITLS_KEY_EXCH_DHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CCM
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_PSK_WITH_AES_256_CCM"),
        .stdName = CIPHER_NAME("TLS_DHE_PSK_WITH_AES_256_CCM"),
        .cipherSuite = HITLS_DHE_PSK_WITH_AES_256_CCM,
        .cipherAlg = HITLS_CIPHER_AES_256_CCM,
        .kxAlg = HITLS_KEY_EXCH_DHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_PSK_WITH_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_RSA_PSK,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_PSK_WITH_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_RSA_PSK,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_PSK_WITH_AES_128_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_PSK_WITH_AES_128_CBC_SHA256"),
        .cipherSuite = HITLS_PSK_WITH_AES_128_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_PSK_WITH_AES_256_CBC_SHA384"),
        .stdName = CIPHER_NAME("TLS_PSK_WITH_AES_256_CBC_SHA384"),
        .cipherSuite = HITLS_PSK_WITH_AES_256_CBC_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_384,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 48u, 16u, 16u, 48u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_PSK_WITH_AES_128_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"),
        .cipherSuite = HITLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_PSK_WITH_AES_256_CBC_SHA384"),
        .stdName = CIPHER_NAME("TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"),
        .cipherSuite = HITLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_384,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 48u, 16u, 16u, 48u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_PSK_WITH_AES_128_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"),
        .cipherSuite = HITLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_RSA_PSK,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_PSK_WITH_AES_256_CBC_SHA384"),
        .stdName = CIPHER_NAME("TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"),
        .cipherSuite = HITLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_RSA_PSK,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_384,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 48u, 16u, 16u, 48u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"),
        .cipherSuite = HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"),
        .stdName = CIPHER_NAME("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"),
        .cipherSuite = HITLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_384,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 48u, 16u, 16u, 48u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_CHACHA20_POLY1305_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        .stdName = CIPHER_NAME("TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        .cipherSuite = HITLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
        .cipherAlg = HITLS_CIPHER_CHACHA20_POLY1305,
        .kxAlg = HITLS_KEY_EXCH_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(12u, 32u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        .stdName = CIPHER_NAME("TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        .cipherSuite = HITLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        .cipherAlg = HITLS_CIPHER_CHACHA20_POLY1305,
        .kxAlg = HITLS_KEY_EXCH_ECDHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(12u, 32u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        .stdName = CIPHER_NAME("TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        .cipherSuite = HITLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        .cipherAlg = HITLS_CIPHER_CHACHA20_POLY1305,
        .kxAlg = HITLS_KEY_EXCH_DHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(12u, 32u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        .stdName = CIPHER_NAME("TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        .cipherSuite = HITLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
        .cipherAlg = HITLS_CIPHER_CHACHA20_POLY1305,
        .kxAlg = HITLS_KEY_EXCH_RSA_PSK,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(12u, 32u, 0u, 0u, 0u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"),
        .cipherSuite = HITLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CCM,
        .kxAlg = HITLS_KEY_EXCH_ECDHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_ECDHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_ECDHE_PSK,
        .authAlg = HITLS_AUTH_PSK,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
/* Anonymous cipher suites support */
#ifdef HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DH_ANON_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_DH_anon_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_DH_ANON_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_NULL,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DH_ANON_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_DH_anon_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_DH_ANON_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_NULL,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_SSL30, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DH_ANON_WITH_AES_128_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_DH_anon_WITH_AES_128_CBC_SHA256"),
        .cipherSuite = HITLS_DH_ANON_WITH_AES_128_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_NULL,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DH_ANON_WITH_AES_256_CBC_SHA256"),
        .stdName = CIPHER_NAME("TLS_DH_anon_WITH_AES_256_CBC_SHA256"),
        .cipherSuite = HITLS_DH_ANON_WITH_AES_256_CBC_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_NULL,
        .macAlg = HITLS_MAC_256,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_GCM_SHA256
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DH_ANON_WITH_AES_128_GCM_SHA256"),
        .stdName = CIPHER_NAME("TLS_DH_anon_WITH_AES_128_GCM_SHA256"),
        .cipherSuite = HITLS_DH_ANON_WITH_AES_128_GCM_SHA256,
        .cipherAlg = HITLS_CIPHER_AES_128_GCM,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_NULL,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_GCM_SHA384
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DH_ANON_WITH_AES_256_GCM_SHA384"),
        .stdName = CIPHER_NAME("TLS_DH_anon_WITH_AES_256_GCM_SHA384"),
        .cipherSuite = HITLS_DH_ANON_WITH_AES_256_GCM_SHA384,
        .cipherAlg = HITLS_CIPHER_AES_256_GCM,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_NULL,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_384,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_128_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDH_ANON_WITH_AES_128_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_ECDH_anon_WITH_AES_128_CBC_SHA"),
        .cipherSuite = HITLS_ECDH_ANON_WITH_AES_128_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_128_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_NULL,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_256_CBC_SHA
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDH_ANON_WITH_AES_256_CBC_SHA"),
        .stdName = CIPHER_NAME("TLS_ECDH_anon_WITH_AES_256_CBC_SHA"),
        .cipherSuite = HITLS_ECDH_ANON_WITH_AES_256_CBC_SHA,
        .cipherAlg = HITLS_CIPHER_AES_256_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_NULL,
        .macAlg = HITLS_MAC_1,
        .hashAlg = HITLS_HASH_SHA1,
        .signScheme = CERT_SIG_SCHEME_UNKNOWN,
        KEY_BLOCK_PARTITON_LENGTH(16u, 32u, 20u, 16u, 16u, 20u),
        VERSION_SCOPE(HITLS_VERSION_TLS10, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_ECDSA_WITH_AES_128_CCM"),
        .stdName = CIPHER_NAME("TLS_ECDHE_ECDSA_WITH_AES_128_CCM"),
        .cipherSuite = HITLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        .cipherAlg = HITLS_CIPHER_AES_128_CCM,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_ECDSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_ECDSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_ECDSA_WITH_AES_256_CCM"),
        .stdName = CIPHER_NAME("TLS_ECDHE_ECDSA_WITH_AES_256_CCM"),
        .cipherSuite = HITLS_ECDHE_ECDSA_WITH_AES_256_CCM,
        .cipherAlg = HITLS_CIPHER_AES_256_CCM,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_ECDSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_ECDSA_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CCM
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_RSA_WITH_AES_128_CCM"),
        .stdName = CIPHER_NAME("TLS_DHE_RSA_WITH_AES_128_CCM"),
        .cipherSuite = HITLS_DHE_RSA_WITH_AES_128_CCM,
        .cipherAlg = HITLS_CIPHER_AES_128_CCM,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CCM
    {.enable = true,
        .name = CIPHER_NAME("HITLS_DHE_RSA_WITH_AES_256_CCM"),
        .stdName = CIPHER_NAME("TLS_DHE_RSA_WITH_AES_256_CCM"),
        .cipherSuite = HITLS_DHE_RSA_WITH_AES_256_CCM,
        .cipherAlg = HITLS_CIPHER_AES_256_CCM,
        .kxAlg = HITLS_KEY_EXCH_DHE,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_WITH_AES_128_CCM"),
        .stdName = CIPHER_NAME("TLS_RSA_WITH_AES_128_CCM"),
        .cipherSuite = HITLS_RSA_WITH_AES_128_CCM,
        .cipherAlg = HITLS_CIPHER_AES_128_CCM,
        .kxAlg = HITLS_KEY_EXCH_RSA,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM_8
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_WITH_AES_128_CCM_8"),
        .stdName = CIPHER_NAME("TLS_RSA_WITH_AES_128_CCM_8"),
        .cipherSuite = HITLS_RSA_WITH_AES_128_CCM_8,
        .cipherAlg = HITLS_CIPHER_AES_128_CCM8,
        .kxAlg = HITLS_KEY_EXCH_RSA,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 8u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_WITH_AES_256_CCM"),
        .stdName = CIPHER_NAME("TLS_RSA_WITH_AES_256_CCM"),
        .cipherSuite = HITLS_RSA_WITH_AES_256_CCM,
        .cipherAlg = HITLS_CIPHER_AES_256_CCM,
        .kxAlg = HITLS_KEY_EXCH_RSA,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM_8
    {.enable = true,
        .name = CIPHER_NAME("HITLS_RSA_WITH_AES_256_CCM_8"),
        .stdName = CIPHER_NAME("TLS_RSA_WITH_AES_256_CCM_8"),
        .cipherSuite = HITLS_RSA_WITH_AES_256_CCM_8,
        .cipherAlg = HITLS_CIPHER_AES_256_CCM8,
        .kxAlg = HITLS_KEY_EXCH_RSA,
        .authAlg = HITLS_AUTH_RSA,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SHA_256,
        .signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        KEY_BLOCK_PARTITON_LENGTH(4u, 32u, 0u, 0u, 8u, 8u),
        VERSION_SCOPE(HITLS_VERSION_TLS12, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 256},
#endif
#ifdef HITLS_TLS_PROTO_TLCP11
#ifdef HITLS_TLS_SUITE_ECDHE_SM4_CBC_SM3
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_SM4_CBC_SM3"),
        .stdName = CIPHER_NAME("TLS_ECDHE_SM4_CBC_SM3"),
        .cipherSuite = HITLS_ECDHE_SM4_CBC_SM3,
        .cipherAlg = HITLS_CIPHER_SM4_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_SM2,
        .macAlg = HITLS_MAC_SM3,
        .hashAlg = HITLS_HASH_SM3,
        .signScheme = CERT_SIG_SCHEME_SM2_SM3,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLCP_DTLCP11, HITLS_VERSION_TLCP_DTLCP11, 0, 0),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECC_SM4_CBC_SM3
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECC_SM4_CBC_SM3"),
        .stdName = CIPHER_NAME("TLS_ECC_SM4_CBC_SM3"),
        .cipherSuite = HITLS_ECC_SM4_CBC_SM3,
        .cipherAlg = HITLS_CIPHER_SM4_CBC,
        .kxAlg = HITLS_KEY_EXCH_ECC,
        .authAlg = HITLS_AUTH_SM2,
        .macAlg = HITLS_MAC_SM3,
        .hashAlg = HITLS_HASH_SM3,
        .signScheme = CERT_SIG_SCHEME_SM2_SM3,
        KEY_BLOCK_PARTITON_LENGTH(16u, 16u, 32u, 16u, 16u, 32u),
        VERSION_SCOPE(HITLS_VERSION_TLCP_DTLCP11, HITLS_VERSION_TLCP_DTLCP11, 0, 0),
        .cipherType = HITLS_CBC_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_SM4_GCM_SM3
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECDHE_SM4_GCM_SM3"),
        .stdName = CIPHER_NAME("TLS_ECDHE_SM4_GCM_SM3"),
        .cipherSuite = HITLS_ECDHE_SM4_GCM_SM3,
        .cipherAlg = HITLS_CIPHER_SM4_GCM,
        .kxAlg = HITLS_KEY_EXCH_ECDHE,
        .authAlg = HITLS_AUTH_SM2,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SM3,
        .signScheme = CERT_SIG_SCHEME_SM2_SM3,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLCP_DTLCP11, HITLS_VERSION_TLCP_DTLCP11, 0, 0),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#ifdef HITLS_TLS_SUITE_ECC_SM4_GCM_SM3
    {.enable = true,
        .name = CIPHER_NAME("HITLS_ECC_SM4_GCM_SM3"),
        .stdName = CIPHER_NAME("TLS_ECC_SM4_GCM_SM3"),
        .cipherSuite = HITLS_ECC_SM4_GCM_SM3,
        .cipherAlg = HITLS_CIPHER_SM4_GCM,
        .kxAlg = HITLS_KEY_EXCH_ECC,
        .authAlg = HITLS_AUTH_SM2,
        .macAlg = HITLS_MAC_AEAD,
        .hashAlg = HITLS_HASH_SM3,
        .signScheme = CERT_SIG_SCHEME_SM2_SM3,
        KEY_BLOCK_PARTITON_LENGTH(4u, 16u, 0u, 0u, 8u, 16u),
        VERSION_SCOPE(HITLS_VERSION_TLCP_DTLCP11, HITLS_VERSION_TLCP_DTLCP11, 0, 0),
        .cipherType = HITLS_AEAD_CIPHER,
        .strengthBits = 128},
#endif
#endif
};

const CipherSuiteCertType g_cipherSuiteAndCertTypes[] = {
    { HITLS_RSA_WITH_AES_128_CBC_SHA, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_WITH_AES_256_CBC_SHA, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_WITH_AES_128_CBC_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_WITH_AES_256_CBC_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_WITH_AES_128_GCM_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_WITH_AES_256_GCM_SHA384, CERT_TYPE_RSA_SIGN },
    { HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, CERT_TYPE_RSA_SIGN },
    { HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, CERT_TYPE_RSA_SIGN },
    { HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, CERT_TYPE_RSA_SIGN },
    { HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, CERT_TYPE_RSA_SIGN },
    { HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_DHE_RSA_WITH_AES_128_CBC_SHA, CERT_TYPE_RSA_SIGN },
    { HITLS_DHE_RSA_WITH_AES_256_CBC_SHA, CERT_TYPE_RSA_SIGN },
    { HITLS_DHE_RSA_WITH_AES_128_CBC_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384, CERT_TYPE_RSA_SIGN },
    { HITLS_DHE_RSA_WITH_AES_128_CCM, CERT_TYPE_RSA_SIGN },
    { HITLS_DHE_RSA_WITH_AES_256_CCM, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_WITH_AES_128_CCM, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_WITH_AES_128_CCM_8, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_WITH_AES_256_CCM, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_WITH_AES_256_CCM_8, CERT_TYPE_RSA_SIGN },
    { HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_PSK_WITH_AES_128_CBC_SHA, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_PSK_WITH_AES_256_CBC_SHA, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_PSK_WITH_AES_128_GCM_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_PSK_WITH_AES_256_GCM_SHA384, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_PSK_WITH_AES_128_CBC_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_PSK_WITH_AES_256_CBC_SHA384, CERT_TYPE_RSA_SIGN },
    { HITLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256, CERT_TYPE_RSA_SIGN },
    { HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECDHE_ECDSA_WITH_AES_128_CCM, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECDHE_ECDSA_WITH_AES_256_CCM, CERT_TYPE_ECDSA_SIGN },
    { HITLS_DHE_DSS_WITH_AES_128_CBC_SHA, CERT_TYPE_DSS_SIGN },
    { HITLS_DHE_DSS_WITH_AES_256_CBC_SHA, CERT_TYPE_DSS_SIGN },
    { HITLS_DHE_DSS_WITH_AES_128_CBC_SHA256, CERT_TYPE_DSS_SIGN },
    { HITLS_DHE_DSS_WITH_AES_256_CBC_SHA256, CERT_TYPE_DSS_SIGN },
    { HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256, CERT_TYPE_DSS_SIGN },
    { HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384, CERT_TYPE_DSS_SIGN },
    { HITLS_ECDHE_SM4_CBC_SM3, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECC_SM4_CBC_SM3, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECDHE_SM4_GCM_SM3, CERT_TYPE_ECDSA_SIGN },
    { HITLS_ECC_SM4_GCM_SM3, CERT_TYPE_ECDSA_SIGN },
    { HITLS_SM4_GCM_SM3, CERT_TYPE_ECDSA_SIGN },
    { HITLS_SM4_CCM_SM3, CERT_TYPE_ECDSA_SIGN },
};

/**
 * @brief   Obtain the cipher suite information
 *
 * @param   cipherSuite [IN] Cipher suite of the information to be obtained
 * @param   cipherInfo  [OUT] Cipher suite information
 *
 * @retval  HITLS_SUCCESS obtained successfully
 * @retval  HITLS_INTERNAL_EXCEPTION Unexpected internal error
 * @retval  HITLS_MEMCPY_FAIL memcpy_s failed to be executed.
 * @retval  HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE No information about the cipher suite is found.
 */
int32_t CFG_GetCipherSuiteInfo(uint16_t cipherSuite, CipherSuiteInfo *cipherInfo)
{
    if (cipherInfo == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15858, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CFG:cipherInfo is NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }
    /* Obtain the cipher suite information. If the cipher suite information is successfully obtained, a response is
     * returned. */
    for (uint32_t i = 0; i < (sizeof(g_cipherSuiteList) / sizeof(g_cipherSuiteList[0])); i++) {
        if (g_cipherSuiteList[i].cipherSuite == cipherSuite) {
            if (g_cipherSuiteList[i].enable == false) {
                break;
            }
            int32_t ret = memcpy_s(cipherInfo, sizeof(CipherSuiteInfo), &g_cipherSuiteList[i], sizeof(CipherSuiteInfo));
            if (ret != EOK) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15859, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "CFG:memcpy failed.", 0, 0, 0, 0);
                BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
                return HITLS_MEMCPY_FAIL;
            }
            return HITLS_SUCCESS;
        }
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15860, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "CFG: [0x%x]cipher suite is not supported.", cipherSuite, 0, 0, 0);
    BSL_ERR_PUSH_ERROR(HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE);
    return HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE;
}

/**
 * @brief   Check whether the input cipher suite is supported.
 *
 * @param   cipherSuite [IN] Cipher suite to be checked
 *
 * @retval  true support
 * @retval  false Not supported
 */
bool CFG_CheckCipherSuiteSupported(uint16_t cipherSuite)
{   /** @alias Check the suite and return true if supported. */
    for (uint32_t i = 0; i < (sizeof(g_cipherSuiteList) / sizeof(g_cipherSuiteList[0])); i++) {
        if (cipherSuite == g_cipherSuiteList[i].cipherSuite) {
            return g_cipherSuiteList[i].enable;
        }
    }

    return false;
}

/** Check whether the version is within the allowed range */
static bool CheckTlsVersionInRange(uint16_t cipherMinVersion, uint16_t cipherMaxVersion,
    uint16_t cfgMinVersion, uint16_t cfgMaxVersion)
{
    if ((cipherMaxVersion < cfgMinVersion) || (cipherMinVersion > cfgMaxVersion)) {
        return false;
    }
    return true;
}

/** Check whether the version of the TLCP is within the allowed range */
static bool CheckTLCPVersionInRange(uint16_t version, uint16_t minVersion, uint16_t maxVersion)
{
    return (version >= minVersion) && (version <= maxVersion);
}

/** Check whether the version is within the allowed range. (DTLS version numbers are sorted in reverse order. For
 * example, DTLS 1.2 is greater than DTLS 1.3 */
static bool CheckDtlsVersionInRange(uint16_t cipherMinVersion, uint16_t cipherMaxVersion,
    uint16_t cfgMinVersion, uint16_t cfgMaxVersion)
{
    if ((cipherMaxVersion > cfgMinVersion) || (cipherMinVersion < cfgMaxVersion)) {
        return false;
    }
    return true;
}

/**
 * @brief   Check whether the input cipher suite complies with the version
 *
 * @param   cipherSuite [IN] Cipher suite to be checked
 *          minVersion  [IN] Indicates the earliest version of the cipher suite
 *          maxVersion  [IN] Indicates the latest version of the cipher suite
 *
 * @retval  true support
 * @retval  false Not supported
 */
bool CFG_CheckCipherSuiteVersion(uint16_t cipherSuite, uint16_t minVersion, uint16_t maxVersion)
{
    const CipherSuiteInfo *suiteInfo = NULL;

    /** @alias Check the suite and return true if supported. */
    for (uint32_t i = 0; i < (sizeof(g_cipherSuiteList) / sizeof(g_cipherSuiteList[0])); i++) {
        suiteInfo = &g_cipherSuiteList[i];
        if (cipherSuite == suiteInfo->cipherSuite) { /** tlcp max version equal min version  */
            return CheckTlsVersionInRange(suiteInfo->minVersion, suiteInfo->maxVersion, minVersion, maxVersion) ||
                CheckDtlsVersionInRange(suiteInfo->minDtlsVersion, suiteInfo->maxDtlsVersion, minVersion, maxVersion) ||
                CheckTLCPVersionInRange(minVersion, suiteInfo->minVersion, suiteInfo->maxVersion) ||
                CheckTLCPVersionInRange(maxVersion, suiteInfo->minVersion, suiteInfo->maxVersion);
        }
    }

    return false;
}

/**
 * @brief   Obtain the signature algorithm and hash algorithm by combining the parameters of the signature hash
 * algorithm.
 *
 * @param   ctx [IN] HITLS context
 * @param   scheme [IN] Signature and hash algorithm combination
 * @param   signAlg [OUT] Signature algorithm
 * @param   hashAlg [OUT] Hash algorithm
 *
 * @retval  true Obtained successfully.
 * @retval  false Obtaining failed.
 */
bool CFG_GetSignParamBySchemes(const HITLS_Ctx *ctx, HITLS_SignHashAlgo scheme, HITLS_SignAlgo *signAlg,
    HITLS_HashAlgo *hashAlg)
{
    if (ctx == NULL || signAlg == NULL || hashAlg == NULL) {
        return false;
    }

    const TLS_SigSchemeInfo *info = ConfigGetSignatureSchemeInfo(&ctx->config.tlsConfig, scheme);
    if (info == NULL) {
        return false;
    }
    *signAlg = info->signAlgId;
    *hashAlg = info->hashAlgId;
    return true;
}

/**
 * @brief   get the group name of the signature algorithm
 * @param   ctx [IN] HITLS context
 * @param   scheme [IN] signature algorithm
 *
 * @retval  group name
 */
HITLS_NamedGroup CFG_GetEcdsaCurveNameBySchemes(const HITLS_Ctx *ctx, HITLS_SignHashAlgo scheme)
{
    const TLS_SigSchemeInfo *info = ConfigGetSignatureSchemeInfo(&ctx->config.tlsConfig, scheme);
    if (info == NULL) {
        return HITLS_NAMED_GROUP_BUTT;
    }
    uint32_t groupInfoNum = 0;
    const TLS_GroupInfo *groupInfo = ConfigGetGroupInfoList(&ctx->config.tlsConfig, &groupInfoNum);
    if (groupInfo == NULL || groupInfoNum == 0) {
        return HITLS_NAMED_GROUP_BUTT;
    }
    for (uint32_t i = 0; i < groupInfoNum; i++) {
        if (groupInfo[i].paraId == info->paraId) {
            return groupInfo[i].groupId;
        }
    }
    return HITLS_NAMED_GROUP_BUTT;
}

/**
 * @brief   Obtain the certificate type based on the cipher suite
 *
 * @param   cipherSuite [IN] Cipher suite
 *
 * @return  Certificate type corresponding to the cipher suite
 */
uint8_t CFG_GetCertTypeByCipherSuite(uint16_t cipherSuite)
{
    for (uint32_t i = 0; i < (sizeof(g_cipherSuiteAndCertTypes) / sizeof(g_cipherSuiteAndCertTypes[0])); i++) {
        if (cipherSuite == g_cipherSuiteAndCertTypes[i].cipherSuite) {
            return g_cipherSuiteAndCertTypes[i].certType;
        }
    }

    return CERT_TYPE_UNKNOWN;
}
#ifdef HITLS_TLS_CONFIG_CIPHER_SUITE
/* Convert the supported version number to the corresponding character string */
static const uint8_t* ProtocolToString(uint16_t version)
{
    const char *ret = NULL;
    switch (version) {
        case HITLS_VERSION_TLS12:
            ret = "TLSv1.2";
            break;
        case HITLS_VERSION_TLS13:
            ret = "TLSv1.3";
            break;
        case HITLS_VERSION_DTLS10:
            ret = "DTLSv1";
            break;
        case HITLS_VERSION_DTLS12:
            ret = "DTLSv1.2";
            break;
        case HITLS_VERSION_TLCP_DTLCP11:
            ret = "(D)TLCP1.1";
            break;
        default:
            ret = "unknown";
            break;
    }
    return (const uint8_t *)ret;
}

/* Convert the server authorization algorithm type to the corresponding character string */
static const uint8_t* AuthAlgToString(HITLS_AuthAlgo authAlg)
{
    const char *ret = NULL;
    switch (authAlg) {
        case HITLS_AUTH_RSA:
            ret = "RSA";
            break;
        case HITLS_AUTH_ECDSA:
            ret = "ECDSA";
            break;
        case HITLS_AUTH_DSS:
            ret = "DSS";
            break;
        case HITLS_AUTH_SM2:
            ret = "SM2";
            break;
        default:
            ret = "unknown";
            break;
    }
    return (const uint8_t *)ret;
}

/* Convert the key exchange algorithm type to the corresponding character string */
static const uint8_t* KeyExchAlgToString(HITLS_KeyExchAlgo kxAlg)
{
    const char *ret = NULL;
    switch (kxAlg) {
        case HITLS_KEY_EXCH_ECDHE:
            ret = "ECDHE";
            break;
        case HITLS_KEY_EXCH_DHE:
            ret = "DHE";
            break;
        case HITLS_KEY_EXCH_ECDH:
            ret = "ECDH";
            break;
        case HITLS_KEY_EXCH_DH:
            ret = "DH";
            break;
        case HITLS_KEY_EXCH_RSA:
            ret = "RSA";
            break;
        case HITLS_KEY_EXCH_PSK:
            ret = "PSK";
            break;
        case HITLS_KEY_EXCH_ECC:
            ret = "ECC";
            break;
        default:
            ret = "unknown";
            break;
    }
    return (const uint8_t *)ret;
}

/* Convert the MAC algorithm type to the corresponding character string */
static const uint8_t* MacAlgToString(HITLS_MacAlgo macAlg)
{
    const char *ret = NULL;
    switch (macAlg) {
        case HITLS_MAC_1:
            ret = "SHA1";
            break;
        case HITLS_MAC_256:
            ret = "SHA256";
            break;
        case HITLS_MAC_384:
            ret = "SHA384";
            break;
        case HITLS_MAC_512:
            ret = "SHA512";
            break;
        case HITLS_MAC_AEAD:
            ret = "AEAD";
            break;
        case HITLS_MAC_SM3:
            ret = "SM3";
            break;
        default:
            ret = "unknown";
            break;
    }
    return (const uint8_t *)ret;
}

/* Convert the hash algorithm type to the corresponding character string */
static const uint8_t* HashAlgToString(HITLS_HashAlgo hashAlg)
{
    const char *ret = NULL;
    switch (hashAlg) {
        case HITLS_HASH_MD5:
            ret = "MD5";
            break;
        case HITLS_HASH_SHA1:
            ret = "SHA1";
            break;
        case HITLS_HASH_SHA_256:
            ret = "SHA256";
            break;
        case HITLS_HASH_SHA_384:
            ret = "SHA384";
            break;
        case HITLS_HASH_SHA_512:
            ret = "SHA512";
            break;
        case HITLS_HASH_SM3:
            ret = "SM3";
            break;
        default:
            ret = "unknown";
            break;
    }
    return (const uint8_t *)ret;
}

/* Search the corresponding index in the table based on the cipher suite. If the cipher suite is invalid,
 * CIPHER_SUITE_NOT_EXIST is returned */
static int32_t FindCipherSuiteIndexByCipherSuite(const uint16_t cipherSuite)
{
    uint32_t i;
    for (i = 0; i < sizeof(g_cipherSuiteList) / sizeof(CipherSuiteInfo); i++) {
        if (g_cipherSuiteList[i].cipherSuite == cipherSuite) {
            return (int32_t)i;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE);
    return HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE;
}


static int32_t GetCipherSuiteDescription(const CipherSuiteInfo *cipherSuiteInfo, uint8_t *buf, int len)
{
    if (cipherSuiteInfo == NULL || buf == NULL || len < CIPHERSUITE_DESCRIPTION_MAXLEN) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    const uint8_t *ver, *kx, *au, *hash, *mac;
    static const char *format = "%-30s %-7s Kx=%-8s Au=%-5s Hash=%-22s Mac=%-4s\n";

    ver = ProtocolToString(cipherSuiteInfo->minVersion);
    kx = KeyExchAlgToString(cipherSuiteInfo->kxAlg);
    au = AuthAlgToString(cipherSuiteInfo->authAlg);
    mac = MacAlgToString(cipherSuiteInfo->macAlg);
    hash = HashAlgToString(cipherSuiteInfo->hashAlg);

    int32_t ret = snprintf_s((char *)buf, CIPHERSUITE_DESCRIPTION_MAXLEN, CIPHERSUITE_DESCRIPTION_MAXLEN,
        format, cipherSuiteInfo->name, ver, kx, au, hash, mac);
    if (ret < 0 || ret > CIPHERSUITE_DESCRIPTION_MAXLEN - 1) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    return HITLS_SUCCESS;
}

/**
 * @brief   Obtain the Symmetric-key algorithm type based on the cipher suite
 *
 * @param   cipher[IN] Cipher suite
 * @param   cipherAlg [OUT] Obtained Symmetric-key algorithm type.
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetCipherId(const HITLS_Cipher *cipher, HITLS_CipherAlgo *cipherAlg)
{
    if (cipher == NULL || cipherAlg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *cipherAlg = cipher->cipherAlg;
    return HITLS_SUCCESS;
}

/**
 * @brief   Obtain the hash algorithm type based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @param   hashAlg [OUT] Obtained hash algorithm type
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For other error codes, see hitls_error.h
 */
int32_t HITLS_CFG_GetHashId(const HITLS_Cipher *cipher, HITLS_HashAlgo *hashAlg)
{
    if (cipher == NULL || hashAlg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *hashAlg = cipher->hashAlg;
    return HITLS_SUCCESS;
}

/**
 * @brief   Obtain the MAC algorithm type based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @param   macAlg [OUT] Obtained MAC algorithm type.
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For other error codes, see hitls_error.h
 */
int32_t HITLS_CFG_GetMacId(const HITLS_Cipher *cipher, HITLS_MacAlgo *macAlg)
{
    if (cipher == NULL || macAlg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *macAlg = cipher->macAlg;
    return HITLS_SUCCESS;
}

/**
 * @brief   Obtain the server authorization algorithm type based on the cipher suite
 *
 * @param   cipher [IN] Cipher suite
 * @param   authAlg [OUT] Obtained server authorization type.
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetAuthId(const HITLS_Cipher *cipher, HITLS_AuthAlgo *authAlg)
{
    if (cipher == NULL || authAlg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    *authAlg = cipher->authAlg;
    return HITLS_SUCCESS;
}

/**
 * @brief   Obtain the key exchange algorithm type based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @param   kxAlg [OUT] Obtained key exchange algorithm type.
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetKeyExchId(const HITLS_Cipher *cipher, HITLS_KeyExchAlgo *kxAlg)
{
    if (cipher == NULL || kxAlg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    *kxAlg = cipher->kxAlg;
    return HITLS_SUCCESS;
}

/**
 * @brief   Obtain the cipher suite name based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @retval  "(NONE)" Invalid cipher suite.
 * @retval  Name of the given cipher suite
 */
const uint8_t* HITLS_CFG_GetCipherSuiteName(const HITLS_Cipher *cipher)
{
    if (cipher == NULL) {
        return (const uint8_t *)"(NONE)";
    }
    return (const uint8_t *)cipher->name;
}

/**
 * @brief   Obtain the RFC standard name of the cipher suite based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 *
 * @retval  "(NONE)" Invalid cipher suite.
 * @retval  RFC standard name for the given cipher suite
 */
const uint8_t* HITLS_CFG_GetCipherSuiteStdName(const HITLS_Cipher *cipher)
{
    if (cipher == NULL) {
        return (const uint8_t *)"(NONE)";
    }
    return (const uint8_t *)cipher->stdName;
}

static int32_t FindCipherSuiteIndexByStdName(const uint8_t* stdName)
{
    for (uint32_t i = 0; i < sizeof(g_cipherSuiteList) / sizeof(CipherSuiteInfo); i++) {
        if (strncmp(g_cipherSuiteList[i].stdName, (const char *)stdName, strlen(g_cipherSuiteList[i].stdName) + 1) ==
            0) {
            return (int32_t)i;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE);
    return HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE;
}

const HITLS_Cipher* HITLS_CFG_GetCipherSuiteByStdName(const uint8_t* stdName)
{
    if (stdName == NULL) {
        return NULL;
    }
    int32_t index = FindCipherSuiteIndexByStdName(stdName);
    if (index == HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16549, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "No proper cipher suite", 0, 0, 0, 0);
        return NULL;
    }
    return &g_cipherSuiteList[index];
}

/**
 * @brief   Obtain the earliest TLS version supported by the cipher suite based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @param   version [OUT] Obtain the earliest TLS version supported by the cipher suite.
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetCipherVersion(const HITLS_Cipher *cipher, int32_t *version)
{
    if (cipher == NULL || version == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *version = cipher->minVersion;
    return HITLS_SUCCESS;
}

/**
 * @brief   Output the description of the cipher suite as a character string.
 *
 * @param   cipherSuite [IN] Cipher suite
 * @param   buf [OUT] Output the description.
 * @param   len [IN] Description length
 * @retval  NULL Failed to obtain the description.
 * @retval  Description of the cipher suite
 */
int32_t HITLS_CFG_GetDescription(const HITLS_Cipher *cipher, uint8_t *buf, int32_t len)
{
    return GetCipherSuiteDescription(cipher, buf, len);
}

/**
 * @brief   Determine whether to use the AEAD algorithm based on the cipher suite information.
 *
 * @param   cipher [IN] Cipher suite information
 * @param   isAead [OUT] Indicates whether to use the AEAD algorithm.
 * @return  HITLS_SUCCESS Obtained successfully.
 *          HITLS_NULL_INPUT The input parameter pointer is NULL.
 */
int32_t HITLS_CIPHER_IsAead(const HITLS_Cipher *cipher, bool *isAead)
{
    if (cipher == NULL || isAead == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isAead = (cipher->cipherType == HITLS_AEAD_CIPHER);
    return HITLS_SUCCESS;
}

const HITLS_Cipher *HITLS_CFG_GetCipherByID(uint16_t cipherSuite)
{
    int32_t index = FindCipherSuiteIndexByCipherSuite(cipherSuite);
    if (index == HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE) {
        return NULL;
    }

    return &g_cipherSuiteList[index];
}

int32_t HITLS_CFG_GetCipherSuite(const HITLS_Cipher *cipher, uint16_t *cipherSuite)
{
    if (cipher == NULL || cipherSuite == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *cipherSuite = cipher->cipherSuite;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_CONFIG_CIPHER_SUITE */