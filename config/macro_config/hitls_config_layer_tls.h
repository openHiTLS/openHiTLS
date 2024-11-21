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
/* Derivation of configuration features.
 * The derivation type (rule) and sequence are as follows:
 * 1. Parent features derive child features.
 * 2. Derive the features of dependencies.
 *    For example, if feature a depends on features b and c, you need to derive features b and c.
 * 3. Child features derive parent features.
 *    The high-level interfaces of the crypto module is controlled by the parent feature macro,
 *    if there is no parent feature, such interfaces will be unavailable.
 */

#ifndef HITLS_CONFIG_LAYER_TLS_H
#define HITLS_CONFIG_LAYER_TLS_H

// version
#ifdef HITLS_TLS_PROTO_VERSION
    #ifndef HITLS_TLS_PROTO_TLS12
        #define HITLS_TLS_PROTO_TLS12
    #endif
    #ifndef HITLS_TLS_PROTO_TLS13
        #define HITLS_TLS_PROTO_TLS13
    #endif
    #ifndef HITLS_TLS_PROTO_TLCP11
        #define HITLS_TLS_PROTO_TLCP11
    #endif
    #ifndef HITLS_TLS_PROTO_DTLS12
        #define HITLS_TLS_PROTO_DTLS12
    #endif
#endif

#if defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_TLS13) || defined(HITLS_TLS_PROTO_TLCP11)
    #ifndef HITLS_TLS_PROTO_TLS
        #define HITLS_TLS_PROTO_TLS
    #endif
#endif

#if defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_TLCP11)
    #ifndef HITLS_TLS_PROTO_TLS_BASIC
        #define HITLS_TLS_PROTO_TLS_BASIC
    #endif
#endif

#if defined(HITLS_TLS_PROTO_DTLS12)
    #ifndef HITLS_TLS_PROTO_DTLS
        #define HITLS_TLS_PROTO_DTLS
    #endif
#endif

#if defined(HITLS_TLS_PROTO_TLS12) && defined(HITLS_TLS_PROTO_TLS13)
    #ifndef HITLS_TLS_PROTO_ALL
        #define HITLS_TLS_PROTO_ALL
    #endif
#endif

// host
#ifdef HITLS_TLS_HOST
    #ifndef HITLS_TLS_HOST_SERVER
        #define HITLS_TLS_HOST_SERVER
    #endif
    #ifndef HITLS_TLS_HOST_CLIENT
        #define HITLS_TLS_HOST_CLIENT
    #endif
#endif

#if defined(HITLS_TLS_HOST_SERVER) || defined(HITLS_TLS_HOST_CLIENT)
    #ifndef HITLS_TLS_HOST
        #define HITLS_TLS_HOST
    #endif
#endif

// callback
#ifdef HITLS_TLS_CALLBACK
    #ifndef HITLS_TLS_CALLBACK_CERT
        #define HITLS_TLS_CALLBACK_CERT
    #endif
    #ifndef HITLS_TLS_CALLBACK_CRYPT
        #define HITLS_TLS_CALLBACK_CRYPT
    #endif
#endif

// feature
#ifdef HITLS_TLS_FEATURE
    #ifndef HITLS_TLS_FEATURE_RENEGOTIATION
        #define HITLS_TLS_FEATURE_RENEGOTIATION
    #endif
    #ifndef HITLS_TLS_FEATURE_ALPN
        #define HITLS_TLS_FEATURE_ALPN
    #endif
    #ifndef HITLS_TLS_FEATURE_SNI
        #define HITLS_TLS_FEATURE_SNI
    #endif
    #ifndef HITLS_TLS_FEATURE_PHA
        #define HITLS_TLS_FEATURE_PHA
    #endif
    #ifndef HITLS_TLS_FEATURE_PSK
        #define HITLS_TLS_FEATURE_PSK
    #endif
    #ifndef HITLS_TLS_FEATURE_SECURITY
        #define HITLS_TLS_FEATURE_SECURITY
    #endif
    #ifndef HITLS_TLS_FEATURE_INDICATOR
        #define HITLS_TLS_FEATURE_INDICATOR
    #endif
    #ifndef HITLS_TLS_FEATURE_SESSION
        #define HITLS_TLS_FEATURE_SESSION
    #endif
    #ifndef HITLS_TLS_FEATURE_KEY_UPDATE
        #define HITLS_TLS_FEATURE_KEY_UPDATE
    #endif
    #ifndef HITLS_TLS_FEATURE_FLIGHT
        #define HITLS_TLS_FEATURE_FLIGHT
    #endif
    #ifndef HITLS_TLS_FEATURE_CERT_MODE
        #define HITLS_TLS_FEATURE_CERT_MODE
    #endif
#endif /* HITLS_TLS_FEATURE */

#ifdef HITLS_TLS_FEATURE_SESSION
    #ifndef HITLS_TLS_FEATURE_SESSION_TICKET
        #define HITLS_TLS_FEATURE_SESSION_TICKET
    #endif
    #ifndef HITLS_TLS_FEATURE_SESSION_ID
        #define HITLS_TLS_FEATURE_SESSION_ID
    #endif
#endif

#if defined(HITLS_TLS_FEATURE_SESSION_TICKET) || defined(HITLS_TLS_FEATURE_SESSION_ID)
    #ifndef HITLS_TLS_FEATURE_SESSION
        #define HITLS_TLS_FEATURE_SESSION
    #endif
#endif

#ifdef HITLS_TLS_FEATURE_SECURITY
    #ifndef HITLS_TLS_CONFIG_CIPHER_SUITE
        #define HITLS_TLS_CONFIG_CIPHER_SUITE
    #endif
#endif

// proto
#ifdef HITLS_TLS_PROTO
    #ifndef HITLS_BSL_TLV
        #define HITLS_BSL_TLV
    #endif
    #ifndef HITLS_BSL_SAL
        #define HITLS_BSL_SAL
    #endif
    #ifndef HITLS_CRYPTO_EAL
        #define HITLS_CRYPTO_EAL
    #endif
#endif

// suite_cipher
#ifdef HITLS_TLS_SUITE_CIPHER
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
#endif

// KX
#ifdef HITLS_TLS_SUITE_KX
    #ifndef HITLS_TLS_SUITE_KX_ECDHE
        #define HITLS_TLS_SUITE_KX_ECDHE
    #endif
    #ifndef HITLS_TLS_SUITE_KX_DHE
        #define HITLS_TLS_SUITE_KX_DHE
    #endif
    #ifndef HITLS_TLS_SUITE_KX_ECDH
        #define HITLS_TLS_SUITE_KX_ECDH
    #endif
    #ifndef HITLS_TLS_SUITE_KX_DH
        #define HITLS_TLS_SUITE_KX_DH
    #endif
    #ifndef HITLS_TLS_SUITE_KX_RSA
        #define HITLS_TLS_SUITE_KX_RSA
    #endif
#endif

// AUTH
#ifdef HITLS_TLS_SUITE_AUTH
    #ifndef HITLS_TLS_SUITE_AUTH_RSA
        #define HITLS_TLS_SUITE_AUTH_RSA
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_ECDSA
        #define HITLS_TLS_SUITE_AUTH_ECDSA
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_DSS
        #define HITLS_TLS_SUITE_AUTH_DSS
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_PSK
        #define HITLS_TLS_SUITE_AUTH_PSK
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_SM2
        #define HITLS_TLS_SUITE_AUTH_SM2
    #endif
#endif

// MAINTAIN
#ifdef HITLS_TLS_MAINTAIN
    #ifndef HITLS_TLS_MAINTAIN_KEYLOG
        #define HITLS_TLS_MAINTAIN_KEYLOG
    #endif
#endif

#ifdef HITLS_TLS_CONFIG
    #ifndef HITLS_TLS_CONFIG_MANUAL_DH
        #define HITLS_TLS_CONFIG_MANUAL_DH
    #endif
    #ifndef HITLS_TLS_CONFIG_CERT
        #define HITLS_TLS_CONFIG_CERT
    #endif
    #ifndef HITLS_TLS_CONFIG_KEY_USAGE
        #define HITLS_TLS_CONFIG_KEY_USAGE
    #endif
    #ifndef HITLS_TLS_CONFIG_INFO
        #define HITLS_TLS_CONFIG_INFO
    #endif
    #ifndef HITLS_TLS_CONFIG_STATE
        #define HITLS_TLS_CONFIG_STATE
    #endif
    #ifndef HITLS_TLS_CONFIG_RECORD_PADDING
        #define HITLS_TLS_CONFIG_RECORD_PADDING
    #endif
    #ifndef HITLS_TLS_CONFIG_USER_DATA
        #define HITLS_TLS_CONFIG_USER_DATA
    #endif
    #ifndef HITLS_TLS_CONFIG_CIPHER_SUITE
        #define HITLS_TLS_CONFIG_CIPHER_SUITE
    #endif
#endif

#ifdef HITLS_TLS_CONNECTION
    #ifndef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
        #define HITLS_TLS_CONNECTION_INFO_NEGOTIATION
    #endif
#endif

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
    #ifndef HITLS_TLS_CONNECTION
        #define HITLS_TLS_CONNECTION
    #endif
#endif

#ifdef HITLS_TLS_CONFIG_CERT
    #ifndef HITLS_TLS_CONFIG_CERT_LOAD_FILE
        #define HITLS_TLS_CONFIG_CERT_LOAD_FILE
    #endif
    #ifndef HITLS_TLS_CONFIG_CERT_CALLBACK
        #define HITLS_TLS_CONFIG_CERT_CALLBACK
    #endif
#endif

#if defined(HITLS_TLS_PROTO_TLS13)
    #ifndef HITLS_TLS_EXTENSION_CERT_AUTH
        #define HITLS_TLS_EXTENSION_CERT_AUTH
    #endif
#endif

#if defined(HITLS_TLS_PROTO_DTLS12) || defined(HITLS_TLS_PROTO_TLS13)
    #ifndef HITLS_TLS_EXTENSION_COOKIE
        #define HITLS_TLS_EXTENSION_COOKIE
    #endif
#endif

#if defined(HITLS_TLS_SUITE_CIPHER_AEAD) && defined(HITLS_TLS_SUITE_KX_ECDHE) && defined(HITLS_TLS_SUITE_AUTH_RSA)
    #if !defined(HITLS_TLS_SUITE_AES_128_GCM_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_GCM_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_256_GCM_SHA384) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_256_GCM_SHA384
    #endif
    #if !defined(HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_128_CCM_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_CCM_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_128_CCM_8_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_CCM_8_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        #define HITLS_TLS_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_AEAD) && defined(HITLS_TLS_SUITE_KX_ECDHE) && defined(HITLS_TLS_SUITE_AUTH_ECDSA)
    #if !defined(HITLS_TLS_SUITE_AES_128_GCM_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_GCM_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_256_GCM_SHA384) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_256_GCM_SHA384
    #endif
    #if !defined(HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_128_CCM_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_CCM_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_128_CCM_8_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_CCM_8_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        #define HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM
        #define HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM
        #define HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_AEAD) && defined(HITLS_TLS_SUITE_KX_ECDHE) && defined(HITLS_TLS_SUITE_AUTH_PSK)
    #if !defined(HITLS_TLS_SUITE_AES_128_GCM_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_GCM_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_256_GCM_SHA384) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_256_GCM_SHA384
    #endif
    #if !defined(HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_128_CCM_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_CCM_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_128_CCM_8_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_CCM_8_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
        #define HITLS_TLS_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256
        #define HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_AEAD) && defined(HITLS_TLS_SUITE_KX_DHE) && defined(HITLS_TLS_SUITE_AUTH_RSA)

    #ifndef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        #define HITLS_TLS_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CCM
        #define HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CCM
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CCM
        #define HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CCM
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_AEAD) && defined(HITLS_TLS_SUITE_KX_DHE) && defined(HITLS_TLS_SUITE_AUTH_DSS)
    #ifndef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_GCM_SHA384
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_AEAD) && defined(HITLS_TLS_SUITE_KX_DHE) && defined(HITLS_TLS_SUITE_AUTH_PSK)
    #if !defined(HITLS_TLS_SUITE_AES_128_GCM_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_GCM_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_256_GCM_SHA384) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_256_GCM_SHA384
    #endif
    #if !defined(HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_128_CCM_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_CCM_SHA256
    #endif
    #if !defined(HITLS_TLS_SUITE_AES_128_CCM_8_SHA256) && defined(HITLS_TLS_PROTO_TLS13)
        #define HITLS_TLS_SUITE_AES_128_CCM_8_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_GCM_SHA384
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CCM
        #define HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CCM
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CCM
        #define HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CCM
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
        #define HITLS_TLS_SUITE_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_AEAD) && defined(HITLS_TLS_SUITE_KX_RSA) && defined(HITLS_TLS_SUITE_AUTH_RSA)
    #ifndef HITLS_TLS_SUITE_RSA_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_RSA_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_RSA_WITH_AES_256_GCM_SHA384
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_GCM_SHA384
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM
        #define HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM_8
        #define HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM_8
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM
        #define HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM_8
        #define HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM_8
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_AEAD) && defined(HITLS_TLS_SUITE_KX_RSA) && defined(HITLS_TLS_SUITE_AUTH_PSK)
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_GCM_SHA384
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_ECDHE) && defined(HITLS_TLS_SUITE_AUTH_RSA)
    #ifndef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        #define HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_ECDHE) && defined(HITLS_TLS_SUITE_AUTH_ECDSA)
    #ifndef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        #define HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_ECDHE) && defined(HITLS_TLS_SUITE_AUTH_PSK)
    #ifndef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA384
        #define HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA384
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_ECDHE) && defined(HITLS_TLS_SUITE_AUTH_SM2)
    #ifndef HITLS_TLS_SUITE_ECDHE_SM4_CBC_SM3
        #define HITLS_TLS_SUITE_ECDHE_SM4_CBC_SM3
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_DHE) && defined(HITLS_TLS_SUITE_AUTH_RSA)
    #ifndef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256
        #define HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_DHE) && defined(HITLS_TLS_SUITE_AUTH_DSS)
    #ifndef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA256
        #define HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA256
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_DHE) && defined(HITLS_TLS_SUITE_AUTH_PSK)
    #ifndef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA384
        #define HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA384
    #endif
#endif

#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_RSA) && defined(HITLS_TLS_SUITE_AUTH_RSA)
    #ifndef HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA256
        #define HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA384
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA384
    #endif
#endif

#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_RSA) && defined(HITLS_TLS_SUITE_AUTH_PSK)
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA384
        #define HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA384
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_AEAD) && defined(HITLS_TLS_SUITE_KX_DHE)
    #ifndef HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_GCM_SHA384
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_ECDHE)
    #ifndef HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_256_CBC_SHA
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_KX_DHE)
    #ifndef HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA256
        #define HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA256
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_AEAD) && defined(HITLS_TLS_SUITE_AUTH_PSK)
    #ifndef HITLS_TLS_SUITE_PSK_WITH_AES_128_GCM_SHA256
        #define HITLS_TLS_SUITE_PSK_WITH_AES_128_GCM_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_PSK_WITH_AES_256_GCM_SHA384
        #define HITLS_TLS_SUITE_PSK_WITH_AES_256_GCM_SHA384
    #endif
    #ifndef HITLS_TLS_SUITE_PSK_WITH_AES_256_CCM
        #define HITLS_TLS_SUITE_PSK_WITH_AES_256_CCM
    #endif
    #ifndef HITLS_TLS_SUITE_PSK_WITH_CHACHA20_POLY1305_SHA256
        #define HITLS_TLS_SUITE_PSK_WITH_CHACHA20_POLY1305_SHA256
    #endif
#endif
#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_AUTH_PSK)
    #ifndef HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA
        #define HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA
        #define HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA
    #endif
    #ifndef HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA256
        #define HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA256
    #endif
    #ifndef HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA384
        #define HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA384
    #endif
#endif

#if defined(HITLS_TLS_SUITE_CIPHER_CBC) && defined(HITLS_TLS_SUITE_AUTH_SM2)
    #ifndef HITLS_TLS_SUITE_ECC_SM4_CBC_SM3
        #define HITLS_TLS_SUITE_ECC_SM4_CBC_SM3
    #endif
#endif

#if defined(HITLS_TLS_SUITE_AES_128_GCM_SHA256) || defined(HITLS_TLS_SUITE_AES_256_GCM_SHA384) || \
    defined(HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256) || defined(HITLS_TLS_SUITE_AES_128_CCM_SHA256) || \
    defined(HITLS_TLS_SUITE_AES_128_CCM_8_SHA256)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_KX_ECDHE
        #define HITLS_TLS_SUITE_KX_ECDHE
    #endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA) || defined(HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA256) || defined(HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA256)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_RSA
        #define HITLS_TLS_SUITE_KX_RSA
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_RSA
        #define HITLS_TLS_SUITE_AUTH_RSA
    #endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_128_GCM_SHA256) || \
    defined(HITLS_TLS_SUITE_RSA_WITH_AES_256_GCM_SHA384) || \
    defined(HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM) || defined(HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM_8) || \
    defined(HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM) || defined(HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM_8)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_KX_RSA
        #define HITLS_TLS_SUITE_KX_RSA
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_RSA
        #define HITLS_TLS_SUITE_AUTH_RSA
    #endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256) || \
    defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384) || \
    defined(HITLS_TLS_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256) || \
    defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CCM) || defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CCM)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_KX_DHE
        #define HITLS_TLS_SUITE_KX_DHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_RSA
        #define HITLS_TLS_SUITE_AUTH_RSA
    #endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256) || \
    defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_ECDHE
        #define HITLS_TLS_SUITE_KX_ECDHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_ECDSA
        #define HITLS_TLS_SUITE_AUTH_ECDSA
    #endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) || \
    defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) || \
    defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256) || \
    defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM) || defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_KX_ECDHE
        #define HITLS_TLS_SUITE_KX_ECDHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_ECDSA
        #define HITLS_TLS_SUITE_AUTH_ECDSA
    #endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256) || \
    defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_ECDHE
        #define HITLS_TLS_SUITE_KX_ECDHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_RSA
        #define HITLS_TLS_SUITE_AUTH_RSA
    #endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256) || \
    defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384) || \
    defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_KX_ECDHE
        #define HITLS_TLS_SUITE_KX_ECDHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_RSA
        #define HITLS_TLS_SUITE_AUTH_RSA
    #endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_GCM_SHA256) || \
    defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_GCM_SHA384)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_KX_DHE
        #define HITLS_TLS_SUITE_KX_DHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_DSS
        #define HITLS_TLS_SUITE_AUTH_DSS
    #endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA256) || \
    defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA256)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_DHE
        #define HITLS_TLS_SUITE_KX_DHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_DSS
        #define HITLS_TLS_SUITE_AUTH_DSS
    #endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256) || \
    defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_DHE
        #define HITLS_TLS_SUITE_KX_DHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_RSA
        #define HITLS_TLS_SUITE_AUTH_RSA
    #endif
#endif
#if defined(HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA) || defined(HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA256) || defined(HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA384)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_PSK
        #define HITLS_TLS_SUITE_AUTH_PSK
    #endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA256) || \
    defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA384)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_DHE
        #define HITLS_TLS_SUITE_KX_DHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_PSK
        #define HITLS_TLS_SUITE_AUTH_PSK
    #endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA256) || \
    defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA384)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_RSA
        #define HITLS_TLS_SUITE_KX_RSA
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_RSA
        #define HITLS_TLS_SUITE_AUTH_RSA
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_PSK
        #define HITLS_TLS_SUITE_AUTH_PSK
    #endif
#endif
#if defined(HITLS_TLS_SUITE_PSK_WITH_AES_128_GCM_SHA256) || defined(HITLS_TLS_SUITE_PSK_WITH_AES_256_GCM_SHA384) || \
    defined(HITLS_TLS_SUITE_PSK_WITH_AES_256_CCM) || defined(HITLS_TLS_SUITE_PSK_WITH_CHACHA20_POLY1305_SHA256)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_PSK
        #define HITLS_TLS_SUITE_AUTH_PSK
    #endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_GCM_SHA256) || \
    defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_GCM_SHA384) || defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CCM) || \
    defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CCM) || defined(HITLS_TLS_SUITE_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_KX_DHE
        #define HITLS_TLS_SUITE_KX_DHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_PSK
        #define HITLS_TLS_SUITE_AUTH_PSK
    #endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_GCM_SHA256) || \
    defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_GCM_SHA384) || \
    defined(HITLS_TLS_SUITE_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_KX_RSA
        #define HITLS_TLS_SUITE_KX_RSA
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_RSA
        #define HITLS_TLS_SUITE_AUTH_RSA
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_PSK
        #define HITLS_TLS_SUITE_AUTH_PSK
    #endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA256) || \
    defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA384)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_ECDHE
        #define HITLS_TLS_SUITE_KX_ECDHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_PSK
        #define HITLS_TLS_SUITE_AUTH_PSK
    #endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256) || \
    defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256) || \
    defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256) || \
    defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_KX_ECDHE
        #define HITLS_TLS_SUITE_KX_ECDHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_PSK
        #define HITLS_TLS_SUITE_AUTH_PSK
    #endif
#endif
#if defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA256) || \
    defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA256)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_DHE
        #define HITLS_TLS_SUITE_KX_DHE
    #endif
#endif
#if defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_GCM_SHA256) || \
    defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_GCM_SHA384)
    #ifndef HITLS_TLS_SUITE_CIPHER_AEAD
        #define HITLS_TLS_SUITE_CIPHER_AEAD
    #endif
    #ifndef HITLS_TLS_SUITE_KX_DHE
        #define HITLS_TLS_SUITE_KX_DHE
    #endif
#endif
#if defined(HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_128_CBC_SHA) || \
    defined(HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_256_CBC_SHA)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_ECDHE
        #define HITLS_TLS_SUITE_KX_ECDHE
    #endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_SM4_CBC_SM3)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_KX_ECDHE
        #define HITLS_TLS_SUITE_KX_ECDHE
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_SM2
        #define HITLS_TLS_SUITE_AUTH_SM2
    #endif
#endif
#if defined(HITLS_TLS_SUITE_ECC_SM4_CBC_SM3)
    #ifndef HITLS_TLS_SUITE_CIPHER_CBC
        #define HITLS_TLS_SUITE_CIPHER_CBC
    #endif
    #ifndef HITLS_TLS_SUITE_AUTH_SM2
        #define HITLS_TLS_SUITE_AUTH_SM2
    #endif
#endif

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    #ifndef HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES
        #define HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES
    #endif
#endif

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    #ifndef HITLS_TLS_FEATURE_ETM
        #define HITLS_TLS_FEATURE_ETM
    #endif
#endif

#if defined(HITLS_TLS_SUITE_AUTH_ECDSA) || defined(HITLS_TLS_SUITE_AUTH_RSA) || defined(HITLS_TLS_SUITE_AUTH_DSS) || \
    defined(HITLS_TLS_SUITE_AUTH_PSK) || defined(HITLS_TLS_SUITE_AUTH_SM2)
    #ifndef HITLS_TLS_SUITE_AUTH
        #define HITLS_TLS_SUITE_AUTH
    #endif
#endif

#endif /* HITLS_CONFIG_LAYER_TLS_H */