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
/* Check the dependency of the configuration features. The check rules are as follows:
 * Non-deterministic feature dependency needs to be checked.
 * For example, feature a depends on feature b or c:
 * if feature a is defined, at least one of feature b and c must be defined.
 */

#ifndef HITLS_CONFIG_CHECK_H
#define HITLS_CONFIG_CHECK_H

#ifdef HITLS_TLS
#if defined(HITLS_TLS_FEATURE_PROVIDER) && !defined(HITLS_CRYPTO_PROVIDER)
#error "[HiTLS] The tls-provider must work with crypto-provider"
#endif

#if defined(HITLS_TLS_CONFIG_CERT_VERIFY_LOCATION) && defined(HITLS_TLS_CALLBACK_CERT) && \
    !defined(HITLS_PKI_X509_VFY_LOCATION)
#error "[HiTLS] The tls verify must work with pki vfy location"
#endif

#if (defined(HITLS_TLS_FEATURE_PHA) || defined(HITLS_TLS_FEATURE_KEY_UPDATE) || defined(HITLS_TLS_FEATURE_SM_TLS13)) && \
    !defined(HITLS_TLS_PROTO_TLS13)
    #error "[HiTLS] Integrity check must work with TLS13"
#endif

#if defined(HITLS_TLS_PROTO_TLS_BASIC) && defined(HITLS_TLS_FEATURE_SESSION_TICKET) && \
    !defined(HITLS_TLS_FEATURE_SESSION_ID)
    #error "[HiTLS] session ticket must work with session id in tls12 and blow"
#endif

#if defined(HITLS_TLS_FEATURE_SNI) && !defined(HITLS_TLS_FEATURE_SESSION)
    #error "[HiTLS] SNI must work with session"
#endif

#if defined(HITLS_TLS_SUITE_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_AES_128_GCM_SHA256 must work with sha256, gcm, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_AES_256_GCM_SHA384 must work with sha384, gcm, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CHACHA20POLY1305) || !defined(HITLS_CRYPTO_CHACHA20)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256 must work with sha256, chacha20poly1305, \
        chacha20"
#endif
#endif
#if defined(HITLS_TLS_SUITE_AES_128_CCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_AES_128_CCM_SHA256 must work with sha256, ccm, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_AES_128_CCM_8_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_AES_128_CCM_8_SHA256 must work with sha256, ccm, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA256 must work with sha256, cbc, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA256 must work with sha256, cbc, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_WITH_AES_128_GCM_SHA256 must work with sha256, gcm, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_WITH_AES_256_GCM_SHA384 must work with sha384, gcm, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 must work with sha256, gcm, aes, rsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 must work with sha384, gcm, aes, rsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH) || !defined(HITLS_CRYPTO_ECDSA)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes, ecdh, ecdsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH) || !defined(HITLS_CRYPTO_ECDSA)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes, ecdh, ecdsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH) || !defined(HITLS_CRYPTO_ECDSA)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 must work with sha256, cbc, aes, ecdh, \
ecdsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH) || !defined(HITLS_CRYPTO_ECDSA)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 must work with sha384, cbc, aes, ecdh, \
ecdsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH) || !defined(HITLS_CRYPTO_ECDSA)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 must work with sha256, gcm, aes, ecdh, \
ecdsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH) || !defined(HITLS_CRYPTO_ECDSA)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 must work with sha384, gcm, aes, ecdh, \
ecdsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes, rsa, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes, rsa, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_ECDH)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256 must work with sha256, cbc, aes, rsa, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_ECDH)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384 must work with sha384, cbc, aes, rsa, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_ECDH)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 must work with sha256, gcm, aes, rsa, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_ECDH)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384 must work with sha384, gcm, aes, rsa, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CHACHA20POLY1305) || !defined(HITLS_CRYPTO_CHACHA20) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_ECDH)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 must work with sha256, \
chacha20poly1305, chacha20, rsa, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CHACHA20POLY1305) || !defined(HITLS_CRYPTO_CHACHA20) || \
    !defined(HITLS_CRYPTO_ECDH) || !defined(HITLS_CRYPTO_ECDSA)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 must work with sha256, \
chacha20poly1305, chacha20, ecdh, ecdsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CHACHA20POLY1305) || !defined(HITLS_CRYPTO_CHACHA20) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_DH)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 must work with sha256, \
chacha20poly1305, chacha20, rsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_GCM_SHA256 must work with sha256, gcm, aes, dsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_GCM_SHA384 must work with sha384, gcm, aes, dsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes, dsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes, dsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA256 must work with sha256, cbc, aes, dsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA256 must work with sha256, cbc, aes, dsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes, rsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes, rsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 must work with sha256, cbc, aes, rsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 must work with sha256, cbc, aes, rsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_PSK_WITH_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_PSK_WITH_AES_128_GCM_SHA256 must work with sha256, gcm, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_PSK_WITH_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_PSK_WITH_AES_256_GCM_SHA384 must work with sha384, gcm, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_PSK_WITH_AES_256_CCM)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_PSK_WITH_AES_256_CCM must work with ccm, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_GCM_SHA256 must work with sha256, gcm, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_GCM_SHA384 must work with sha384, gcm, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CCM)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CCM must work with ccm, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CCM)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CCM must work with ccm, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_GCM_SHA256 must work with sha256, gcm, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_GCM_SHA384 must work with sha384, gcm, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA256 must work with sha256, cbc, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA384 must work with sha384, cbc, aes"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA256 must work with sha256, cbc, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA384 must work with sha384, cbc, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA256 must work with sha256, cbc, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA384 must work with sha384, cbc, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA256 must work with sha256, cbc, aes, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA384 must work with sha384, cbc, aes, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_PSK_WITH_CHACHA20_POLY1305_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CHACHA20POLY1305) || !defined(HITLS_CRYPTO_CHACHA20)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_PSK_WITH_CHACHA20_POLY1305_SHA256 must work with sha256, chacha20poly1305, \
chacha20"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CHACHA20POLY1305) || !defined(HITLS_CRYPTO_CHACHA20) || \
    !defined(HITLS_CRYPTO_ECDH)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 must work with sha256, \
chacha20poly1305, chacha20, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CHACHA20POLY1305) || !defined(HITLS_CRYPTO_CHACHA20) || \
    !defined(HITLS_CRYPTO_DH)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 must work with sha256, \
chacha20poly1305, chacha20, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CHACHA20POLY1305) || !defined(HITLS_CRYPTO_CHACHA20) || \
    !defined(HITLS_CRYPTO_RSA)
#error \
    "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 must work with sha256, \
chacha20poly1305, chacha20, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256 must work with sha256, ccm, aes, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256 must work with sha256, gcm, aes, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384 must work with sha384, gcm, aes, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA256 must work with sha256, cbc, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA256 must work with sha256, cbc, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_GCM_SHA256)
#if !defined(HITLS_CRYPTO_SHA256) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_GCM_SHA256 must work with sha256, gcm, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_GCM_SHA384)
#if !defined(HITLS_CRYPTO_SHA384) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_GCM_SHA384 must work with sha384, gcm, aes, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_128_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH) || !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_128_CBC_SHA must work with sha1, cbc, aes, dh, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_256_CBC_SHA)
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_AES) || \
    !defined(HITLS_CRYPTO_DH) || !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_256_CBC_SHA must work with sha1, cbc, aes, dh, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_ECDH) || \
    !defined(HITLS_CRYPTO_ECDSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM must work with ccm, aes, ecdh, ecdsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_ECDH) || \
    !defined(HITLS_CRYPTO_ECDSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM must work with ccm, aes, ecdh, ecdsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CCM)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CCM must work with ccm, aes, rsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CCM)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_DH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CCM must work with ccm, aes, rsa, dh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM must work with ccm, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM_8)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM_8 must work with ccm, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM must work with ccm, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM_8)
#if !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_RSA)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM_8 must work with ccm, aes, rsa"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_SM4_CBC_SM3)
#if !defined(HITLS_CRYPTO_SM3) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_SM4) || \
    !defined(HITLS_CRYPTO_SM2) || !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_SM4_CBC_SM3 must work with sm3, cbc, sm4, sm2, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECC_SM4_CBC_SM3)
#if !defined(HITLS_CRYPTO_SM3) || !defined(HITLS_CRYPTO_CBC) || !defined(HITLS_CRYPTO_SM4) || \
    !defined(HITLS_CRYPTO_SM2)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECC_SM4_CBC_SM3 must work with sm3, cbc, sm4, sm2"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECDHE_SM4_GCM_SM3)
#if !defined(HITLS_CRYPTO_SM3) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_SM4) || \
    !defined(HITLS_CRYPTO_SM2) || !defined(HITLS_CRYPTO_ECDH)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECDHE_SM4_GCM_SM3 must work with sm3, gcm, sm4, sm2, ecdh"
#endif
#endif
#if defined(HITLS_TLS_SUITE_ECC_SM4_GCM_SM3)
#if !defined(HITLS_CRYPTO_SM3) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_SM4) || \
    !defined(HITLS_CRYPTO_SM2)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_ECC_SM4_GCM_SM3 must work with sm3, gcm, sm4, sm2"
#endif
#endif
#if defined(HITLS_TLS_SUITE_SM4_GCM_SM3)
#if !defined(HITLS_CRYPTO_SM3) || !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_SM4) || \
    !defined(HITLS_CRYPTO_SM2)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_SM4_GCM_SM3 must work with sm3, gcm, sm4, sm2"
#endif
#endif
#if defined(HITLS_TLS_SUITE_SM4_CCM_SM3)
#if !defined(HITLS_CRYPTO_SM3) || !defined(HITLS_CRYPTO_CCM) || !defined(HITLS_CRYPTO_SM4) || \
    !defined(HITLS_CRYPTO_SM2)
#error "[HiTLS] cipher suite HITLS_TLS_SUITE_SM4_CCM_SM3 must work with sm3, ccm, sm4, sm2"
#endif
#endif

#if defined(HITLS_TLS_SUITE_AES_128_GCM_SHA256) || defined(HITLS_TLS_SUITE_AES_256_GCM_SHA384) || \
    defined(HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256) || defined(HITLS_TLS_SUITE_AES_128_CCM_SHA256) || \
    defined(HITLS_TLS_SUITE_AES_128_CCM_8_SHA256)
    #if (!defined(HITLS_TLS_SUITE_AUTH_RSA) && !defined(HITLS_TLS_SUITE_AUTH_ECDSA) && \
        !defined(HITLS_TLS_SUITE_AUTH_PSK))
    #error "[HiTLS] tls13 ciphersuite must work with suite_auth_rsa or suite_auth_ecdsa or suite_auth_psk"
    #endif
#endif

#if defined(HITLS_TLS_FEATURE_ETM) && !defined(HITLS_TLS_SUITE_CIPHER_CBC)
#error "[HiTLS] The etm must work with cbc"
#endif

#endif /* HITLS_TLS */

#ifdef HITLS_CRYPTO
#if defined(HITLS_CRYPTO_HMAC) && !defined(HITLS_CRYPTO_MD)
    #error "[HiTLS] The hmac must work with hash"
#endif

#if defined(HITLS_CRYPTO_DRBG_HASH) && !defined(HITLS_CRYPTO_MD)
    #error "[HiTLS] The drbg_hash must work with hash"
#endif

#if defined(HITLS_CRYPTO_DRBG_CTR) && !defined(HITLS_CRYPTO_AES) && !defined(HITLS_CRYPTO_SM4)
    #error "[HiTLS] AES or SM4 must be enabled for DRBG-CTR"
#endif

#if defined(HITLS_CRYPTO_ENTROPY) && !defined(HITLS_CRYPTO_DRBG)
    #error "[HiTLS] The entropy must work with at least one drbg algorithm."
#endif

#if defined(HITLS_CRYPTO_DRBG_GM) && !defined(HITLS_CRYPTO_DRBG_CTR) && !defined(HITLS_CRYPTO_DRBG_HASH)
    #error "[HiTLS]DRBG-HASH or DRBG-CTR must be enabled for DRBG-GM"
#endif

#if defined(HITLS_CRYPTO_ENTROPY_HARDWARE) && !defined(HITLS_CRYPTO_EALINIT)
    #error "[HiTLS] ealinit must be enabled when the hardware entropy source is enabled."
#endif

#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_DRBG_CTR) && !defined(HITLS_CRYPTO_DRBG_GM)
    #ifndef HITLS_CRYPTO_CMAC_AES
        #error "[HiTLS] Configure the conditioning function. Currently, CRYPT_MAC_CMAC_AES is supported. \
            others may be supported in the future."
    #endif
#endif

#if defined(HITLS_CRYPTO_BN) && !(defined(HITLS_THIRTY_TWO_BITS) || defined(HITLS_SIXTY_FOUR_BITS))
    #error "[HiTLS] To use bn, the number of system bits must be specified first."
#endif

#if defined(HITLS_CRYPTO_HPKE)
    #if !defined(HITLS_CRYPTO_AES) && !defined(HITLS_CRYPTO_CHACHA20POLY1305)
    #error "[HiTLS] The hpke must work with aes or chacha20poly1305."
    #endif

    #if !defined(HITLS_CRYPTO_CHACHA20POLY1305) && defined(HITLS_CRYPTO_AES) && !defined(HITLS_CRYPTO_GCM)
    #error "[HiTLS] The hpke must work with aes-gcm."
    #endif

    #if !defined(HITLS_CRYPTO_CURVE_NISTP256) && !defined(HITLS_CRYPTO_CURVE_NISTP384) && \
        !defined(HITLS_CRYPTO_CURVE_NISTP521) && !defined(HITLS_CRYPTO_X25519)
    #error "[HiTLS] The hpke must work with p256 or p384 or p521 or x25519."
    #endif
#endif /* HITLS_CRYPTO_HPKE */

#if defined(HITLS_CRYPTO_RSA_BLINDING) && !(defined(HITLS_CRYPTO_BN_RAND))
    #error "[HiTLS] The blind must work with bn_rand"
#endif

#if defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY)
    #if !defined(HITLS_CRYPTO_RSA_EMSA_PSS) && !defined(HITLS_CRYPTO_RSA_EMSA_PKCSV15) && \
        !defined(HITLS_CRYPTO_RSA_EMSA_ISO9796_2)
    #error "[HiTLS] The rsa_sign/rsa_verify must work with rsa_emsa_pss/rsa_emsa_pkcsv15/rsa_emsa_iso9796_2"
    #endif
#endif

#if defined(HITLS_CRYPTO_RSA_ENCRYPT) || defined(HITLS_CRYPTO_RSA_DECRYPT)
    #if !defined(HITLS_CRYPTO_RSAES_OAEP) && !defined(HITLS_CRYPTO_RSAES_PKCSV15) && \
        !defined(HITLS_CRYPTO_RSAES_PKCSV15_TLS) && !defined(HITLS_CRYPTO_RSA_NO_PAD)
    #error "[HiTLS] The rsa_encrypt/rsa_decrypt must work with rsaes_oaep/rsaes_pkcsv15/rsaes_pkcsv15_tls/rsa_no_pad"
    #endif
#endif

#if defined(HITLS_CRYPTO_RSA_NO_PAD) || defined(HITLS_CRYPTO_RSAES_OAEP) || defined(HITLS_CRYPTO_RSAES_PKCSV15) || \
    defined(HITLS_CRYPTO_RSAES_PKCSV15_TLS)
    #if !defined(HITLS_CRYPTO_RSA_ENCRYPT) && !defined(HITLS_CRYPTO_RSA_DECRYPT)
    #error "[HiTLS] The rsaes_oaep/rsaes_pkcsv15/rsaes_pkcsv15_tls/rsa_no_pad must work with rsa_encrypt/rsa_decrypt"
    #endif
#endif

#if defined(HITLS_CRYPTO_RSA_EMSA_PSS) || defined(HITLS_CRYPTO_RSA_EMSA_PKCSV15) || \
    defined(HITLS_CRYPTO_RSA_EMSA_ISO9796_2)
    #if !defined(HITLS_CRYPTO_RSA_SIGN) && !defined(HITLS_CRYPTO_RSA_VERIFY)
    #error "[HiTLS] The rsa_emsa_pss/rsa_emsa_pkcsv15/rsa_emsa_iso9796_2 must work with rsa_sign/rsa_verify"
    #endif
#endif

#if defined(HITLS_CRYPTO_RSA_BLINDING) && !defined(HITLS_CRYPTO_RSA_SIGN) && !defined(HITLS_CRYPTO_RSA_DECRYPT)
    #error "[HiTLS] The rsa_blinding must work with rsa_sign or rsa_decrypt"
#endif

#if defined(HITLS_CRYPTO_RSA_ENCRYPT) && (defined(HITLS_CRYPTO_RSAES_OAEP) || defined(HITLS_CRYPTO_RSAES_PKCSV15))
    #ifndef HITLS_CRYPTO_DRBG
    #error "[HiTLS] The rsa_encrypt+rsaes_oaep/rsa_pkcsv15 must work with a drbg algorithm."
    #endif
#endif

#if defined(HITLS_CRYPTO_RSA_SIGN) && defined(HITLS_CRYPTO_RSA_EMSA_PSS) && !defined(HITLS_CRYPTO_DRBG)
    #error "[HiTLS] The rsa_sign+rsa_emsa_pss must work with a drbg algorithm."
#endif

#if defined(HITLS_CRYPTO_RSA_GEN) && !(defined(HITLS_CRYPTO_BN_RAND) && defined(HITLS_CRYPTO_BN_PRIME))
    #error "[HiTLS] The rsa_gen must work with bn_rand and bn_prime"
#endif

#if defined(HITLS_CRYPTO_ECDSA)
    #if !defined(HITLS_CRYPTO_CURVE_NISTP224) && !defined(HITLS_CRYPTO_CURVE_NISTP256) && \
        !defined(HITLS_CRYPTO_CURVE_NISTP384) && !defined(HITLS_CRYPTO_CURVE_NISTP521) && \
        !defined(HITLS_CRYPTO_CURVE_BP256R1) && !defined(HITLS_CRYPTO_CURVE_BP384R1) && \
        !defined(HITLS_CRYPTO_CURVE_BP512R1) && !defined(HITLS_CRYPTO_CURVE_192WAPI)
    #error "[HiTLS] Nist curves or brainpool curves or 192Wapi curve must be enabled for ECDSA."
    #endif
#endif

#if defined(HITLS_CRYPTO_ECDH)
    #if !defined(HITLS_CRYPTO_CURVE_NISTP224) && !defined(HITLS_CRYPTO_CURVE_NISTP256) && \
        !defined(HITLS_CRYPTO_CURVE_NISTP384) && !defined(HITLS_CRYPTO_CURVE_NISTP521) && \
        !defined(HITLS_CRYPTO_CURVE_BP256R1) && !defined(HITLS_CRYPTO_CURVE_BP384R1) && \
        !defined(HITLS_CRYPTO_CURVE_BP512R1) && !defined(HITLS_CRYPTO_CURVE_192WAPI)
    #error "[HiTLS] Nist curves or brainpool curves must be enabled for ECDH."
    #endif
#endif

#if defined(HITLS_CRYPTO_CMVP_INTEGRITY) && !defined(HITLS_CRYPTO_CMVP)
    #error "[HiTLS] Integrity check must work with CMVP"
#endif

#if (defined(HITLS_CRYPTO_SHA1_ARMV8) || \
     defined(HITLS_CRYPTO_SHA256_ARMV8) || defined(HITLS_CRYPTO_SHA224_ARMV8) || defined(HITLS_CRYPTO_SHA2_ARMV8) || \
     defined(HITLS_CRYPTO_SM4_X8664)) && !defined(HITLS_CRYPTO_EALINIT)
    #error "[HiTLS] ealinit must be enabled for sha1_armv8 or sha256_armv8 or sha224_armv8 or sm4_x8664."
#endif

#if defined(HITLS_CRYPTO_HYBRIDKEM)
    #if !defined(HITLS_CRYPTO_X25519) && !defined(HITLS_CRYPTO_ECDH)
        #error "[HiTLS] The hybrid must work with x25519 or ecdh."
    #endif
#endif

#ifdef HITLS_CRYPTO_KEY_EPKI
    #if !defined(HITLS_CRYPTO_KEY_ENCODE) && !defined(HITLS_CRYPTO_KEY_DECODE)
        #error "[HiTLS] The key encrypt must work with key gen or key parse."
    #endif
    #if !defined(HITLS_CRYPTO_DRBG)
        #error "[HiTLS] The key encrypt must work with a drbg algorithm."
    #endif
    #if !defined(HITLS_CRYPTO_CIPHER)
        #error "[HiTLS] The key encrypt must work with a symmetric algorithm."
    #endif
#endif

#if defined(HITLS_CRYPTO_CODECSKEY) && (!defined(HITLS_CRYPTO_ECDSA) && !defined(HITLS_CRYPTO_SM2_SIGN) && \
    !defined(HITLS_CRYPTO_SM2_CRYPT) && !defined(HITLS_CRYPTO_ED25519) && !defined(HITLS_CRYPTO_RSA_SIGN)) && \
    !defined(HITLS_CRYPTO_RSA_VERIFY) && !defined(HITLS_CRYPTO_MLDSA)
    #error "[HiTLS] The encode must work with ecdsa or sm2_sign or sm2_crypt or ed25519 or rsa_sign or rsa_verify \
    or mldsa."
#endif

#if defined(HITLS_CRYPTO_SHA256_SMALL_MEM) && !defined(HITLS_CRYPTO_SHA256)
    #error "[HiTLS] The HITLS_CRYPTO_SHA256_SMALL_MEM must work with sha256."
#endif

#if defined(HITLS_CRYPTO_SHA512_SMALL_MEM) && !defined(HITLS_CRYPTO_SHA512)
    #error "[HiTLS] The HITLS_CRYPTO_SHA512_SMALL_MEM must work with sha512."
#endif

#if defined(HITLS_CRYPTO_SHA1_SMALL_MEM) && !defined(HITLS_CRYPTO_SHA1)
    #error "[HiTLS] The HITLS_CRYPTO_SHA1_SMALL_MEM must work with sha1."
#endif

#endif /* HITLS_CRYPTO */

#ifdef HITLS_PKI

#if defined(HITLS_PKI_INFO_CRT) && !defined(HITLS_PKI_X509_CRT)
#error "[HiTLS] The info_crt must work with x509_crt_gen or x509_crt_parse."
#endif

#if defined(HITLS_PKI_INFO_CSR) && !defined(HITLS_PKI_X509_CSR)
#error "[HiTLS] The info_csr must work with x509_csr_gen or x509_csr_parse."
#endif

#if defined(HITLS_PKI_INFO_CRL) && !defined(HITLS_PKI_X509_CRL)
#error "[HiTLS] The info_crl must work with x509_crl_gen or x509_crl_parse."
#endif


#if defined(HITLS_PKI_X509_CSR_GET) && !defined(HITLS_PKI_X509_CSR)
#error "[HiTLS] The x509_csr_get must work with x509_csr_gen or x509_csr_parse."
#endif

#if defined(HITLS_PKI_X509_CSR_ATTR) && !defined(HITLS_PKI_X509_CSR)
#error "[HiTLS] The x509_csr_attr must work with x509_csr_gen or x509_csr_parse."
#endif

#endif /* HITLS_PKI */

#endif /* HITLS_CONFIG_CHECK_H */
