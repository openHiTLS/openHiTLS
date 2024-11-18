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

#if defined(HITLS_BSL_SAL_MEM) || defined(HITLS_BSL_SAL_LOCK) || defined(HITLS_BSL_SAL_THREAD) || \
    defined(HITLS_BSL_SAL_TIME) || defined(HITLS_BSL_SAL_FILE) || defined(HITLS_BSL_SAL_NET) ||   \
    defined(HITLS_BSL_SAL_STR) || defined(HITLS_BSL_SAL_DL)
    #ifndef HITLS_BSL_SAL_LINUX
    #error "[HiTLS] sal_* only work with HITLS_BSL_SAL_LINUX."
    #endif
#endif

#if defined(HITLS_CRYPTO_HMAC) && !defined(HITLS_CRYPTO_MD)
#error "[HiTLS] The hmac must work with hash."
#endif

#if defined(HITLS_CRYPTO_DRBG_HASH) && !defined(HITLS_CRYPTO_MD)
#error "[HiTLS] The drbg_hash must work with hash."
#endif

#if defined(HITLS_CRYPTO_ENTROPY) && !defined(HITLS_CRYPTO_DRBG)
#error "[HiTLS] The entropy must work with at leaset one drbg algorithm."
#endif

#if defined(HITLS_CRYPTO_PKEY) && !defined(HITLS_CRYPTO_MD)
#error "[HiTLS] The pkey must work with hash."
#endif

#if defined(HITLS_CRYPTO_BN) && !(defined(HITLS_THIRTY_TWO_BITS) || defined(HITLS_SIXTY_FOUR_BITS))
#error "[HiTLS] To use bn, the number of system bits must be specified first."
#endif

#if (defined(HITLS_TLS_FEATURE_PHA) || defined(HITLS_TLS_FEATURE_KEY_UPDATE)) && !defined(HITLS_TLS_PROTO_TLS13)
    #error "[HiTLS] Integrity check must work with TLS13"
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

#if defined(HITLS_TLS_SUITE_AES_128_GCM_SHA256) || defined(HITLS_TLS_SUITE_AES_256_GCM_SHA384) || \
    defined(HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256) || defined(HITLS_TLS_SUITE_AES_128_CCM_SHA256) || \
    defined(HITLS_TLS_SUITE_AES_128_CCM_8_SHA256)
    #if (!defined(HITLS_TLS_SUITE_AUTH_RSA) && !defined(HITLS_TLS_SUITE_AUTH_ECDSA) && \
        !defined(HITLS_TLS_SUITE_AUTH_PSK))
    #error "[HiTLS] tls13 ciphersuite must work with suite_auth_rsa or suite_auth_ecdsa or suite_auth_psk"
    #endif
#endif
#endif /* HITLS_CONFIG_CHECK_H */
