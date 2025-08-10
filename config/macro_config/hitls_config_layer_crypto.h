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

#ifndef HITLS_CONFIG_LAYER_CRYPTO_H
#define HITLS_CONFIG_LAYER_CRYPTO_H

/* KDF */
#ifdef HITLS_CRYPTO_KDF
    #ifndef HITLS_CRYPTO_PBKDF2
        #define HITLS_CRYPTO_PBKDF2
    #endif
    #ifndef HITLS_CRYPTO_HKDF
        #define HITLS_CRYPTO_HKDF
    #endif
    #ifndef HITLS_CRYPTO_KDFTLS12
        #define HITLS_CRYPTO_KDFTLS12
    #endif
    #ifndef HITLS_CRYPTO_SCRYPT
        #define HITLS_CRYPTO_SCRYPT
    #endif
#endif

#ifdef HITLS_CRYPTO_HPKE
    #ifndef HITLS_CRYPTO_HKDF
        #define HITLS_CRYPTO_HKDF
    #endif
#endif

#ifdef HITLS_CRYPTO_SCRYPT
    #ifndef HITLS_CRYPTO_SHA256
        #define HITLS_CRYPTO_SHA256
    #endif
    #ifndef HITLS_CRYPTO_PBKDF2
        #define HITLS_CRYPTO_PBKDF2
    #endif
#endif

#if defined(HITLS_CRYPTO_PBKDF2) || defined(HITLS_CRYPTO_HKDF) || defined(HITLS_CRYPTO_KDFTLS12) || \
    defined(HITLS_CRYPTO_SCRYPT)
    #ifndef HITLS_CRYPTO_KDF
            #define HITLS_CRYPTO_KDF
    #endif
#endif

#if defined(HITLS_CRYPTO_KDF) && !defined(HITLS_CRYPTO_HMAC)
    #define HITLS_CRYPTO_HMAC
#endif

/* DRBG */
#ifdef HITLS_CRYPTO_DRBG
    #ifndef HITLS_CRYPTO_DRBG_HASH
        #define HITLS_CRYPTO_DRBG_HASH
    #endif
    #ifndef HITLS_CRYPTO_DRBG_HMAC
        #define HITLS_CRYPTO_DRBG_HMAC
    #endif
    #ifndef HITLS_CRYPTO_DRBG_CTR
        #define HITLS_CRYPTO_DRBG_CTR
    #endif
#endif

#if defined(HITLS_CRYPTO_DRBG_HMAC) && !defined(HITLS_CRYPTO_HMAC)
    #define HITLS_CRYPTO_HMAC
#endif

#if defined(HITLS_CRYPTO_DRBG_CTR) && !defined(HITLS_CRYPTO_AES)
    #define HITLS_CRYPTO_AES
#endif

#if defined(HITLS_CRYPTO_DRBG_HASH) || defined(HITLS_CRYPTO_DRBG_HMAC) || defined(HITLS_CRYPTO_DRBG_CTR)
    #ifndef HITLS_CRYPTO_DRBG
        #define HITLS_CRYPTO_DRBG
    #endif
#endif

/* MAC */
#ifdef HITLS_CRYPTO_MAC
    #ifndef HITLS_CRYPTO_HMAC
        #define HITLS_CRYPTO_HMAC
    #endif
#endif

#if defined(HITLS_CRYPTO_HMAC)
    #ifndef HITLS_CRYPTO_MAC
        #define HITLS_CRYPTO_MAC
    #endif
#endif

/* CIPHER */
#ifdef HITLS_CRYPTO_CIPHER
    #ifndef HITLS_CRYPTO_AES
        #define HITLS_CRYPTO_AES
    #endif
    #ifndef HITLS_CRYPTO_SM4
        #define HITLS_CRYPTO_SM4
    #endif
    #ifndef HITLS_CRYPTO_CHACHA20
        #define HITLS_CRYPTO_CHACHA20
    #endif
#endif
 
#if defined(HITLS_CRYPTO_CHACHA20) && !defined(HITLS_CRYPTO_CHACHA20POLY1305)
    #define HITLS_CRYPTO_CHACHA20POLY1305
#endif
 
#if defined(HITLS_CRYPTO_AES) || defined(HITLS_CRYPTO_SM4) || defined(HITLS_CRYPTO_CHACHA20)
    #ifndef HITLS_CRYPTO_CIPHER
        #define HITLS_CRYPTO_CIPHER
    #endif
#endif

/* MODES */
#ifdef HITLS_CRYPTO_MODES
    #ifndef HITLS_CRYPTO_CTR
        #define HITLS_CRYPTO_CTR
    #endif
    #ifndef HITLS_CRYPTO_CBC
        #define HITLS_CRYPTO_CBC
    #endif
    #ifndef HITLS_CRYPTO_ECB
        #define HITLS_CRYPTO_ECB
    #endif
    #ifndef HITLS_CRYPTO_GCM
        #define HITLS_CRYPTO_GCM
    #endif
    #ifndef HITLS_CRYPTO_CCM
        #define HITLS_CRYPTO_CCM
    #endif
    #ifndef HITLS_CRYPTO_XTS
        #define HITLS_CRYPTO_XTS
    #endif
    #ifndef HITLS_CRYPTO_CFB
        #define HITLS_CRYPTO_CFB
    #endif
    #ifndef HITLS_CRYPTO_OFB
        #define HITLS_CRYPTO_OFB
    #endif
    #ifndef HITLS_CRYPTO_CHACHA20POLY1305
        #define HITLS_CRYPTO_CHACHA20POLY1305
    #endif
#endif

#if defined(HITLS_CRYPTO_CTR) || defined(HITLS_CRYPTO_CBC) || defined(HITLS_CRYPTO_GCM) || \
    defined(HITLS_CRYPTO_CCM) || defined(HITLS_CRYPTO_XTS) || defined(HITLS_CRYPTO_CFB) || \
    defined(HITLS_CRYPTO_OFB) || defined(HITLS_CRYPTO_CHACHA20POLY1305)
    #ifndef HITLS_CRYPTO_MODES
        #define HITLS_CRYPTO_MODES
    #endif
#endif

/* PKEY */
#ifdef HITLS_CRYPTO_PKEY
    #ifndef HITLS_CRYPTO_ECC
        #define HITLS_CRYPTO_ECC
    #endif
    #ifndef HITLS_CRYPTO_RSA
        #define HITLS_CRYPTO_RSA
    #endif
    #ifndef HITLS_CRYPTO_DSA
        #define HITLS_CRYPTO_DSA
    #endif
    #ifndef HITLS_CRYPTO_DH
        #define HITLS_CRYPTO_DH
    #endif
    #ifndef HITLS_CRYPTO_ECDSA
        #define HITLS_CRYPTO_ECDSA
    #endif
    #ifndef HITLS_CRYPTO_ECDH
        #define HITLS_CRYPTO_ECDH
    #endif
    #ifndef HITLS_CRYPTO_SM2
        #define HITLS_CRYPTO_SM2
    #endif
    #ifndef HITLS_CRYPTO_CURVE25519
        #define HITLS_CRYPTO_CURVE25519
    #endif
    #ifndef HITLS_CRYPTO_PAILLIER
        #define HITLS_CRYPTO_PAILLIER
    #endif
    #ifndef HITLS_CRYPTO_ELGAMAL
        #define HITLS_CRYPTO_ELGAMAL
    #endif
#endif

#ifdef HITLS_CRYPTO_ECC
    #ifndef HITLS_CRYPTO_CURVE_NISTP224
        #define HITLS_CRYPTO_CURVE_NISTP224
    #endif
    #ifndef HITLS_CRYPTO_CURVE_NISTP256
        #define HITLS_CRYPTO_CURVE_NISTP256
    #endif
    #ifndef HITLS_CRYPTO_CURVE_NISTP384
        #define HITLS_CRYPTO_CURVE_NISTP384
    #endif
    #ifndef HITLS_CRYPTO_CURVE_NISTP521
        #define HITLS_CRYPTO_CURVE_NISTP521
    #endif
    #ifndef HITLS_CRYPTO_CURVE_BP256R1
        #define HITLS_CRYPTO_CURVE_BP256R1
    #endif
    #ifndef HITLS_CRYPTO_CURVE_BP384R1
        #define HITLS_CRYPTO_CURVE_BP384R1
    #endif
    #ifndef HITLS_CRYPTO_CURVE_BP512R1
        #define HITLS_CRYPTO_CURVE_BP512R1
    #endif
    #ifndef HITLS_CRYPTO_CURVE_192WAPI
        #define HITLS_CRYPTO_CURVE_192WAPI
    #endif
    #ifndef HITLS_CRYPTO_CURVE_SM2
        #define HITLS_CRYPTO_CURVE_SM2
    #endif
#endif

#if defined(HITLS_CRYPTO_CURVE_NISTP224) || defined(HITLS_CRYPTO_CURVE_NISTP256) || \
    defined(HITLS_CRYPTO_CURVE_NISTP384) || defined(HITLS_CRYPTO_CURVE_NISTP521) || \
    defined(HITLS_CRYPTO_CURVE_BP256R1) || defined(HITLS_CRYPTO_CURVE_BP384R1) || \
    defined(HITLS_CRYPTO_CURVE_BP512R1) || defined(HITLS_CRYPTO_CURVE_192WAPI) || \
    defined(HITLS_CRYPTO_CURVE_SM2)
    #ifndef HITLS_CRYPTO_ECC
        #define HITLS_CRYPTO_ECC
    #endif
#endif

#ifdef HITLS_CRYPTO_CURVE25519
    #ifndef HITLS_CRYPTO_X25519
        #define HITLS_CRYPTO_X25519
    #endif
    #ifndef HITLS_CRYPTO_ED25519
        #define HITLS_CRYPTO_ED25519
    #endif
#endif

#if defined(HITLS_CRYPTO_ED25519) && !defined(HITLS_CRYPTO_SHA512)
    #define HITLS_CRYPTO_SHA512
#endif

#if defined(HITLS_CRYPTO_X25519) || defined(HITLS_CRYPTO_ED25519)
    #ifndef HITLS_CRYPTO_CURVE25519
        #define HITLS_CRYPTO_CURVE25519
    #endif
#endif

#ifdef HITLS_CRYPTO_SM2
    #ifndef HITLS_CRYPTO_SM2_SIGN
        #define HITLS_CRYPTO_SM2_SIGN
    #endif
    #ifndef HITLS_CRYPTO_SM2_CRYPT
        #define HITLS_CRYPTO_SM2_CRYPT
    #endif
    #ifndef HITLS_CRYPTO_SM2_EXCH
        #define HITLS_CRYPTO_SM2_EXCH
    #endif
#endif

#if defined(HITLS_CRYPTO_SM2_SIGN) || defined(HITLS_CRYPTO_SM2_CRYPT) || defined(HITLS_CRYPTO_SM2_EXCH)
    #ifndef HITLS_CRYPTO_SM2
        #define HITLS_CRYPTO_SM2
    #endif
#endif

#ifdef HITLS_CRYPTO_SM2
    #ifndef HITLS_CRYPTO_ENCODE
        #define HITLS_CRYPTO_ENCODE
    #endif
    #ifndef HITLS_CRYPTO_SM3
        #define HITLS_CRYPTO_SM3
    #endif
    #ifndef HITLS_CRYPTO_ECC
        #define HITLS_CRYPTO_ECC
    #endif
#endif

#if defined(HITLS_CRYPTO_SM2) && !defined(HITLS_CRYPTO_CURVE_SM2)
    #define HITLS_CRYPTO_CURVE_SM2
#endif

#if defined(HITLS_CRYPTO_ECDH) || defined(HITLS_CRYPTO_ECDSA)
    #ifndef HITLS_CRYPTO_ECC
        #define HITLS_CRYPTO_ECC
    #endif
#endif

#if defined(HITLS_CRYPTO_SM2)
    #define HITLS_CRYPTO_CURVE_SM2
#endif

#if defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ECDSA)
    #ifndef HITLS_CRYPTO_ENCODE
        #define HITLS_CRYPTO_ENCODE
    #endif
#endif

#if defined(HITLS_CRYPTO_ECC) || defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_DSA)|| defined(HITLS_CRYPTO_DH)
    #ifndef HITLS_CRYPTO_BN
        #define HITLS_CRYPTO_BN
    #endif
#endif

#if defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_CURVE25519) || defined(HITLS_CRYPTO_RSA) || \
    defined(HITLS_CRYPTO_DH) || defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_ECDH) ||      \
    defined(HITLS_CRYPTO_SM2) || defined(HITLS_CRYPTO_PAILLIER)|| defined(HITLS_CRYPTO_ELGAMAL)
    #ifndef HITLS_CRYPTO_PKEY
        #define HITLS_CRYPTO_PKEY
    #endif
#endif

#if defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE) && !defined(HITLS_CRYPTO_ECC)
    #undef HITLS_CRYPTO_NIST_ECC_ACCELERATE
#endif

#if defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE) && defined(__SIZEOF_INT128__) && (__SIZEOF_INT128__ == 16)
    #define HITLS_CRYPTO_NIST_USE_ACCEL
#endif

/* MD */
#ifdef HITLS_CRYPTO_MD
    #ifndef HITLS_CRYPTO_MD5
        #define HITLS_CRYPTO_MD5
    #endif
    #ifndef HITLS_CRYPTO_SM3
        #define HITLS_CRYPTO_SM3
    #endif
    #ifndef HITLS_CRYPTO_SHA1
        #define HITLS_CRYPTO_SHA1
    #endif
    #ifndef HITLS_CRYPTO_SHA2
        #define HITLS_CRYPTO_SHA2
    #endif
    #ifndef HITLS_CRYPTO_SHA3
        #define HITLS_CRYPTO_SHA3
    #endif
#endif

#ifdef HITLS_CRYPTO_SHA2
    #ifndef HITLS_CRYPTO_SHA224
        #define HITLS_CRYPTO_SHA224
    #endif
    #ifndef HITLS_CRYPTO_SHA256
        #define HITLS_CRYPTO_SHA256
    #endif
    #ifndef HITLS_CRYPTO_SHA384
        #define HITLS_CRYPTO_SHA384
    #endif
    #ifndef HITLS_CRYPTO_SHA512
        #define HITLS_CRYPTO_SHA512
    #endif
#endif

#if defined(HITLS_CRYPTO_SHA224) && !defined(HITLS_CRYPTO_SHA256)
    #define HITLS_CRYPTO_SHA256
#endif
#if defined(HITLS_CRYPTO_SHA384) && !defined(HITLS_CRYPTO_SHA512)
    #define HITLS_CRYPTO_SHA512
#endif

#if defined(HITLS_CRYPTO_SHA256) || defined(HITLS_CRYPTO_SHA512)
    #ifndef HITLS_CRYPTO_SHA2
        #define HITLS_CRYPTO_SHA2
    #endif
#endif

#if defined(HITLS_CRYPTO_MD5) || defined(HITLS_CRYPTO_SM3) || defined(HITLS_CRYPTO_SHA1) || \
    defined(HITLS_CRYPTO_SHA2) || defined(HITLS_CRYPTO_SHA3)
    #ifndef HITLS_CRYPTO_MD
        #define HITLS_CRYPTO_MD
    #endif
#endif

#if defined(HITLS_CRYPTO_MODES_X8664) && !defined(HITLS_CRYPTO_GCM_X8664)
    #define HITLS_CRYPTO_GCM_X8664
#endif

#if defined(HITLS_CRYPTO_MODES_ARMV8) && !defined(HITLS_CRYPTO_GCM_ARMV8)
    #define HITLS_CRYPTO_GCM_ARMV8
#endif

#if (defined(HITLS_CRYPTO_MODES_X8664) || defined(HITLS_CRYPTO_MODES_ARMV8)) && !defined(HITLS_CRYPTO_MODES_ASM)
#define HITLS_CRYPTO_MODES_ASM
#endif

#if (defined(HITLS_CRYPTO_GCM_X8664) || defined(HITLS_CRYPTO_GCM_ARMV8)) && !defined(HITLS_CRYPTO_GCM_ASM)
#define HITLS_CRYPTO_GCM_ASM
#endif

#if (defined(HITLS_CRYPTO_AES_X8664) || defined(HITLS_CRYPTO_AES_ARMV8) || defined(HITLS_CRYPTO_AES_RISCV64)) && !defined(HITLS_CRYPTO_AES_ASM)
#define HITLS_CRYPTO_AES_ASM
#endif

#if (defined(HITLS_CRYPTO_SM4_X8664) || defined(HITLS_CRYPTO_SM4_ARMV8) || defined(HITLS_CRYPTO_SM4_RISCV64)) && !defined(HITLS_CRYPTO_SM4_ASM)
#define HITLS_CRYPTO_SM4_ASM
#endif

#if defined(HITLS_CRYPTO_SHA1_X8664) && !defined(HITLS_CRYPTO_SHA1_ASM)
#define HITLS_CRYPTO_SHA1_ASM
#endif

#if (defined(HITLS_CRYPTO_SHA2_X8664) || defined(HITLS_CRYPTO_SHA2_RISCV64)) && !defined(HITLS_CRYPTO_SHA2_ASM)
#define HITLS_CRYPTO_SHA2_ASM
#endif

#if defined(HITLS_CRYPTO_MD5_X8664) && !defined(HITLS_CRYPTO_MD5_ASM)
#define HITLS_CRYPTO_MD5_ASM
#endif

#if defined(HITLS_CRYPTO_SM3_X8664) && !defined(HITLS_CRYPTO_SM3_ASM)
#define HITLS_CRYPTO_SM3_ASM
#endif

#if defined(HITLS_CRYPTO_ECC_X8664) && !defined(HITLS_CRYPTO_CURVE_NISTP256_X8664)
    #define HITLS_CRYPTO_CURVE_NISTP256_X8664
#endif

#if defined(HITLS_CRYPTO_ECC_X8664) && !defined(HITLS_CRYPTO_ECC_ASM)
#define HITLS_CRYPTO_ECC_ASM
#endif

#if defined(HITLS_CRYPTO_CURVE_NISTP256_X8664) && !defined(HITLS_CRYPTO_CURVE_NISTP256_ASM)
#define HITLS_CRYPTO_CURVE_NISTP256_ASM
#endif

#endif /* HITLS_CONFIG_LAYER_CRYPTO_H */
