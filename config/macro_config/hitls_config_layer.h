/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

#ifndef HITLS_CONFIG_LAYER_H
#define HITLS_CONFIG_LAYER_H

/* BSL_INIT */
#if defined(HITLS_CRYPTO_EAL) && !defined(HITLS_BSL_INIT)
    #define HITLS_BSL_INIT
#endif

#if defined(HITLS_BSL_INIT) && !defined(HITLS_BSL_ERR)
    #define HITLS_BSL_ERR
#endif

/* BSL_UIO */
/* Derive the child-features of uio. */
#ifdef HITLS_BSL_UIO
    #ifndef HITLS_BSL_UIO_PLT
        #define HITLS_BSL_UIO_PLT
    #endif
    #ifndef HITLS_BSL_UIO_BUFFER
        #define HITLS_BSL_UIO_BUFFER
    #endif
    #ifndef HITLS_BSL_UIO_SCTP
        #define HITLS_BSL_UIO_SCTP
    #endif
    #ifndef HITLS_BSL_UIO_TCP
        #define HITLS_BSL_UIO_TCP
    #endif
#endif

/* Derive the dependency features of uio_tcp and uio_sctp. */
#if defined(HITLS_BSL_UIO_TCP) || defined(HITLS_BSL_UIO_SCTP)
    #ifndef HITLS_BSL_SAL_NET
        #define HITLS_BSL_SAL_NET
    #endif
#endif

/* Derive parent feature from child features. */
#if defined(HITLS_BSL_UIO_BUFFER) || defined(HITLS_BSL_UIO_SCTP) || defined(HITLS_BSL_UIO_TCP)
    #ifndef HITLS_BSL_UIO_PLT
        #define HITLS_BSL_UIO_PLT
    #endif
#endif

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
    #ifndef HITLS_CRYPTO_CURVE448
        #define HITLS_CRYPTO_CURVE448
    #endif
    #ifndef HITLS_CRYPTO_CURVE25519
        #define HITLS_CRYPTO_CURVE25519
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
    #ifndef HITLS_CRYPTO_CURVE_SM9
        #define HITLS_CRYPTO_CURVE_SM9
    #endif
#endif

#if defined(HITLS_CRYPTO_CURVE_NISTP224) || defined(HITLS_CRYPTO_CURVE_NISTP256) || \
    defined(HITLS_CRYPTO_CURVE_NISTP384) || defined(HITLS_CRYPTO_CURVE_NISTP521) || \
    defined(HITLS_CRYPTO_CURVE_BP256R1) || defined(HITLS_CRYPTO_CURVE_BP384R1) || \
    defined(HITLS_CRYPTO_CURVE_BP512R1) || defined(HITLS_CRYPTO_CURVE_192WAPI) || \
    defined(HITLS_CRYPTO_CURVE_SM2) || defined(HITLS_CRYPTO_CURVE_SM9)
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

#ifdef HITLS_CRYPTO_CURVE448
    #ifndef HITLS_CRYPTO_X448
        #define HITLS_CRYPTO_X448
    #endif
    #ifndef HITLS_CRYPTO_ED448
        #define HITLS_CRYPTO_ED448
    #endif
#endif


#if defined(HITLS_CRYPTO_ED448) && !defined(HITLS_CRYPTO_SHA3)
    #define HITLS_CRYPTO_SHA3
#endif

#if defined(HITLS_CRYPTO_X448) || defined(HITLS_CRYPTO_ED448)
    #ifndef HITLS_CRYPTO_CURVE448
        #define HITLS_CRYPTO_CURVE448
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
    defined(HITLS_CRYPTO_SM2) || defined(HITLS_CRYPTO_CURVE448)
    #ifndef HITLS_CRYPTO_PKEY
        #define HITLS_CRYPTO_PKEY
    #endif
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

#if defined(HITLS_CRYPTO_MODES_X8664)
#define HITLS_CRYPTO_CHACHA20POLY1305_X8664
#define HITLS_CRYPTO_GCM_X8664
#endif

#if defined(HITLS_CRYPTO_MODES_ARMV8)
#define HITLS_CRYPTO_CHACHA20POLY1305_ARMV8
#define HITLS_CRYPTO_GCM_ARMV8
#endif

#if (defined(HITLS_CRYPTO_MODES_X8664) || defined(HITLS_CRYPTO_MODES_ARMV7) || defined(HITLS_CRYPTO_MODES_ARMV8)) && \
    !defined(HITLS_CRYPTO_MODES_ASM)
#define HITLS_CRYPTO_MODES_ASM
#endif

#endif /* HITLS_CONFIG_LAYER_H */
