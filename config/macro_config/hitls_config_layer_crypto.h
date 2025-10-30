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

#ifdef HITLS_CRYPTO_CODECSKEY
    #ifndef HITLS_CRYPTO_KEY_ENCODE
        #define HITLS_CRYPTO_KEY_ENCODE
    #endif
    #ifndef HITLS_CRYPTO_KEY_DECODE
        #define HITLS_CRYPTO_KEY_DECODE
    #endif
    #ifndef HITLS_CRYPTO_KEY_EPKI
        #define HITLS_CRYPTO_KEY_EPKI
    #endif
    #ifndef HITLS_CRYPTO_KEY_INFO
        #define HITLS_CRYPTO_KEY_INFO
    #endif
#endif

#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
    #ifndef HITLS_CRYPTO_KEY_DECODE
        #define HITLS_CRYPTO_KEY_DECODE
    #endif
    #ifndef HITLS_CRYPTO_CODECS
        #define HITLS_CRYPTO_CODECS
    #endif
#endif

#ifdef HITLS_CRYPTO_KEY_EPKI
    #ifndef HITLS_CRYPTO_PBKDF2
        #define HITLS_CRYPTO_PBKDF2
    #endif
#endif

#ifdef HITLS_CRYPTO_KEY_INFO
    #ifndef HITLS_BSL_PRINT
        #define HITLS_BSL_PRINT
    #endif
#endif

#if defined(HITLS_CRYPTO_KEY_ENCODE) || defined(HITLS_CRYPTO_KEY_DECODE) || defined(HITLS_CRYPTO_KEY_EPKI) || \
    defined(HITLS_CRYPTO_KEY_INFO)
    #ifndef HITLS_CRYPTO_CODECSKEY
        #define HITLS_CRYPTO_CODECSKEY
    #endif
    #ifndef HITLS_BSL_ASN1
        #define HITLS_BSL_ASN1
    #endif
    #ifndef HITLS_BSL_OBJ_DEFAULT
        #define HITLS_BSL_OBJ_DEFAULT
    #endif
#endif

#ifdef HITLS_CRYPTO_CODECS
    #ifndef HITLS_CRYPTO_PROVIDER
        #define HITLS_CRYPTO_PROVIDER
    #endif
#endif

#ifdef HITLS_CRYPTO_PROVIDER
    #ifndef HITLS_BSL_PARAMS
        #define HITLS_BSL_PARAMS
    #endif
#endif

/* kdf */
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
    #ifndef HITLS_BSL_PARAMS
        #define HITLS_BSL_PARAMS
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
    #ifndef HITLS_CRYPTO_HMAC
        #define HITLS_CRYPTO_HMAC
    #endif
    #ifndef HITLS_BSL_PARAMS
        #define HITLS_BSL_PARAMS
    #endif
#endif

/* DRBG */
#if defined(HITLS_CRYPTO_ENTROPY) && !defined(HITLS_BSL_LIST)
    #define HITLS_BSL_LIST
#endif

#if defined(HITLS_CRYPTO_ENTROPY) && !defined(HITLS_CRYPTO_ENTROPY_GETENTROPY) && \
    !defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM) && !defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    !defined(HITLS_CRYPTO_ENTROPY_HARDWARE)
#define HITLS_CRYPTO_ENTROPY_DEVRANDOM
#endif

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

#if defined(HITLS_CRYPTO_DRBG_HASH) || defined(HITLS_CRYPTO_DRBG_HMAC) || defined(HITLS_CRYPTO_DRBG_CTR)
    #ifndef HITLS_CRYPTO_DRBG
        #define HITLS_CRYPTO_DRBG
    #endif
    #ifndef HITLS_BSL_PARAMS
        #define HITLS_BSL_PARAMS
    #endif
#endif

#if defined(HITLS_CRYPTO_DRBG) && !defined(HITLS_BSL_SAL_PID)
    #define HITLS_BSL_SAL_PID
#endif

#if defined(HITLS_CRYPTO_DRBG_GM) && !defined(HITLS_BSL_SAL_TIME)
    #define HITLS_BSL_SAL_TIME
#endif
/* MAC */
#ifdef HITLS_CRYPTO_MAC
    #ifndef HITLS_CRYPTO_HMAC
        #define HITLS_CRYPTO_HMAC
    #endif
    #ifndef HITLS_CRYPTO_CMAC
        #define HITLS_CRYPTO_CMAC
    #endif
    #ifndef HITLS_CRYPTO_GMAC
        #define HITLS_CRYPTO_GMAC
    #endif
    #ifndef HITLS_CRYPTO_SIPHASH
        #define HITLS_CRYPTO_SIPHASH
    #endif
    #ifndef HITLS_CRYPTO_CBC_MAC
        #define HITLS_CRYPTO_CBC_MAC
    #endif
#endif

#if defined(HITLS_CRYPTO_CBC_MAC) && !defined(HITLS_CRYPTO_SM4)
    #define HITLS_CRYPTO_SM4
#endif

#ifdef HITLS_CRYPTO_GMAC
    #ifndef HITLS_CRYPTO_EAL
        #define HITLS_CRYPTO_EAL
    #endif
    #ifndef HITLS_CRYPTO_AES
        #define HITLS_CRYPTO_AES
    #endif
    #ifndef HITLS_CRYPTO_GCM
        #define HITLS_CRYPTO_GCM
    #endif
#endif

#ifdef HITLS_CRYPTO_CMAC
    #ifndef HITLS_CRYPTO_CMAC_AES
        #define HITLS_CRYPTO_CMAC_AES
    #endif
    #ifndef HITLS_CRYPTO_CMAC_SM4
        #define HITLS_CRYPTO_CMAC_SM4
    #endif
#endif
#if defined(HITLS_CRYPTO_CMAC_AES) && !defined(HITLS_CRYPTO_AES)
    #define HITLS_CRYPTO_AES
#endif
#if defined(HITLS_CRYPTO_CMAC_SM4) && !defined(HITLS_CRYPTO_SM4)
    #define HITLS_CRYPTO_SM4
#endif
#if defined(HITLS_CRYPTO_CMAC_AES) || defined(HITLS_CRYPTO_CMAC_SM4)
    #ifndef HITLS_CRYPTO_CMAC
        #define HITLS_CRYPTO_CMAC
    #endif
#endif

#if defined(HITLS_CRYPTO_HMAC) || defined(HITLS_CRYPTO_CMAC) || defined(HITLS_CRYPTO_GMAC) || \
    defined(HITLS_CRYPTO_SIPHASH) || defined(HITLS_CRYPTO_CBC_MAC)
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
    #ifndef HITLS_CRYPTO_HCTR
        #define HITLS_CRYPTO_HCTR
    #endif
#endif

#if defined(HITLS_CRYPTO_CTR) || defined(HITLS_CRYPTO_CBC) || defined(HITLS_CRYPTO_ECB) || \
    defined(HITLS_CRYPTO_GCM) || defined(HITLS_CRYPTO_CCM) || defined(HITLS_CRYPTO_XTS) || \
    defined(HITLS_CRYPTO_CFB) || defined(HITLS_CRYPTO_OFB) || defined(HITLS_CRYPTO_CHACHA20POLY1305) || \
    defined(HITLS_CRYPTO_HCTR)
    #ifndef HITLS_CRYPTO_MODES
        #define HITLS_CRYPTO_MODES
    #endif
#endif

/* PKEY */
#ifdef HITLS_CRYPTO_PKEY
    #ifndef HITLS_CRYPTO_PKEY_CMP
        #define HITLS_CRYPTO_PKEY_CMP
    #endif
    #ifndef HITLS_CRYPTO_ECC
        #define HITLS_CRYPTO_ECC
    #endif
    #ifndef HITLS_CRYPTO_DSA
        #define HITLS_CRYPTO_DSA
    #endif
    #ifndef HITLS_CRYPTO_RSA
        #define HITLS_CRYPTO_RSA
    #endif
    #ifndef HITLS_CRYPTO_RSA_BSSA
        #define HITLS_CRYPTO_RSA_BSSA
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
    #ifndef HITLS_CRYPTO_SM9
        #define HITLS_CRYPTO_SM9
    #endif
    #ifndef HITLS_CRYPTO_CURVE25519
        #define HITLS_CRYPTO_CURVE25519
    #endif
    #ifndef HITLS_CRYPTO_MLKEM
        #define HITLS_CRYPTO_MLKEM
    #endif
    #ifndef HITLS_CRYPTO_HYBRIDKEM
        #define HITLS_CRYPTO_HYBRIDKEM
    #endif
    #ifndef HITLS_CRYPTO_MLDSA
        #define HITLS_CRYPTO_MLDSA
    #endif
    #ifndef HITLS_CRYPTO_PAILLIER
        #define HITLS_CRYPTO_PAILLIER
    #endif
    #ifndef HITLS_CRYPTO_ELGAMAL
        #define HITLS_CRYPTO_ELGAMAL
    #endif
    #ifndef HITLS_CRYPTO_SLH_DSA
        #define HITLS_CRYPTO_SLH_DSA
    #endif
    #ifndef HITLS_CRYPTO_XMSS
        #define HITLS_CRYPTO_XMSS
    #endif
#endif

#ifdef HITLS_CRYPTO_RSA
    #ifndef HITLS_CRYPTO_RSA_SIGN
        #define HITLS_CRYPTO_RSA_SIGN
    #endif
    #ifndef HITLS_CRYPTO_RSA_VERIFY
        #define HITLS_CRYPTO_RSA_VERIFY
    #endif
    #ifndef HITLS_CRYPTO_RSA_RECOVER
        #define HITLS_CRYPTO_RSA_RECOVER
    #endif
    #ifndef HITLS_CRYPTO_RSA_ENCRYPT
        #define HITLS_CRYPTO_RSA_ENCRYPT
    #endif
    #ifndef HITLS_CRYPTO_RSA_DECRYPT
        #define HITLS_CRYPTO_RSA_DECRYPT
    #endif
    #ifndef HITLS_CRYPTO_RSA_BLINDING
        #define HITLS_CRYPTO_RSA_BLINDING
    #endif
    #ifndef HITLS_CRYPTO_RSA_GEN
        #define HITLS_CRYPTO_RSA_GEN
    #endif
    #ifndef HITLS_CRYPTO_RSA_PAD
        #define HITLS_CRYPTO_RSA_PAD
    #endif
    #ifndef HITLS_CRYPTO_RSA_CHECK
        #define HITLS_CRYPTO_RSA_CHECK
    #endif
#endif

#ifdef HITLS_CRYPTO_RSA_BSSA
    #ifndef HITLS_CRYPTO_RSA_EMSA_PSS
        #define HITLS_CRYPTO_RSA_EMSA_PSS
    #endif
    #ifndef HITLS_CRYPTO_RSA_BLINDING
        #define HITLS_CRYPTO_RSA_BLINDING
    #endif
#endif

#ifdef HITLS_CRYPTO_RSA_GEN
    #ifndef HITLS_CRYPTO_BN_RAND
        #define HITLS_CRYPTO_BN_RAND
    #endif
    #ifndef HITLS_CRYPTO_BN_PRIME
        #define HITLS_CRYPTO_BN_PRIME
    #endif
#endif

#if defined(HITLS_CRYPTO_RSA_BLINDING) && !defined(HITLS_CRYPTO_BN_RAND)
    #define HITLS_CRYPTO_BN_RAND
#endif

#ifdef HITLS_CRYPTO_RSA_CHECK
    #ifndef HITLS_CRYPTO_BN_RAND
        #define HITLS_CRYPTO_BN_RAND
    #endif
    #ifndef HITLS_CRYPTO_BN_PRIME
        #define HITLS_CRYPTO_BN_PRIME
    #endif
#endif

#ifdef HITLS_CRYPTO_RSA_PAD
    #ifndef HITLS_CRYPTO_RSA_EMSA_PSS
        #define HITLS_CRYPTO_RSA_EMSA_PSS
    #endif
    #ifndef HITLS_CRYPTO_RSA_EMSA_PKCSV15
        #define HITLS_CRYPTO_RSA_EMSA_PKCSV15
    #endif
    #ifndef HITLS_CRYPTO_RSAES_OAEP
        #define HITLS_CRYPTO_RSAES_OAEP
    #endif
    #ifndef HITLS_CRYPTO_RSAES_PKCSV15
        #define HITLS_CRYPTO_RSAES_PKCSV15
    #endif
    #ifndef HITLS_CRYPTO_RSAES_PKCSV15_TLS
        #define HITLS_CRYPTO_RSAES_PKCSV15_TLS
    #endif
    #ifndef HITLS_CRYPTO_RSA_NO_PAD
        #define HITLS_CRYPTO_RSA_NO_PAD
    #endif
#endif

#if defined(HITLS_CRYPTO_RSA_EMSA_PSS) || defined(HITLS_CRYPTO_RSA_EMSA_PKCSV15) || \
    defined(HITLS_CRYPTO_RSAES_OAEP) || defined(HITLS_CRYPTO_RSAES_PKCSV15) || \
    defined(HITLS_CRYPTO_RSAES_PKCSV15_TLS) || defined(HITLS_CRYPTO_RSA_NO_PAD)
    #ifndef HITLS_CRYPTO_RSA_PAD
        #define HITLS_CRYPTO_RSA_PAD
    #endif
#endif

#if defined(HITLS_CRYPTO_RSA_RECOVER) && !defined(HITLS_CRYPTO_RSA_VERIFY)
    #define HITLS_CRYPTO_RSA_VERIFY
#endif

#if defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY) || defined(HITLS_CRYPTO_RSA_RECOVER) || \
    defined(HITLS_CRYPTO_RSA_ENCRYPT) || defined(HITLS_CRYPTO_RSA_DECRYPT) || \
    defined(HITLS_CRYPTO_RSA_BLINDING) || defined(HITLS_CRYPTO_RSA_PAD) || defined(HITLS_CRYPTO_RSA_GEN)
    #ifndef HITLS_CRYPTO_RSA
        #define HITLS_CRYPTO_RSA
    #endif

    // rsa common dependency
    #ifndef HITLS_CRYPTO_BN_BASIC
        #define HITLS_CRYPTO_BN_BASIC
    #endif
#endif

#ifdef HITLS_CRYPTO_CURVE25519
    #ifndef HITLS_CRYPTO_X25519
        #define HITLS_CRYPTO_X25519
    #endif
    #ifndef HITLS_CRYPTO_ED25519
        #define HITLS_CRYPTO_ED25519
    #endif
    #ifndef HITLS_CRYPTO_X25519_CHECK
        #define HITLS_CRYPTO_X25519_CHECK
    #endif
    #ifndef HITLS_CRYPTO_ED25519_CHECK
        #define HITLS_CRYPTO_ED25519_CHECK
    #endif
#endif

#if defined(HITLS_CRYPTO_ED25519) && !defined(HITLS_CRYPTO_SHA512)
    #define HITLS_CRYPTO_SHA512
#endif

#if (defined(HITLS_CRYPTO_X25519) || defined(HITLS_CRYPTO_ED25519)) && !defined(HITLS_CRYPTO_CURVE25519)
    #define HITLS_CRYPTO_CURVE25519
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
    #ifndef HITLS_CRYPTO_SM3
        #define HITLS_CRYPTO_SM3
    #endif
    #ifndef HITLS_CRYPTO_CURVE_SM2
        #define HITLS_CRYPTO_CURVE_SM2
    #endif
    #ifndef HITLS_CRYPTO_SM2_CHECK
        #define HITLS_CRYPTO_SM2_CHECK
    #endif
#endif

#if defined(HITLS_CRYPTO_SM9_SIGN) || defined(HITLS_CRYPTO_SM9_CRYPT) || defined(HITLS_CRYPTO_SM9_EXCH)
    #ifndef HITLS_CRYPTO_SM9
        #define HITLS_CRYPTO_SM9
    #endif
#endif

#ifdef HITLS_CRYPTO_SM9
    #ifndef HITLS_CRYPTO_SM3
        #define HITLS_CRYPTO_SM3
    #endif
    #ifndef HITLS_CRYPTO_SM9_SIGN
        #define HITLS_CRYPTO_SM9_SIGN
    #endif
    #ifndef HITLS_CRYPTO_SM9_CRYPT
        #define HITLS_CRYPTO_SM9_CRYPT
    #endif
    #ifndef HITLS_CRYPTO_SM9_EXCH
        #define HITLS_CRYPTO_SM9_EXCH
    #endif
    #ifndef HITLS_CRYPTO_SM9_CHECK
        #define HITLS_CRYPTO_SM9_CHECK
    #endif
#endif

#ifdef HITLS_CRYPTO_XMSS
    #ifndef HITLS_CRYPTO_SLH_DSA
        #define HITLS_CRYPTO_SLH_DSA
    #endif
#endif

#ifdef HITLS_CRYPTO_SLH_DSA
    #ifndef HITLS_CRYPTO_SHA2
        #define HITLS_CRYPTO_SHA2
    #endif
    #ifndef HITLS_CRYPTO_SHA3
        #define HITLS_CRYPTO_SHA3
    #endif
    #ifndef HITLS_BSL_OBJ_DEFAULT
        #define HITLS_BSL_OBJ_DEFAULT
    #endif
    #ifndef HITLS_CRYPTO_EAL
        #define HITLS_CRYPTO_EAL
    #endif
    #ifndef HITLS_CRYPTO_HMAC
        #define HITLS_CRYPTO_HMAC
    #endif
    #ifndef HITLS_CRYPTO_SHA256
        #define HITLS_CRYPTO_SHA256
    #endif
    #ifndef HITLS_CRYPTO_SHA512
        #define HITLS_CRYPTO_SHA512
    #endif
    #ifndef HITLS_CRYPTO_SLH_DSA_CHECK
        #define HITLS_CRYPTO_SLH_DSA_CHECK
    #endif
#endif

#if defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_ELGAMAL)
    #ifndef HITLS_CRYPTO_BN_RAND
        #define HITLS_CRYPTO_BN_RAND
    #endif
    #ifndef HITLS_CRYPTO_BN_PRIME
        #define HITLS_CRYPTO_BN_PRIME
    #endif
#endif

#if defined(HITLS_CRYPTO_HYBRIDKEM) && !defined(HITLS_CRYPTO_MLKEM)
    #define HITLS_CRYPTO_MLKEM
#endif

#ifdef HITLS_CRYPTO_MLKEM
    #ifndef HITLS_CRYPTO_SHA3
        #define HITLS_CRYPTO_SHA3
    #endif
    #ifndef HITLS_CRYPTO_MLKEM_CHECK
        #define HITLS_CRYPTO_MLKEM_CHECK
    #endif
#endif

#ifdef HITLS_CRYPTO_MLDSA
    #ifndef HITLS_CRYPTO_SHA3
        #define HITLS_CRYPTO_SHA3
    #endif
    #ifndef HITLS_BSL_OBJ_DEFAULT
        #define HITLS_BSL_OBJ_DEFAULT
    #endif
    #ifndef HITLS_CRYPTO_MLDSA_CHECK
        #define HITLS_CRYPTO_MLDSA_CHECK
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
    #ifndef HITLS_CRYPTO_CURVE_SM2
        #define HITLS_CRYPTO_CURVE_SM2
    #endif
    #ifndef HITLS_CRYPTO_ECC_CHECK
        #define HITLS_CRYPTO_ECC_CHECK
    #endif
#endif

#if defined(HITLS_CRYPTO_CURVE_NISTP224) || defined(HITLS_CRYPTO_CURVE_NISTP256) || \
    defined(HITLS_CRYPTO_CURVE_NISTP384) || defined(HITLS_CRYPTO_CURVE_NISTP521) || \
    defined(HITLS_CRYPTO_CURVE_BP256R1) || defined(HITLS_CRYPTO_CURVE_BP384R1) || \
    defined(HITLS_CRYPTO_CURVE_BP512R1) || defined(HITLS_CRYPTO_CURVE_SM2)
    #ifndef HITLS_CRYPTO_ECC
        #define HITLS_CRYPTO_ECC
    #endif
    #ifndef HITLS_CRYPTO_BN_RAND
        #define HITLS_CRYPTO_BN_RAND
    #endif
#endif

#if defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE) && !defined(HITLS_CRYPTO_ECC)
    #undef HITLS_CRYPTO_NIST_ECC_ACCELERATE // Avoid turning on unnecessary functions.
#endif

#if defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE) && defined(__SIZEOF_INT128__) && (__SIZEOF_INT128__ == 16)
    #define HITLS_CRYPTO_NIST_USE_ACCEL
#endif

#if defined(HITLS_CRYPTO_DSA_GEN_PARA) && !defined(HITLS_CRYPTO_DSA)
    #define HITLS_CRYPTO_DSA
#endif

#if defined(HITLS_CRYPTO_ECDH) && !defined(HITLS_CRYPTO_ECDH_CHECK)
    #define HITLS_CRYPTO_ECDH_CHECK
#endif

#if defined(HITLS_CRYPTO_ECDSA) && !defined(HITLS_CRYPTO_ECDSA_CHECK)
    #define HITLS_CRYPTO_ECDSA_CHECK
#endif

#if defined(HITLS_CRYPTO_DH) && !defined(HITLS_CRYPTO_DH_CHECK)
    #define HITLS_CRYPTO_DH_CHECK
#endif

#if defined(HITLS_CRYPTO_DSA) && !defined(HITLS_CRYPTO_DSA_CHECK)
    #define HITLS_CRYPTO_DSA_CHECK
#endif

#if defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_CURVE25519) || defined(HITLS_CRYPTO_RSA) || \
    defined(HITLS_CRYPTO_DH) || defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_ECDH) ||      \
    defined(HITLS_CRYPTO_SM2) || defined(HITLS_CRYPTO_SM9) || defined(HITLS_CRYPTO_PAILLIER)|| defined(HITLS_CRYPTO_ELGAMAL) || \
    defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_MLKEM) || defined(HITLS_CRYPTO_HYBRIDKEM) || \
    defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_XMSS)
    #ifndef HITLS_CRYPTO_PKEY
        #define HITLS_CRYPTO_PKEY
    #endif
    #ifndef HITLS_BSL_PARAMS
        #define HITLS_BSL_PARAMS
    #endif
#endif

#if defined(HITLS_CRYPTO_X25519) || defined(HITLS_CRYPTO_DH) || defined(HITLS_CRYPTO_ECDH) || \
    defined(HITLS_CRYPTO_SM2_EXCH) || defined(HITLS_CRYPTO_SM9)
    #ifndef HITLS_CRYPTO_PKEY_EXCH
        #define HITLS_CRYPTO_PKEY_EXCH
    #endif
#endif

#if defined(HITLS_CRYPTO_RSA_ENCRYPT) || defined(HITLS_CRYPTO_RSA_DECRYPT) || defined(HITLS_CRYPTO_SM2_CRYPT) || \
    defined(HITLS_CRYPTO_SM9) || defined(HITLS_CRYPTO_PAILLIER) || defined(HITLS_CRYPTO_ELGAMAL)
    #ifndef HITLS_CRYPTO_PKEY_CRYPT
        #define HITLS_CRYPTO_PKEY_CRYPT
    #endif
#endif

#if defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY) || \
    defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2_SIGN) || defined(HITLS_CRYPTO_SM9) || defined(HITLS_CRYPTO_ED25519) || \
    defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_MLDSA)
    #ifndef HITLS_CRYPTO_PKEY_SIGN
        #define HITLS_CRYPTO_PKEY_SIGN
    #endif
#endif

#if (defined(HITLS_CRYPTO_MLKEM) || defined(HITLS_CRYPTO_HYBRIDKEM)) && !defined(HITLS_CRYPTO_PKEY_KEM)
    #define HITLS_CRYPTO_PKEY_KEM
#endif

#ifdef HITLS_CRYPTO_PKEY_CMP
    #if defined(HITLS_CRYPTO_RSA) && !defined(HITLS_CRYPTO_RSA_CMP)
        #define HITLS_CRYPTO_RSA_CMP
    #endif
    #if defined(HITLS_CRYPTO_DSA) && !defined(HITLS_CRYPTO_DSA_CMP)
        #define HITLS_CRYPTO_DSA_CMP
    #endif
    #if defined(HITLS_CRYPTO_DH) && !defined(HITLS_CRYPTO_DH_CMP)
        #define HITLS_CRYPTO_DH_CMP
    #endif
    #if defined(HITLS_CRYPTO_ECDSA) && !defined(HITLS_CRYPTO_ECDSA_CMP)
        #define HITLS_CRYPTO_ECDSA_CMP
    #endif
    #if defined(HITLS_CRYPTO_ECDH) && !defined(HITLS_CRYPTO_ECDH_CMP)
        #define HITLS_CRYPTO_ECDH_CMP
    #endif
    #if defined(HITLS_CRYPTO_SM2) && !defined(HITLS_CRYPTO_SM2_CMP)
        #define HITLS_CRYPTO_SM2_CMP
    #endif
    #if defined(HITLS_CRYPTO_CURVE25519) && !defined(HITLS_CRYPTO_CURVE25519_CMP)
        #define HITLS_CRYPTO_CURVE25519_CMP
    #endif
    #if defined(HITLS_CRYPTO_MLDSA) && !defined(HITLS_CRYPTO_MLDSA_CMP)
        #define HITLS_CRYPTO_MLDSA_CMP
    #endif
    #if defined(HITLS_CRYPTO_MLKEM) && !defined(HITLS_CRYPTO_MLKEM_CMP)
        #define HITLS_CRYPTO_MLKEM_CMP
    #endif

    #if defined(HITLS_CRYPTO_ECDSA_CMP) || defined(HITLS_CRYPTO_ECDH_CMP) || defined(HITLS_CRYPTO_SM2_CMP)
        #ifndef HITLS_CRYPTO_ECC_CMP
            #define HITLS_CRYPTO_ECC_CMP
        #endif
    #endif
#endif

/* bn */
#ifdef HITLS_CRYPTO_BN
    #ifndef HITLS_CRYPTO_BN_BASIC
        #define HITLS_CRYPTO_BN_BASIC
    #endif
    #ifndef HITLS_CRYPTO_BN_RAND
        #define HITLS_CRYPTO_BN_RAND
    #endif
    #ifndef HITLS_CRYPTO_EAL_BN
        #define HITLS_CRYPTO_EAL_BN
    #endif
    #ifndef HITLS_CRYPTO_BN_PRIME
        #define HITLS_CRYPTO_BN_PRIME
    #endif
    #ifndef HITLS_CRYPTO_BN_STR_CONV
        #define HITLS_CRYPTO_BN_STR_CONV
    #endif
    #ifndef HITLS_CRYPTO_BN_CB
        #define HITLS_CRYPTO_BN_CB
    #endif
    #ifndef HITLS_CRYPTO_BN_PRIME_RFC3526
        #define HITLS_CRYPTO_BN_PRIME_RFC3526
    #endif
#endif

#if defined(HITLS_CRYPTO_BN_PRIME) && !defined(HITLS_CRYPTO_BN_RAND)
    #define HITLS_CRYPTO_BN_RAND
#endif

#if defined(HITLS_CRYPTO_BN_RAND) || defined(HITLS_CRYPTO_EAL_BN) || defined(HITLS_CRYPTO_BN_PRIME) || \
    defined(HITLS_CRYPTO_BN_STR_CONV) || defined(HITLS_CRYPTO_BN_CB) || defined(HITLS_CRYPTO_BN_PRIME_RFC3526) || \
    defined(HITLS_CRYPTO_BN_BASIC)
    #ifndef HITLS_CRYPTO_BN
        #define HITLS_CRYPTO_BN
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

/* Assembling Macros */
#if defined(HITLS_CRYPTO_AES_X8664) || defined(HITLS_CRYPTO_AES_ARMV8)
#define HITLS_CRYPTO_AES_ASM
#endif

#if defined(HITLS_CRYPTO_CHACHA20_X8664) || defined(HITLS_CRYPTO_CHACHA20_ARMV8)
#define HITLS_CRYPTO_CHACHA20_ASM
#endif

#if defined(HITLS_CRYPTO_SM4_X8664) || defined(HITLS_CRYPTO_SM4_ARMV8)
#define HITLS_CRYPTO_SM4_ASM
#endif

#if defined(HITLS_CRYPTO_MODES_X8664)
#define HITLS_CRYPTO_CHACHA20POLY1305_X8664
#define HITLS_CRYPTO_GCM_X8664
#endif

#if defined(HITLS_CRYPTO_MODES_ARMV8)
#define HITLS_CRYPTO_CHACHA20POLY1305_ARMV8
#define HITLS_CRYPTO_GCM_ARMV8
#endif

#if defined(HITLS_CRYPTO_MODES_X8664) || defined(HITLS_CRYPTO_MODES_ARMV8)
#define HITLS_CRYPTO_MODES_ASM
#endif

#if defined(HITLS_CRYPTO_CHACHA20POLY1305_X8664) || defined(HITLS_CRYPTO_CHACHA20POLY1305_ARMV8)
#define HITLS_CRYPTO_CHACHA20POLY1305_ASM
#endif

#if defined(HITLS_CRYPTO_GCM_X8664) || defined(HITLS_CRYPTO_GCM_ARMV8)
#define HITLS_CRYPTO_GCM_ASM
#endif

#if defined(HITLS_CRYPTO_MD5_X8664)
#define HITLS_CRYPTO_MD5_ASM
#endif

#if defined(HITLS_CRYPTO_SHA1_X8664) || defined(HITLS_CRYPTO_SHA1_ARMV8)
#define HITLS_CRYPTO_SHA1_ASM
#endif

#if defined(HITLS_CRYPTO_SHA224_X8664) || defined(HITLS_CRYPTO_SHA224_ARMV8) || \
    defined(HITLS_CRYPTO_SHA256_X8664) || defined(HITLS_CRYPTO_SHA256_ARMV8) || \
    defined(HITLS_CRYPTO_SHA384_X8664) || defined(HITLS_CRYPTO_SHA384_ARMV8) || \
    defined(HITLS_CRYPTO_SHA512_X8664) || defined(HITLS_CRYPTO_SHA512_ARMV8) || \
    defined(HITLS_CRYPTO_SHA2_X8664) || defined(HITLS_CRYPTO_SHA2_ARMV8)
#define HITLS_CRYPTO_SHA2_ASM
#endif

#if defined(HITLS_CRYPTO_SM3_X8664) || defined(HITLS_CRYPTO_SM3_ARMV8)
#define HITLS_CRYPTO_SM3_ASM
#endif

#if defined(HITLS_CRYPTO_BN_X8664) || defined(HITLS_CRYPTO_BN_ARMV8)
#define HITLS_CRYPTO_BN_ASM
#endif

#if defined(HITLS_CRYPTO_ECC_X8664)
#define HITLS_CRYPTO_CURVE_NISTP256_X8664
#define HITLS_CRYPTO_CURVE_SM2_X8664
#endif

#if defined(HITLS_CRYPTO_ECC_ARMV8)
#define HITLS_CRYPTO_CURVE_NISTP256_ARMV8
#define HITLS_CRYPTO_CURVE_SM2_ARMV8
#endif

#if defined(HITLS_CRYPTO_ECC_X8664) || defined(HITLS_CRYPTO_ECC_ARMV8)
#define HITLS_CRYPTO_ECC_ASM
#endif

#if defined(HITLS_CRYPTO_CURVE_NISTP256_X8664) || defined(HITLS_CRYPTO_CURVE_NISTP256_ARMV8)
#define HITLS_CRYPTO_CURVE_NISTP256_ASM
#endif

#if defined(HITLS_CRYPTO_CURVE_NISTP384_X8664) || defined(HITLS_CRYPTO_CURVE_NISTP384_ARMV8)
#define HITLS_CRYPTO_CURVE_NISTP384_ASM
#endif

#if defined(HITLS_CRYPTO_CURVE_SM2_X8664) || defined(HITLS_CRYPTO_CURVE_SM2_ARMV8)
#define HITLS_CRYPTO_CURVE_SM2_ASM
#endif

#if (!defined(HITLS_SIXTY_FOUR_BITS))
    #if (((defined(HITLS_CRYPTO_CURVE_NISTP224) || defined(HITLS_CRYPTO_CURVE_NISTP521)) && \
            !defined(HITLS_CRYPTO_NIST_USE_ACCEL)) || \
        defined(HITLS_CRYPTO_CURVE_NISTP384) || \
        (defined(HITLS_CRYPTO_CURVE_NISTP256) && !defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) &&  \
            (!defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE)) && (!defined(HITLS_CRYPTO_NIST_USE_ACCEL))) || \
        (defined(HITLS_CRYPTO_CURVE_SM2) && !defined(HITLS_CRYPTO_CURVE_SM2_ASM)))
            #define HITLS_CRYPTO_CURVE_MONT_NIST
    #endif
#endif

#if defined(HITLS_CRYPTO_CURVE_BP256R1) || defined(HITLS_CRYPTO_CURVE_BP384R1) || \
    defined(HITLS_CRYPTO_CURVE_BP512R1)
        #define HITLS_CRYPTO_CURVE_MONT_PRIME
#endif

#if defined(HITLS_CRYPTO_CURVE_MONT_PRIME) || defined(HITLS_CRYPTO_CURVE_MONT_NIST)
#define HITLS_CRYPTO_CURVE_MONT
#endif

#if defined(HITLS_CRYPTO_ECDSA_CHECK) || defined(HITLS_CRYPTO_ECDH_CHECK) || defined(HITLS_CRYPTO_SM2_CHECK)
    #ifndef HITLS_CRYPTO_ECC_CHECK
        #define HITLS_CRYPTO_ECC_CHECK
    #endif
#endif

#endif /* HITLS_CONFIG_LAYER_CRYPTO_H */
