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

#ifndef CRYPT_PARAMS_KEY_H
#define CRYPT_PARAMS_KEY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPT_PARAM_PKEY_BASE                               0
#define CRYPT_PARAM_PKEY_ENCODE_PUBKEY                      (CRYPT_PARAM_PKEY_BASE + 1)
#define CRYPT_PARAM_PKEY_PROCESS_FUNC                       (CRYPT_PARAM_PKEY_BASE + 2)
#define CRYPT_PARAM_PKEY_PROCESS_ARGS                       (CRYPT_PARAM_PKEY_BASE + 3)
#define CRYPT_PARAM_PKEY_HE_CIPHERTEXT1                     (CRYPT_PARAM_PKEY_BASE + 4)
#define CRYPT_PARAM_PKEY_HE_CIPHERTEXT2                     (CRYPT_PARAM_PKEY_BASE + 5)
#define CRYPT_PARAM_PKEY_SIG_PAD_MODE                       (CRYPT_PARAM_PKEY_BASE + 6)
#define CRYPT_PARAM_PKEY_SIG_PAD_DIGEST                     (CRYPT_PARAM_PKEY_BASE + 7)

#define CRYPT_PARAM_KDF_BASE                                100
#define CRYPT_PARAM_KDF_PASSWORD                            (CRYPT_PARAM_KDF_BASE + 1)
#define CRYPT_PARAM_KDF_MAC_ID                              (CRYPT_PARAM_KDF_BASE + 2)
#define CRYPT_PARAM_KDF_SALT                                (CRYPT_PARAM_KDF_BASE + 3)
#define CRYPT_PARAM_KDF_ITER                                (CRYPT_PARAM_KDF_BASE + 4)
#define CRYPT_PARAM_KDF_MODE                                (CRYPT_PARAM_KDF_BASE + 5)
#define CRYPT_PARAM_KDF_KEY                                 (CRYPT_PARAM_KDF_BASE + 6)
#define CRYPT_PARAM_KDF_PRK                                 (CRYPT_PARAM_KDF_BASE + 7)
#define CRYPT_PARAM_KDF_INFO                                (CRYPT_PARAM_KDF_BASE + 8)
#define CRYPT_PARAM_KDF_EXLEN                               (CRYPT_PARAM_KDF_BASE + 9)
#define CRYPT_PARAM_KDF_LABEL                               (CRYPT_PARAM_KDF_BASE + 11)
#define CRYPT_PARAM_KDF_SEED                                (CRYPT_PARAM_KDF_BASE + 12)
#define CRYPT_PARAM_KDF_N                                   (CRYPT_PARAM_KDF_BASE + 13)
#define CRYPT_PARAM_KDF_P                                   (CRYPT_PARAM_KDF_BASE + 14)
#define CRYPT_PARAM_KDF_R                                   (CRYPT_PARAM_KDF_BASE + 15)

#define CRYPT_PARAM_EC_BASE                                 200
#define CRYPT_PARAM_EC_PUBKEY                               (CRYPT_PARAM_EC_BASE + 1)
#define CRYPT_PARAM_EC_PRVKEY                               (CRYPT_PARAM_EC_BASE + 2)
#define CRYPT_PARAM_EC_P                                    (CRYPT_PARAM_EC_BASE + 3)
#define CRYPT_PARAM_EC_A                                    (CRYPT_PARAM_EC_BASE + 4)
#define CRYPT_PARAM_EC_B                                    (CRYPT_PARAM_EC_BASE + 5)
#define CRYPT_PARAM_EC_N                                    (CRYPT_PARAM_EC_BASE + 6)
#define CRYPT_PARAM_EC_H                                    (CRYPT_PARAM_EC_BASE + 7)
#define CRYPT_PARAM_EC_X                                    (CRYPT_PARAM_EC_BASE + 8)
#define CRYPT_PARAM_EC_Y                                    (CRYPT_PARAM_EC_BASE + 9)
#define CRYPT_PARAM_EC_CURVE_ID                             (CRYPT_PARAM_EC_BASE + 10)

#define CRYPT_PARAM_DH_BASE                                 300
#define CRYPT_PARAM_DH_PUBKEY                               (CRYPT_PARAM_DH_BASE + 1)
#define CRYPT_PARAM_DH_PRVKEY                               (CRYPT_PARAM_DH_BASE + 2)
#define CRYPT_PARAM_DH_P                                    (CRYPT_PARAM_DH_BASE + 3)
#define CRYPT_PARAM_DH_Q                                    (CRYPT_PARAM_DH_BASE + 4)
#define CRYPT_PARAM_DH_G                                    (CRYPT_PARAM_DH_BASE + 5)

#define CRYPT_PARAM_DSA_BASE                                400
#define CRYPT_PARAM_DSA_PUBKEY                              (CRYPT_PARAM_DSA_BASE + 1)
#define CRYPT_PARAM_DSA_PRVKEY                              (CRYPT_PARAM_DSA_BASE + 2)
#define CRYPT_PARAM_DSA_P                                   (CRYPT_PARAM_DSA_BASE + 3)
#define CRYPT_PARAM_DSA_Q                                   (CRYPT_PARAM_DSA_BASE + 4)
#define CRYPT_PARAM_DSA_G                                   (CRYPT_PARAM_DSA_BASE + 5)
#define CRYPT_PARAM_DSA_ALGID                               (CRYPT_PARAM_DSA_BASE + 6)
#define CRYPT_PARAM_DSA_PBITS                               (CRYPT_PARAM_DSA_BASE + 7)
#define CRYPT_PARAM_DSA_QBITS                               (CRYPT_PARAM_DSA_BASE + 8)
#define CRYPT_PARAM_DSA_SEEDLEN                             (CRYPT_PARAM_DSA_BASE + 9)
#define CRYPT_PARAM_DSA_GINDEX                              (CRYPT_PARAM_DSA_BASE + 10)

#define CRYPT_PARAM_PAILLIER_BASE                           500
#define CRYPT_PARAM_PAILLIER_N                              (CRYPT_PARAM_PAILLIER_BASE + 1)
#define CRYPT_PARAM_PAILLIER_G                              (CRYPT_PARAM_PAILLIER_BASE + 2)
#define CRYPT_PARAM_PAILLIER_N2                             (CRYPT_PARAM_PAILLIER_BASE + 3)
#define CRYPT_PARAM_PAILLIER_LAMBDA                         (CRYPT_PARAM_PAILLIER_BASE + 4)
#define CRYPT_PARAM_PAILLIER_MU                             (CRYPT_PARAM_PAILLIER_BASE + 5)
#define CRYPT_PARAM_PAILLIER_P                              (CRYPT_PARAM_PAILLIER_BASE + 6)
#define CRYPT_PARAM_PAILLIER_Q                              (CRYPT_PARAM_PAILLIER_BASE + 7)
#define CRYPT_PARAM_PAILLIER_BITS                           (CRYPT_PARAM_PAILLIER_BASE + 8)

#define CRYPT_PARAM_RAND_BASE                               600
#define CRYPT_PARAM_RAND_SEEDCTX                            (CRYPT_PARAM_RAND_BASE + 1)
#define CRYPT_PARAM_RAND_PR                                 (CRYPT_PARAM_RAND_BASE + 2)
#define CRYPT_PARAM_RAND_SEED_GETENTROPY                    (CRYPT_PARAM_RAND_BASE + 3)
#define CRYPT_PARAM_RAND_SEED_CLEANENTROPY                  (CRYPT_PARAM_RAND_BASE + 4)
#define CRYPT_PARAM_RAND_SEED_GETNONCE                      (CRYPT_PARAM_RAND_BASE + 5)
#define CRYPT_PARAM_RAND_SEED_CLEANNONCE                    (CRYPT_PARAM_RAND_BASE + 6)
#define CRYPT_PARAM_RAND_RESEED_INTERVAL                    (CRYPT_PARAM_RAND_BASE + 7)
#define CRYPT_PARAM_RAND_RESEED_TIME                        (CRYPT_PARAM_RAND_BASE + 8)

#define CRYPT_PARAM_CURVE25519_BASE                         700
#define CRYPT_PARAM_CURVE25519_PUBKEY                       (CRYPT_PARAM_CURVE25519_BASE + 1)
#define CRYPT_PARAM_CURVE25519_PRVKEY                       (CRYPT_PARAM_CURVE25519_BASE + 2)

#define CRYPT_PARAM_ELGAMAL_BASE                            800
#define CRYPT_PARAM_ELGAMAL_P                               (CRYPT_PARAM_ELGAMAL_BASE + 1)
#define CRYPT_PARAM_ELGAMAL_G                               (CRYPT_PARAM_ELGAMAL_BASE + 2)
#define CRYPT_PARAM_ELGAMAL_X                               (CRYPT_PARAM_ELGAMAL_BASE + 3)
#define CRYPT_PARAM_ELGAMAL_Y                               (CRYPT_PARAM_ELGAMAL_BASE + 4)
#define CRYPT_PARAM_ELGAMAL_Q                               (CRYPT_PARAM_ELGAMAL_BASE + 5)
#define CRYPT_PARAM_ELGAMAL_BITS                            (CRYPT_PARAM_ELGAMAL_BASE + 6)
#define CRYPT_PARAM_ELGAMAL_KBITS                           (CRYPT_PARAM_ELGAMAL_BASE + 7)

#define CRYPT_PARAM_RSA_BASE                                900
#define CRYPT_PARAM_RSA_N                                   (CRYPT_PARAM_RSA_BASE + 1)
#define CRYPT_PARAM_RSA_E                                   (CRYPT_PARAM_RSA_BASE + 2)
#define CRYPT_PARAM_RSA_D                                   (CRYPT_PARAM_RSA_BASE + 3)
#define CRYPT_PARAM_RSA_P                                   (CRYPT_PARAM_RSA_BASE + 4)
#define CRYPT_PARAM_RSA_Q                                   (CRYPT_PARAM_RSA_BASE + 5)
#define CRYPT_PARAM_RSA_DQ                                  (CRYPT_PARAM_RSA_BASE + 6)
#define CRYPT_PARAM_RSA_DP                                  (CRYPT_PARAM_RSA_BASE + 7)
#define CRYPT_PARAM_RSA_QINV                                (CRYPT_PARAM_RSA_BASE + 8)
#define CRYPT_PARAM_RSA_BITS                                (CRYPT_PARAM_RSA_BASE + 9)
#define CRYPT_PARAM_RSA_SALTLEN                             (CRYPT_PARAM_RSA_BASE + 10)
#define CRYPT_PARAM_RSA_MD_ID                               (CRYPT_PARAM_RSA_BASE + 11)
#define CRYPT_PARAM_RSA_MGF1_ID                             (CRYPT_PARAM_RSA_BASE + 12)
#define CRYPT_PARAM_RSA_XP                                  (CRYPT_PARAM_RSA_BASE + 13)
#define CRYPT_PARAM_RSA_XQ                                  (CRYPT_PARAM_RSA_BASE + 14)
#define CRYPT_PARAM_RSA_XP1                                 (CRYPT_PARAM_RSA_BASE + 15)
#define CRYPT_PARAM_RSA_XP2                                 (CRYPT_PARAM_RSA_BASE + 16)
#define CRYPT_PARAM_RSA_XQ1                                 (CRYPT_PARAM_RSA_BASE + 17)
#define CRYPT_PARAM_RSA_XQ2                                 (CRYPT_PARAM_RSA_BASE + 18)

#define CRYPT_PARAM_ML_KEM_BASE                             1400
#define CRYPT_PARAM_ML_KEM_PRVKEY                           (CRYPT_PARAM_ML_KEM_BASE + 1)
#define CRYPT_PARAM_ML_KEM_PUBKEY                           (CRYPT_PARAM_ML_KEM_BASE + 2)
#define CRYPT_PARAM_ML_KEM_PRVKEY_SEED                      (CRYPT_PARAM_ML_KEM_BASE + 3)

#define CRYPT_PARAM_ML_DSA_BASE                             1500
#define CRYPT_PARAM_ML_DSA_PRVKEY                           (CRYPT_PARAM_ML_DSA_BASE + 1)
#define CRYPT_PARAM_ML_DSA_PUBKEY                           (CRYPT_PARAM_ML_DSA_BASE + 2)
#define CRYPT_PARAM_ML_DSA_PRVKEY_SEED                      (CRYPT_PARAM_ML_DSA_BASE + 3)

#define CRYPT_PARAM_HYBRID_BASE                             1600
#define CRYPT_PARAM_HYBRID_PRVKEY                           (CRYPT_PARAM_HYBRID_BASE + 1)
#define CRYPT_PARAM_HYBRID_PUBKEY                           (CRYPT_PARAM_HYBRID_BASE + 2)

#define CRYPT_PARAM_SLH_DSA_BASE                            1700
#define CRYPT_PARAM_SLH_DSA_PRV_SEED                        (CRYPT_PARAM_SLH_DSA_BASE + 1)
#define CRYPT_PARAM_SLH_DSA_PRV_PRF                         (CRYPT_PARAM_SLH_DSA_BASE + 2)
#define CRYPT_PARAM_SLH_DSA_PUB_SEED                        (CRYPT_PARAM_SLH_DSA_BASE + 3)
#define CRYPT_PARAM_SLH_DSA_PUB_ROOT                        (CRYPT_PARAM_SLH_DSA_BASE + 4)

#define CRYPT_PARAM_MD_BASE                                 1800
#define CRYPT_PARAM_MD_DIGEST_SIZE                          (CRYPT_PARAM_MD_BASE + 1)
#define CRYPT_PARAM_MD_BLOCK_SIZE                           (CRYPT_PARAM_MD_BASE + 2)
#define CRYPT_PARAM_MD_ATTR                                 (CRYPT_PARAM_MD_BASE + 3)

#define CRYPT_PARAM_XMSS_BASE                               1900
#define CRYPT_PARAM_XMSS_PRV_INDEX                          (CRYPT_PARAM_XMSS_BASE + 1)
#define CRYPT_PARAM_XMSS_PRV_SEED                           (CRYPT_PARAM_XMSS_BASE + 2)
#define CRYPT_PARAM_XMSS_PRV_PRF                            (CRYPT_PARAM_XMSS_BASE + 3)
#define CRYPT_PARAM_XMSS_PUB_SEED                           (CRYPT_PARAM_XMSS_BASE + 4)
#define CRYPT_PARAM_XMSS_PUB_ROOT                           (CRYPT_PARAM_XMSS_BASE + 5)

#define CRYPT_PARAM_DECODE_BASE                             4000
#define CRYPT_PARAM_DECODE_OUTPUT_FORMAT                    (CRYPT_PARAM_DECODE_BASE + 1)
#define CRYPT_PARAM_DECODE_OUTPUT_TYPE                      (CRYPT_PARAM_DECODE_BASE + 2)
#define CRYPT_PARAM_DECODE_PASSWORD                         (CRYPT_PARAM_DECODE_BASE + 3)
#define CRYPT_PARAM_DECODE_KEY_TYPE                         (CRYPT_PARAM_DECODE_BASE + 4)
#define CRYPT_PARAM_DECODE_BUFFER_DATA                      (CRYPT_PARAM_DECODE_BASE + 5)
#define CRYPT_PARAM_DECODE_OBJECT_DATA                      (CRYPT_PARAM_DECODE_BASE + 6)
#define CRYPT_PARAM_DECODE_OBJECT_TYPE                      (CRYPT_PARAM_DECODE_BASE + 7)
#define CRYPT_PARAM_DECODE_PKEY_EXPORT_METHOD_FUNC          (CRYPT_PARAM_DECODE_BASE + 8)
#define CRYPT_PARAM_DECODE_PKEY_DUP_METHOD_FUNC             (CRYPT_PARAM_DECODE_BASE + 9)
#define CRYPT_PARAM_DECODE_PKEY_FREE_METHOD_FUNC            (CRYPT_PARAM_DECODE_BASE + 10)
#define CRYPT_PARAM_DECODE_LIB_CTX                          (CRYPT_PARAM_DECODE_BASE + 11)
#define CRYPT_PARAM_DECODE_TARGET_ATTR_NAME                 (CRYPT_PARAM_DECODE_BASE + 12)
#define CRYPT_PARAM_DECODE_PROVIDER_CTX                     (CRYPT_PARAM_DECODE_BASE + 13)
#define CRYPT_PARAM_DECODE_FLAG_FREE_OUTDATA                (CRYPT_PARAM_DECODE_BASE + 14)

#define CRYPT_PARAM_CIPHER_BASE                             4600
#define CRYPT_PARAM_CIPHER_AEAD_IV_LEN                      (CRYPT_PARAM_CIPHER_BASE + 1)

#define CRYPT_PARAM_MAC_BASE                                4700
#define CRYPT_PARAM_MAC_MAC_DIGEST                          (CRYPT_PARAM_MAC_BASE + 1)

#define CRYPT_PARAM_CAP_TLS_GROUP_BASE                      5000
#define CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_NAME           (CRYPT_PARAM_CAP_TLS_GROUP_BASE + 1)
#define CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_ID             (CRYPT_PARAM_CAP_TLS_GROUP_BASE + 2)
#define CRYPT_PARAM_CAP_TLS_GROUP_PARA_ID                   (CRYPT_PARAM_CAP_TLS_GROUP_BASE + 3)
#define CRYPT_PARAM_CAP_TLS_GROUP_ALG_ID                    (CRYPT_PARAM_CAP_TLS_GROUP_BASE + 4)
#define CRYPT_PARAM_CAP_TLS_GROUP_SEC_BITS                  (CRYPT_PARAM_CAP_TLS_GROUP_BASE + 5)
#define CRYPT_PARAM_CAP_TLS_GROUP_VERSION_BITS              (CRYPT_PARAM_CAP_TLS_GROUP_BASE + 6)
#define CRYPT_PARAM_CAP_TLS_GROUP_IS_KEM                    (CRYPT_PARAM_CAP_TLS_GROUP_BASE + 7)
#define CRYPT_PARAM_CAP_TLS_GROUP_PUBKEY_LEN                (CRYPT_PARAM_CAP_TLS_GROUP_BASE + 8)
#define CRYPT_PARAM_CAP_TLS_GROUP_SHAREDKEY_LEN             (CRYPT_PARAM_CAP_TLS_GROUP_BASE + 9)
#define CRYPT_PARAM_CAP_TLS_GROUP_CIPHERTEXT_LEN            (CRYPT_PARAM_CAP_TLS_GROUP_BASE + 10)

#define CRYPT_PARAM_CAP_TLS_SIGNALG_BASE                    5100
#define CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME          (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 1)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_ID            (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 2)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE                (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 3)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_OID            (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 4)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_NAME           (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 5)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID                 (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 6)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_OID                (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 7)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_NAME               (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 8)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_ID           (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 9)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_OID          (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 10)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_NAME         (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 11)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_SIGN_ID                 (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 12)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_MD_ID                   (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 13)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_MD_OID                  (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 14)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_MD_NAME                 (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 15)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_SEC_BITS                (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 16)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_CHAIN_VERSION_BITS      (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 17)
#define CRYPT_PARAM_CAP_TLS_SIGNALG_CERT_VERSION_BITS       (CRYPT_PARAM_CAP_TLS_SIGNALG_BASE + 18)

#define CRYPT_PARAM_CMVP_BASE                               5200
#define CRYPT_PARAM_CMVP_LOG_FUNC                           (CRYPT_PARAM_CMVP_BASE + 1)
#define CRYPT_PARAM_CMVP_SELFTEST_TYPE                      (CRYPT_PARAM_CMVP_BASE + 2)
#define CRYPT_PARAM_CMVP_RANDOM                             (CRYPT_PARAM_CMVP_BASE + 3)
#define CRYPT_PARAM_CMVP_INTERNAL_LIBCTX_FLAG               (CRYPT_PARAM_CMVP_BASE + 4)

#define CRYPT_PARAM_SM9_BASE                                5300
#define CRYPT_PARAM_SM9_USER_ID                             (CRYPT_PARAM_SM9_BASE + 1)
#define CRYPT_PARAM_SM9_MASTER_KEY                          (CRYPT_PARAM_SM9_BASE + 2)
#define CRYPT_PARAM_SM9_USER_KEY                            (CRYPT_PARAM_SM9_BASE + 3)
#define CRYPT_PARAM_SM9_KEY_TYPE                            (CRYPT_PARAM_SM9_BASE + 4)
#define CRYPT_PARAM_SM9_MASTER_PUB_KEY                      (CRYPT_PARAM_SM9_BASE + 5)

#ifdef __cplusplus
}
#endif

#endif
