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

/**
 * @defgroup crypt_eal_provider
 * @ingroup crypt
 * @brief default provider impl
 */

#ifndef CRYPT_EAL_DEFAULT_PROVIDERIMPL_H
#define CRYPT_EAL_DEFAULT_PROVIDERIMPL_H

#ifdef HITLS_CRYPTO_PROVIDER

#include "crypt_eal_implprovider.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef HITLS_CRYPTO_MD
#ifdef HITLS_CRYPTO_MD5
extern const CRYPT_EAL_Func g_defEalMdMd5[];
#endif // HITLS_CRYPTO_MD5
#ifdef HITLS_CRYPTO_SHA1
extern const CRYPT_EAL_Func g_defEalMdSha1[];
#endif // HITLS_CRYPTO_SHA1
#ifdef HITLS_CRYPTO_SHA224
extern const CRYPT_EAL_Func g_defEalMdSha224[];
#endif // HITLS_CRYPTO_SHA224
#ifdef HITLS_CRYPTO_SHA256
extern const CRYPT_EAL_Func g_defEalMdSha256[];
#endif // HITLS_CRYPTO_SHA256
#ifdef HITLS_CRYPTO_SHA384
extern const CRYPT_EAL_Func g_defEalMdSha384[];
#endif // HITLS_CRYPTO_SHA384
#ifdef HITLS_CRYPTO_SHA512
extern const CRYPT_EAL_Func g_defEalMdSha512[];
#endif // HITLS_CRYPTO_SHA512
#ifdef HITLS_CRYPTO_SHA3
extern const CRYPT_EAL_Func g_defEalMdSha3224[];
extern const CRYPT_EAL_Func g_defEalMdSha3256[];
extern const CRYPT_EAL_Func g_defEalMdSha3384[];
extern const CRYPT_EAL_Func g_defEalMdSha3512[];
extern const CRYPT_EAL_Func g_defEalMdShake512[];
extern const CRYPT_EAL_Func g_defEalMdShake128[];
extern const CRYPT_EAL_Func g_defEalMdShake256[];
#endif // HITLS_CRYPTO_SHA3
#ifdef HITLS_CRYPTO_SM3
extern const CRYPT_EAL_Func g_defEalMdSm3[];
#endif // HITLS_CRYPTO_SM3
#endif // HITLS_CRYPTO_MD

#ifdef HITLS_CRYPTO_MAC
#ifdef HITLS_CRYPTO_HMAC
extern const CRYPT_EAL_Func g_defEalMacHmac[];
#endif
#ifdef HITLS_CRYPTO_CMAC
extern const CRYPT_EAL_Func g_defEalMacCmac[];
#endif
#ifdef HITLS_CRYPTO_CBC_MAC
extern const CRYPT_EAL_Func g_defEalMacCbcMac[];
#endif
#ifdef HITLS_CRYPTO_GMAC
extern const CRYPT_EAL_Func g_defEalMacGmac[];
#endif
#ifdef HITLS_CRYPTO_SIPHASH
extern const CRYPT_EAL_Func g_defEalMacSiphash[];
#endif
#endif // HITLS_CRYPTO_MAC

#ifdef HITLS_CRYPTO_KDF
#ifdef HITLS_CRYPTO_SCRYPT
extern const CRYPT_EAL_Func g_defEalKdfScrypt[];
#endif
#ifdef HITLS_CRYPTO_PBKDF2
extern const CRYPT_EAL_Func g_defEalKdfPBKdf2[];
#endif
#ifdef HITLS_CRYPTO_KDFTLS12
extern const CRYPT_EAL_Func g_defEalKdfKdfTLS12[];
#endif
#ifdef HITLS_CRYPTO_HKDF
extern const CRYPT_EAL_Func g_defEalKdfHkdf[];
#endif
#endif // HITLS_CRYPTO_KDF

#ifdef HITLS_CRYPTO_CIPHER
#ifdef HITLS_CRYPTO_CBC
extern const CRYPT_EAL_Func g_defEalCbc[];
#endif
#ifdef HITLS_CRYPTO_CCM
extern const CRYPT_EAL_Func g_defEalCcm[];
#endif
#ifdef HITLS_CRYPTO_CFB
extern const CRYPT_EAL_Func g_defEalCfb[];
#endif
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
extern const CRYPT_EAL_Func g_defEalChaCha[];
#endif
#ifdef HITLS_CRYPTO_CTR
extern const CRYPT_EAL_Func g_defEalCtr[];
#endif
#ifdef HITLS_CRYPTO_ECB
extern const CRYPT_EAL_Func g_defEalEcb[];
#endif
#ifdef HITLS_CRYPTO_GCM
extern const CRYPT_EAL_Func g_defEalGcm[];
#endif
#ifdef HITLS_CRYPTO_OFB
extern const CRYPT_EAL_Func g_defEalOfb[];
#endif
#ifdef HITLS_CRYPTO_XTS
extern const CRYPT_EAL_Func g_defEalXts[];
#endif
#ifdef HITLS_CRYPTO_WRAP
extern const CRYPT_EAL_Func g_defEalWrap[];
#endif
#ifdef HITLS_CRYPTO_HCTR
extern const CRYPT_EAL_Func g_defEalHctr[];
#endif
#endif // HITLS_CRYPTO_CIPHER

#ifdef HITLS_CRYPTO_DRBG
extern const CRYPT_EAL_Func g_defEalRand[];
#endif // HITLS_CRYPTO_DRBG

#ifdef HITLS_CRYPTO_PKEY
#ifdef HITLS_CRYPTO_DSA
extern const CRYPT_EAL_Func g_defEalKeyMgmtDsa[];
#endif
#ifdef HITLS_CRYPTO_ED25519
extern const CRYPT_EAL_Func g_defEalKeyMgmtEd25519[];
#endif
#ifdef HITLS_CRYPTO_X25519
extern const CRYPT_EAL_Func g_defEalKeyMgmtX25519[];
#endif
#ifdef HITLS_CRYPTO_RSA
extern const CRYPT_EAL_Func g_defEalKeyMgmtRsa[];
#endif
#ifdef HITLS_CRYPTO_DH
extern const CRYPT_EAL_Func g_defEalKeyMgmtDh[];
#endif
#ifdef HITLS_CRYPTO_ECDSA
extern const CRYPT_EAL_Func g_defEalKeyMgmtEcdsa[];
#endif
#ifdef HITLS_CRYPTO_ECDH
extern const CRYPT_EAL_Func g_defEalKeyMgmtEcdh[];
#endif
#ifdef HITLS_CRYPTO_SM2
extern const CRYPT_EAL_Func g_defEalKeyMgmtSm2[];
#endif
#ifdef HITLS_CRYPTO_PAILLIER
extern const CRYPT_EAL_Func g_defEalKeyMgmtPaillier[];
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
extern const CRYPT_EAL_Func g_defEalKeyMgmtElGamal[];
#endif
#ifdef HITLS_CRYPTO_MLDSA
extern const CRYPT_EAL_Func g_defEalKeyMgmtMlDsa[];
#endif
#ifdef HITLS_CRYPTO_XMSS
extern const CRYPT_EAL_Func g_defEalKeyMgmtXmss[];
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
extern const CRYPT_EAL_Func g_defEalKeyMgmtSlhDsa[];
#endif
#ifdef HITLS_CRYPTO_MLKEM
extern const CRYPT_EAL_Func g_defEalKeyMgmtMlKem[];
#endif
#ifdef HITLS_CRYPTO_FRODOKEM
extern const CRYPT_EAL_Func g_defEalKeyMgmtFrodoKem[];
#endif
#ifdef HITLS_CRYPTO_CLASSIC_MCELIECE
extern const CRYPT_EAL_Func g_defEalKeyMgmtMceliece[];
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
extern const CRYPT_EAL_Func g_defEalKeyMgmtHybridKem[];
#endif

#ifdef HITLS_CRYPTO_X25519
extern const CRYPT_EAL_Func g_defEalExchX25519[];
#endif
#ifdef HITLS_CRYPTO_DH
extern const CRYPT_EAL_Func g_defEalExchDh[];
#endif
#ifdef HITLS_CRYPTO_ECDH
extern const CRYPT_EAL_Func g_defEalExchEcdh[];
#endif
#ifdef HITLS_CRYPTO_SM2_EXCH
extern const CRYPT_EAL_Func g_defEalExchSm2[];
#else
#define g_defEalExchSm2 NULL
#endif


#if defined(HITLS_CRYPTO_RSA_ENCRYPT) || defined(HITLS_CRYPTO_RSA_DECRYPT)
extern const CRYPT_EAL_Func g_defEalAsymCipherRsa[];
#else
#define g_defEalAsymCipherRsa NULL
#endif
#ifdef HITLS_CRYPTO_SM2_CRYPT
extern const CRYPT_EAL_Func g_defEalAsymCipherSm2[];
#else
#define g_defEalAsymCipherSm2 NULL
#endif
#ifdef HITLS_CRYPTO_PAILLIER
extern const CRYPT_EAL_Func g_defEalAsymCipherPaillier[];
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
extern const CRYPT_EAL_Func g_defEalAsymCipherElGamal[];
#endif

#ifdef HITLS_CRYPTO_DSA
extern const CRYPT_EAL_Func g_defEalSignDsa[];
#endif
#ifdef HITLS_CRYPTO_ED25519
extern const CRYPT_EAL_Func g_defEalSignEd25519[];
#endif
#if defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY)
extern const CRYPT_EAL_Func g_defEalSignRsa[];
#else
#define g_defEalSignRsa NULL
#endif
#ifdef HITLS_CRYPTO_ECDSA
extern const CRYPT_EAL_Func g_defEalSignEcdsa[];
#endif
#ifdef HITLS_CRYPTO_SM2_SIGN
extern const CRYPT_EAL_Func g_defEalSignSm2[];
#else
#define g_defEalSignSm2 NULL
#endif
#ifdef HITLS_CRYPTO_MLDSA
extern const CRYPT_EAL_Func g_defEalSignMlDsa[];
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
extern const CRYPT_EAL_Func g_defEalSignSlhDsa[];
#endif

#ifdef HITLS_CRYPTO_XMSS
extern const CRYPT_EAL_Func g_defEalSignXmss[];
#endif

#ifdef HITLS_CRYPTO_MLKEM
extern const CRYPT_EAL_Func g_defEalMlKem[];
#endif
#ifdef HITLS_CRYPTO_FRODOKEM
extern const CRYPT_EAL_Func g_defEalFrodoKem[];
#endif
#ifdef HITLS_CRYPTO_CLASSIC_MCELIECE
extern const CRYPT_EAL_Func g_defEalMceliece[];
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
extern const CRYPT_EAL_Func g_defEalHybridKeyKem[];
#endif
#endif // HITLS_CRYPTO_PKEY

#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
#ifdef HITLS_CRYPTO_KEY_EPKI
extern const CRYPT_EAL_Func g_defEalPrvP8Enc2P8[];
#endif
#ifdef HITLS_BSL_PEM
extern const CRYPT_EAL_Func g_defEalPem2Der[];
#endif
#ifdef HITLS_CRYPTO_RSA
extern const CRYPT_EAL_Func g_defEalRsaPrvDer2Key[];
#endif
#ifdef HITLS_CRYPTO_ECDSA
extern const CRYPT_EAL_Func g_defEalEcdsaPrvDer2Key[];
#endif
#ifdef HITLS_CRYPTO_SM2
extern const CRYPT_EAL_Func g_defEalSm2PrvDer2Key[];
#endif
#ifdef HITLS_CRYPTO_RSA
extern const CRYPT_EAL_Func g_defEalP8Der2RsaKey[];
#endif
#ifdef HITLS_CRYPTO_ECDSA
extern const CRYPT_EAL_Func g_defEalP8Der2EcdsaKey[];
#endif
#ifdef HITLS_CRYPTO_SM2
extern const CRYPT_EAL_Func g_defEalP8Der2Sm2Key[];
#endif
#ifdef HITLS_CRYPTO_ED25519
extern const CRYPT_EAL_Func g_defEalP8Der2Ed25519Key[];
#endif
#ifdef HITLS_CRYPTO_X25519
extern const CRYPT_EAL_Func g_defEalP8Der2X25519Key[];
#endif
#ifdef HITLS_CRYPTO_MLDSA
extern const CRYPT_EAL_Func g_defEalP8Der2MldsaKey[];
#endif
#ifdef HITLS_CRYPTO_MLKEM
extern const CRYPT_EAL_Func g_defEalP8Der2MlkemKey[];
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
extern const CRYPT_EAL_Func g_defEalP8Der2SlhDsaKey[];
#endif
#ifdef HITLS_CRYPTO_RSA
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2RsaKey[];
#endif
#ifdef HITLS_CRYPTO_ECDSA
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2EcdsaKey[];
#endif
#ifdef HITLS_CRYPTO_SM2
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2Sm2Key[];
#endif
#ifdef HITLS_CRYPTO_ED25519
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2Ed25519Key[];
#endif
#ifdef HITLS_CRYPTO_X25519
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2X25519Key[];
#endif
#ifdef HITLS_CRYPTO_MLDSA
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2MldsaKey[];
#endif
#ifdef HITLS_CRYPTO_MLKEM
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2MlkemKey[];
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2SlhDsaKey[];
#endif
#ifdef HITLS_CRYPTO_RSA
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2RsaKey[];
#endif
#ifdef HITLS_CRYPTO_ECDSA
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2EcdsaKey[];
#endif
#ifdef HITLS_CRYPTO_SM2
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2Sm2Key[];
#endif
#ifdef HITLS_CRYPTO_ED25519
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2Ed25519Key[];
#endif
#ifdef HITLS_CRYPTO_X25519
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2X25519Key[];
#endif
#ifdef HITLS_CRYPTO_MLDSA
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2MldsaKey[];
#endif

#ifdef HITLS_CRYPTO_MLKEM
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2MlkemKey[];
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2SlhDsaKey[];
#endif
#ifdef HITLS_CRYPTO_RSA
extern const CRYPT_EAL_Func g_defEalRsaPubDer2Key[];
#endif
#ifdef HITLS_CRYPTO_XMSS
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2XmssKey[];
#endif
extern const CRYPT_EAL_Func g_defEalLowKeyObject2PkeyObject[];
#endif // HITLS_CRYPTO_KEY_DECODE_CHAIN

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* HITLS_CRYPTO_PROVIDER */
#endif // CRYPT_EAL_DEFAULT_PROVIDERIMPL_H