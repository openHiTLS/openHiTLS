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
#ifdef HITLS_CRYPTO_PROVIDER

#include <stdint.h>
#include <string.h>
#include "bsl_sal.h"
#include "bsl_obj.h"
#include "bsl_errno.h"
#include "bsl_params.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#ifdef HITLS_TLS_FEATURE_PROVIDER
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#endif
#include "crypt_eal_implprovider.h"
#include "crypt_eal_provider.h"
#include "crypt_provider.h"
#include "crypt_default_provderimpl.h"
#include "crypt_default_provider.h"

#define CRYPT_EAL_DEFAULT_ATTR "provider=default"

#ifdef HITLS_CRYPTO_MD
static const CRYPT_EAL_AlgInfo g_defEalMds[] = {
#ifdef HITLS_CRYPTO_MD5
    {CRYPT_MD_MD5, g_defEalMdMd5, CRYPT_EAL_DEFAULT_ATTR},
#endif // HITLS_CRYPTO_MD5
#ifdef HITLS_CRYPTO_SHA1
    {CRYPT_MD_SHA1, g_defEalMdSha1, CRYPT_EAL_DEFAULT_ATTR},
#endif // HITLS_CRYPTO_SHA1
#ifdef HITLS_CRYPTO_SHA224
    {CRYPT_MD_SHA224, g_defEalMdSha224, CRYPT_EAL_DEFAULT_ATTR},
#endif // HITLS_CRYPTO_SHA224
#ifdef HITLS_CRYPTO_SHA256
    {CRYPT_MD_SHA256, g_defEalMdSha256, CRYPT_EAL_DEFAULT_ATTR},
#endif // HITLS_CRYPTO_SHA256
#ifdef HITLS_CRYPTO_SHA384
    {CRYPT_MD_SHA384, g_defEalMdSha384, CRYPT_EAL_DEFAULT_ATTR},
#endif // HITLS_CRYPTO_SHA384
#ifdef HITLS_CRYPTO_SHA512
    {CRYPT_MD_SHA512, g_defEalMdSha512, CRYPT_EAL_DEFAULT_ATTR},
#endif // HITLS_CRYPTO_SHA512
#ifdef HITLS_CRYPTO_SHA3
    {CRYPT_MD_SHA3_224, g_defEalMdSha3224, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_256, g_defEalMdSha3256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_384, g_defEalMdSha3384, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_512, g_defEalMdSha3512, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHAKE128, g_defEalMdShake128, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHAKE256, g_defEalMdShake256, CRYPT_EAL_DEFAULT_ATTR},
#endif // HITLS_CRYPTO_SHA3
#ifdef HITLS_CRYPTO_SM3
    {CRYPT_MD_SM3, g_defEalMdSm3, CRYPT_EAL_DEFAULT_ATTR},
#endif // HITLS_CRYPTO_SM3
    CRYPT_EAL_ALGINFO_END
};
#endif // HITLS_CRYPTO_MD

#ifdef HITLS_CRYPTO_MAC
static const CRYPT_EAL_AlgInfo g_defEalMacs[] = {
#ifdef HITLS_CRYPTO_HMAC
    // The underlying hash algorithm in HMAC can be offloaded to other providers,
    // so no need to add hash-related macro guards here
    {CRYPT_MAC_HMAC_MD5, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA1, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA224, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA256, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA384, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA512, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_224, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_256, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_384, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_512, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SM3, g_defEalMacHmac, CRYPT_EAL_DEFAULT_ATTR},
#endif /* HITLS_CRYPTO_HMAC */
#ifdef HITLS_CRYPTO_CMAC
#ifdef HITLS_CRYPTO_AES
    {CRYPT_MAC_CMAC_AES128, g_defEalMacCmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_CMAC_AES192, g_defEalMacCmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_CMAC_AES256, g_defEalMacCmac, CRYPT_EAL_DEFAULT_ATTR},
#endif /* HITLS_CRYPTO_AES */
#ifdef HITLS_CRYPTO_SM4
    {CRYPT_MAC_CMAC_SM4, g_defEalMacCmac, CRYPT_EAL_DEFAULT_ATTR},
#endif /* HITLS_CRYPTO_SM4 */
#endif /* HITLS_CRYPTO_CMAC */
#ifdef HITLS_CRYPTO_CBC_MAC
    {CRYPT_MAC_CBC_MAC_SM4, g_defEalMacCbcMac, CRYPT_EAL_DEFAULT_ATTR},
#endif /* HITLS_CRYPTO_CBC_MAC */
#ifdef HITLS_CRYPTO_SIPHASH
    {CRYPT_MAC_SIPHASH64, g_defEalMacSiphash, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_SIPHASH128, g_defEalMacSiphash, CRYPT_EAL_DEFAULT_ATTR},
#endif /* HITLS_CRYPTO_SIPHASH */
#ifdef HITLS_CRYPTO_GMAC
    {CRYPT_MAC_GMAC_AES128, g_defEalMacGmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_GMAC_AES192, g_defEalMacGmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_GMAC_AES256, g_defEalMacGmac, CRYPT_EAL_DEFAULT_ATTR},
#endif /* HITLS_CRYPTO_GMAC */
    CRYPT_EAL_ALGINFO_END
};
#endif

#ifdef HITLS_CRYPTO_KDF
static const CRYPT_EAL_AlgInfo g_defEalKdfs[] = {
#ifdef HITLS_CRYPTO_SCRYPT
    {CRYPT_KDF_SCRYPT, g_defEalKdfScrypt, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_PBKDF2
    {CRYPT_KDF_PBKDF2, g_defEalKdfPBKdf2, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_KDFTLS12
    {CRYPT_KDF_KDFTLS12, g_defEalKdfKdfTLS12, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_HKDF
    {CRYPT_KDF_HKDF, g_defEalKdfHkdf, CRYPT_EAL_DEFAULT_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END
};
#endif

#ifdef HITLS_CRYPTO_CIPHER
static const CRYPT_EAL_AlgInfo g_defEalCiphers[] = {
#ifdef HITLS_CRYPTO_AES
#ifdef HITLS_CRYPTO_CBC
    {CRYPT_CIPHER_AES128_CBC, g_defEalCbc, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CBC, g_defEalCbc, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CBC, g_defEalCbc, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_CTR
    {CRYPT_CIPHER_AES128_CTR, g_defEalCtr, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CTR, g_defEalCtr, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CTR, g_defEalCtr, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_ECB
    {CRYPT_CIPHER_AES128_ECB, g_defEalEcb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_ECB, g_defEalEcb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_ECB, g_defEalEcb, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_CCM
    {CRYPT_CIPHER_AES128_CCM, g_defEalCcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CCM, g_defEalCcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CCM, g_defEalCcm, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_GCM
    {CRYPT_CIPHER_AES128_GCM, g_defEalGcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_GCM, g_defEalGcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_GCM, g_defEalGcm, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_XTS
    {CRYPT_CIPHER_AES128_XTS, g_defEalXts, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_XTS, g_defEalXts, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_CFB
    {CRYPT_CIPHER_AES128_CFB, g_defEalCfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CFB, g_defEalCfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CFB, g_defEalCfb, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_OFB
    {CRYPT_CIPHER_AES128_OFB, g_defEalOfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_OFB, g_defEalOfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_OFB, g_defEalOfb, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_WRAP
    {CRYPT_CIPHER_AES128_WRAP_PAD, g_defEalWrap, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_WRAP_PAD, g_defEalWrap, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_WRAP_PAD, g_defEalWrap, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_WRAP_NOPAD, g_defEalWrap, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_WRAP_NOPAD, g_defEalWrap, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_WRAP_NOPAD, g_defEalWrap, CRYPT_EAL_DEFAULT_ATTR},
#endif
#endif // HITLS_CRYPTO_AES
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
    {CRYPT_CIPHER_CHACHA20_POLY1305, g_defEalChaCha, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM4
#ifdef HITLS_CRYPTO_XTS
    {CRYPT_CIPHER_SM4_XTS, g_defEalXts, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_CBC
    {CRYPT_CIPHER_SM4_CBC, g_defEalCbc, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_ECB
    {CRYPT_CIPHER_SM4_ECB, g_defEalEcb, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_CTR
    {CRYPT_CIPHER_SM4_CTR, g_defEalCtr, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_GCM
    {CRYPT_CIPHER_SM4_GCM, g_defEalGcm, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_CCM
    {CRYPT_CIPHER_SM4_CCM, g_defEalCcm, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_CFB
    {CRYPT_CIPHER_SM4_CFB, g_defEalCfb, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_OFB
    {CRYPT_CIPHER_SM4_OFB, g_defEalOfb, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_HCTR
    {CRYPT_CIPHER_SM4_HCTR, g_defEalHctr, CRYPT_EAL_DEFAULT_ATTR},
#endif
#endif // HITLS_CRYPTO_SM4
    CRYPT_EAL_ALGINFO_END
};
#endif

#ifdef HITLS_CRYPTO_DRBG
static const CRYPT_EAL_AlgInfo g_defEalRands[] = {
#ifdef HITLS_CRYPTO_DRBG_HASH
#ifdef HITLS_CRYPTO_SHA1
    {CRYPT_RAND_SHA1, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA224
    {CRYPT_RAND_SHA224, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA256
    {CRYPT_RAND_SHA256, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA384
    {CRYPT_RAND_SHA384, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA512
    {CRYPT_RAND_SHA512, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM3
    {CRYPT_RAND_SM3, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#endif // HITLS_CRYPTO_DRBG_HASH
#ifdef HITLS_CRYPTO_DRBG_HMAC
#ifdef HITLS_CRYPTO_SHA1
    {CRYPT_RAND_HMAC_SHA1, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA224
    {CRYPT_RAND_HMAC_SHA224, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA256
    {CRYPT_RAND_HMAC_SHA256, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA384
    {CRYPT_RAND_HMAC_SHA384, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SHA512
    {CRYPT_RAND_HMAC_SHA512, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#endif // HITLS_CRYPTO_DRBG_HMAC
#ifdef HITLS_CRYPTO_DRBG_CTR
#ifdef HITLS_CRYPTO_AES
    {CRYPT_RAND_AES128_CTR, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES192_CTR, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES256_CTR, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES128_CTR_DF, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES192_CTR_DF, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES256_CTR_DF, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM4
    {CRYPT_RAND_SM4_CTR_DF, g_defEalRand, CRYPT_EAL_DEFAULT_ATTR},
#endif
#endif // HITLS_CRYPTO_DRBG_CTR
    CRYPT_EAL_ALGINFO_END
};
#endif

#ifdef HITLS_CRYPTO_PKEY
static const CRYPT_EAL_AlgInfo g_defEalKeyMgmt[] = {
#ifdef HITLS_CRYPTO_DSA
    {CRYPT_PKEY_DSA, g_defEalKeyMgmtDsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_PKEY_ED25519, g_defEalKeyMgmtEd25519, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_X25519
    {CRYPT_PKEY_X25519, g_defEalKeyMgmtX25519, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_PKEY_RSA, g_defEalKeyMgmtRsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_DH
    {CRYPT_PKEY_DH, g_defEalKeyMgmtDh, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_PKEY_ECDSA, g_defEalKeyMgmtEcdsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_ECDH
    {CRYPT_PKEY_ECDH, g_defEalKeyMgmtEcdh, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_PKEY_SM2, g_defEalKeyMgmtSm2, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_PAILLIER
    {CRYPT_PKEY_PAILLIER, g_defEalKeyMgmtPaillier, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
    {CRYPT_PKEY_ELGAMAL, g_defEalKeyMgmtElGamal, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
    {CRYPT_PKEY_SLH_DSA, g_defEalKeyMgmtSlhDsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_MLKEM
    {CRYPT_PKEY_ML_KEM, g_defEalKeyMgmtMlKem, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_FRODOKEM
    {CRYPT_PKEY_FRODOKEM, g_defEalKeyMgmtFrodoKem, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_CLASSIC_MCELIECE
    {CRYPT_PKEY_MCELIECE, g_defEalKeyMgmtMceliece, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_MLDSA
    {CRYPT_PKEY_ML_DSA, g_defEalKeyMgmtMlDsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_XMSS
    {CRYPT_PKEY_XMSS, g_defEalKeyMgmtXmss, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
    {CRYPT_PKEY_HYBRID_KEM, g_defEalKeyMgmtHybridKem, CRYPT_EAL_DEFAULT_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END
};

#ifdef HITLS_CRYPTO_PKEY_CRYPT
static const CRYPT_EAL_AlgInfo g_defEalAsymCiphers[] = {
#if defined(HITLS_CRYPTO_RSA_ENCRYPT) || defined(HITLS_CRYPTO_RSA_DECRYPT)
    {CRYPT_PKEY_RSA, g_defEalAsymCipherRsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM2_CRYPT
    {CRYPT_PKEY_SM2, g_defEalAsymCipherSm2, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_PAILLIER
    {CRYPT_PKEY_PAILLIER, g_defEalAsymCipherPaillier, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
    {CRYPT_PKEY_ELGAMAL, g_defEalAsymCipherElGamal, CRYPT_EAL_DEFAULT_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END
};
#endif

#ifdef HITLS_CRYPTO_PKEY_EXCH
static const CRYPT_EAL_AlgInfo g_defEalKeyExch[] = {
#ifdef HITLS_CRYPTO_X25519
    {CRYPT_PKEY_X25519, g_defEalExchX25519, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_DH
    {CRYPT_PKEY_DH, g_defEalExchDh, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_ECDH
    {CRYPT_PKEY_ECDH, g_defEalExchEcdh, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM2_EXCH
    {CRYPT_PKEY_SM2, g_defEalExchSm2, CRYPT_EAL_DEFAULT_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END
};
#endif

#ifdef HITLS_CRYPTO_PKEY_SIGN
static const CRYPT_EAL_AlgInfo g_defEalSigns[] = {
#ifdef HITLS_CRYPTO_DSA
    {CRYPT_PKEY_DSA, g_defEalSignDsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_PKEY_ED25519, g_defEalSignEd25519, CRYPT_EAL_DEFAULT_ATTR},
#endif
#if defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY)
    {CRYPT_PKEY_RSA, g_defEalSignRsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_PKEY_ECDSA, g_defEalSignEcdsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SM2_SIGN
    {CRYPT_PKEY_SM2, g_defEalSignSm2, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
    {CRYPT_PKEY_SLH_DSA, g_defEalSignSlhDsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_MLDSA
    {CRYPT_PKEY_ML_DSA, g_defEalSignMlDsa, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_XMSS
    {CRYPT_PKEY_XMSS, g_defEalSignXmss, CRYPT_EAL_DEFAULT_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END
};
#endif

#ifdef HITLS_CRYPTO_PKEY_KEM
static const CRYPT_EAL_AlgInfo g_defEalKems[] = {
#ifdef HITLS_CRYPTO_MLKEM
    {CRYPT_PKEY_ML_KEM, g_defEalMlKem, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_FRODOKEM
    {CRYPT_PKEY_FRODOKEM, g_defEalFrodoKem, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_CLASSIC_MCELIECE
    {CRYPT_PKEY_MCELIECE, g_defEalMceliece, CRYPT_EAL_DEFAULT_ATTR},
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
    {CRYPT_PKEY_HYBRID_KEM, g_defEalHybridKeyKem, CRYPT_EAL_DEFAULT_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END
};
#endif
#endif // HITLS_CRYPTO_PKEY

#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
static const CRYPT_EAL_AlgInfo g_defEalDecoders[] = {
#ifdef HITLS_BSL_PEM
    {BSL_CID_DECODE_UNKNOWN, g_defEalPem2Der,
        "provider=default, inFormat=PEM, outFormat=ASN1"},
#endif
#ifdef HITLS_CRYPTO_KEY_EPKI
    {BSL_CID_DECODE_UNKNOWN, g_defEalPrvP8Enc2P8,
        "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_ENCRYPT, outFormat=ASN1, outType=PRIKEY_PKCS8_UNENCRYPT"},
#endif
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_PKEY_RSA, g_defEalRsaPrvDer2Key,
        "provider=default, inFormat=ASN1, inType=PRIKEY_RSA, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_RSA, g_defEalRsaPubDer2Key,
        "provider=default, inFormat=ASN1, inType=PUBKEY_RSA, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_PKEY_ECDSA, g_defEalEcdsaPrvDer2Key,
        "provider=default, inFormat=ASN1, inType=PRIKEY_ECC, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_PKEY_SM2, g_defEalSm2PrvDer2Key,
        "provider=default, inFormat=ASN1, inType=PRIKEY_ECC, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_PKEY_RSA, g_defEalP8Der2RsaKey,
        "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_PKEY_ECDSA, g_defEalP8Der2EcdsaKey,
        "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_PKEY_SM2, g_defEalP8Der2Sm2Key,
        "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_PKEY_ED25519, g_defEalP8Der2Ed25519Key,
        "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_MLDSA
    {CRYPT_PKEY_ML_DSA, g_defEalP8Der2MldsaKey,
        "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_MLKEM
    {CRYPT_PKEY_ML_KEM, g_defEalP8Der2MlkemKey,
        "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
    {CRYPT_PKEY_SLH_DSA, g_defEalP8Der2SlhDsaKey,
        "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_PKEY_RSA, g_defEalSubPubKeyDer2RsaKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_PKEY_ECDSA, g_defEalSubPubKeyDer2EcdsaKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_PKEY_SM2, g_defEalSubPubKeyDer2Sm2Key,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_MLDSA
    {CRYPT_PKEY_ML_DSA, g_defEalSubPubKeyDer2MldsaKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_MLKEM
    {CRYPT_PKEY_ML_KEM, g_defEalSubPubKeyDer2MlkemKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
    {CRYPT_PKEY_SLH_DSA, g_defEalSubPubKeyDer2SlhDsaKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_PKEY_ED25519, g_defEalSubPubKeyDer2Ed25519Key,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_PKEY_RSA, g_defEalSubPubKeyWithoutSeqDer2RsaKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_PKEY_ECDSA, g_defEalSubPubKeyWithoutSeqDer2EcdsaKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_PKEY_SM2, g_defEalSubPubKeyWithoutSeqDer2Sm2Key,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_PKEY_ED25519, g_defEalSubPubKeyWithoutSeqDer2Ed25519Key,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_MLDSA
    {CRYPT_PKEY_ML_DSA, g_defEalSubPubKeyWithoutSeqDer2MldsaKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_XMSS
    {CRYPT_PKEY_XMSS, g_defEalSubPubKeyWithoutSeqDer2XmssKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_MLKEM
    {CRYPT_PKEY_ML_KEM, g_defEalSubPubKeyWithoutSeqDer2MlkemKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
    {CRYPT_PKEY_SLH_DSA, g_defEalSubPubKeyWithoutSeqDer2SlhDsaKey,
        "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
#endif
    {BSL_CID_DECODE_UNKNOWN, g_defEalLowKeyObject2PkeyObject,
        "provider=default, inFormat=OBJECT, inType=LOW_KEY, outFormat=OBJECT, outType=HIGH_KEY"},
    CRYPT_EAL_ALGINFO_END
};
#endif

static int32_t CRYPT_EAL_DefaultProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    (void)algInfos;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
#ifdef HITLS_CRYPTO_CIPHER
        case CRYPT_EAL_OPERAID_SYMMCIPHER:
            *algInfos = g_defEalCiphers;
            break;
#endif
#ifdef HITLS_CRYPTO_PKEY
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = g_defEalKeyMgmt;
            break;
#ifdef HITLS_CRYPTO_PKEY_SIGN
        case CRYPT_EAL_OPERAID_SIGN:
            *algInfos = g_defEalSigns;
            break;
#endif
#ifdef HITLS_CRYPTO_PKEY_CRYPT
        case CRYPT_EAL_OPERAID_ASYMCIPHER:
            *algInfos = g_defEalAsymCiphers;
            break;
#endif
#ifdef HITLS_CRYPTO_PKEY_EXCH
        case CRYPT_EAL_OPERAID_KEYEXCH:
            *algInfos = g_defEalKeyExch;
            break;
#endif
#ifdef HITLS_CRYPTO_PKEY_KEM
        case CRYPT_EAL_OPERAID_KEM:
            *algInfos = g_defEalKems;
            break;
#endif
#endif
#ifdef HITLS_CRYPTO_MD
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = g_defEalMds;
            break;
#endif
#ifdef HITLS_CRYPTO_MAC
        case CRYPT_EAL_OPERAID_MAC:
            *algInfos = g_defEalMacs;
            break;
#endif
#ifdef HITLS_CRYPTO_KDF
        case CRYPT_EAL_OPERAID_KDF:
            *algInfos = g_defEalKdfs;
            break;
#endif
#ifdef HITLS_CRYPTO_DRBG
        case CRYPT_EAL_OPERAID_RAND:
            *algInfos = g_defEalRands;
            break;
#endif
#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
        case CRYPT_EAL_OPERAID_DECODER:
            *algInfos = g_defEalDecoders;
            break;
#endif
        default:
            ret = CRYPT_NOT_SUPPORT;
            break;
    }
    return ret;
}

static void CRYPT_EAL_DefaultProvFree(void *provCtx)
{
    BSL_SAL_Free(provCtx);
}

#ifdef HITLS_TLS_FEATURE_PROVIDER
#define TLS_GROUP_PARAM_COUNT 11
#define TLS_SIGN_SCHEME_PARAM_COUNT 18
typedef struct {
    const char *name;           // group name
    int32_t paraId;             // parameter id CRYPT_PKEY_ParaId
    int32_t algId;              // algorithm id CRYPT_PKEY_AlgId
    int32_t secBits;            // security bits
    uint16_t groupId;           // iana group id, HITLS_NamedGroup
    uint32_t pubkeyLen;         // public key length(CH keyshare / SH keyshare)
    uint32_t sharedkeyLen;      // shared key length
    uint32_t ciphertextLen;     // ciphertext length(SH keyshare)
    uint32_t versionBits;       // TLS_VERSION_MASK
    bool isKem;                 // true: KEM, false: KEX
} TLS_GroupInfo;

#ifndef HITLS_TLS_CAP_NO_STR
#define CONST_CAST(str) ((char *)(uintptr_t)(str))
#else
#define CONST_CAST(str) NULL
#endif
static const TLS_GroupInfo g_tlsGroupInfo[] = {
#ifdef HITLS_CRYPTO_X25519
    {
        CONST_CAST("x25519"),
        CRYPT_PKEY_PARAID_MAX,
        CRYPT_PKEY_X25519,
        128,                                    // secBits
        HITLS_EC_GROUP_CURVE25519,             // groupId
        32, 32, 0,                             // pubkeyLen=32, sharedkeyLen=32 (256 bits)
        TLS_VERSION_MASK | DTLS_VERSION_MASK,  // versionBits
        false,
    },
#endif /* HITLS_CRYPTO_X25519 */
#ifdef HITLS_TLS_FEATURE_KEM
    {
        CONST_CAST("X25519MLKEM768"),
        CRYPT_HYBRID_X25519_MLKEM768,
        CRYPT_PKEY_HYBRID_KEM,
        192,                                    // secBits
        HITLS_HYBRID_X25519_MLKEM768,          // groupId
        1184 + 32, 32 + 32, 1088 + 32,         // pubkeyLen=1216, sharedkeyLen=64, ciphertextLen=1120
        TLS13_VERSION_BIT,                     // versionBits
        true,
    },
    {
        CONST_CAST("SecP256r1MLKEM768"),
        CRYPT_HYBRID_ECDH_NISTP256_MLKEM768,
        CRYPT_PKEY_HYBRID_KEM,
        192,                                    // secBits
        HITLS_HYBRID_ECDH_NISTP256_MLKEM768,   // groupId
        1184 + 65, 32 + 32, 1088 + 65,         // pubkeyLen=1249, sharedkeyLen=64, ciphertextLen=1153
        TLS13_VERSION_BIT,                     // versionBits
        true,
    },
    {
        CONST_CAST("SecP384r1MLKEM1024"),
        CRYPT_HYBRID_ECDH_NISTP384_MLKEM1024,
        CRYPT_PKEY_HYBRID_KEM,
        256,                                    // secBits
        HITLS_HYBRID_ECDH_NISTP384_MLKEM1024,  // groupId
        1568 + 97, 32 + 48, 1568 + 97,         // pubkeyLen=1665, sharedkeyLen=80, ciphertextLen=1665
        TLS13_VERSION_BIT,                     // versionBits
        true,
    },
#endif /* HITLS_TLS_FEATURE_KEM */
#ifdef HITLS_CRYPTO_CURVE_NISTP256
    {
        CONST_CAST("secp256r1"),
        CRYPT_ECC_NISTP256, // CRYPT_ECC_NISTP256
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        128, // secBits
        HITLS_EC_GROUP_SECP256R1, // groupId
        65, 32, 0, // pubkeyLen=65, sharedkeyLen=32 (256 bits)
        TLS_VERSION_MASK | DTLS_VERSION_MASK, // versionBits
        false,
    },
#endif /* HITLS_CRYPTO_CURVE_NISTP256 */
#ifdef HITLS_CRYPTO_CURVE_NISTP384
    {
        CONST_CAST("secp384r1"),
        CRYPT_ECC_NISTP384, // CRYPT_ECC_NISTP384
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        192, // secBits
        HITLS_EC_GROUP_SECP384R1, // groupId
        97, 48, 0, // pubkeyLen=97, sharedkeyLen=48 (384 bits)
        TLS_VERSION_MASK | DTLS_VERSION_MASK, // versionBits
        false,
    },
#endif /* HITLS_CRYPTO_CURVE_NISTP384 */
#ifdef HITLS_CRYPTO_CURVE_NISTP521
    {
        CONST_CAST("secp521r1"),
        CRYPT_ECC_NISTP521, // CRYPT_ECC_NISTP521
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        256, // secBits
        HITLS_EC_GROUP_SECP521R1, // groupId
        133, 66, 0, // pubkeyLen=133, sharedkeyLen=66 (521 bits)
        TLS_VERSION_MASK | DTLS_VERSION_MASK, // versionBits
        false,
    },
#endif /* HITLS_CRYPTO_CURVE_NISTP521 */
#ifdef HITLS_CRYPTO_CURVE_BP256R1
    {
        CONST_CAST("brainpoolP256r1"),
        CRYPT_ECC_BRAINPOOLP256R1, // CRYPT_ECC_BRAINPOOLP256R1
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        128, // secBits
        HITLS_EC_GROUP_BRAINPOOLP256R1, // groupId
        65, 32, 0, // pubkeyLen=65, sharedkeyLen=32 (256 bits)
        TLS10_VERSION_BIT | TLS11_VERSION_BIT | TLS12_VERSION_BIT | DTLS_VERSION_MASK, // versionBits
        false,
    },
#endif /* HITLS_CRYPTO_CURVE_BP256R1 */
#ifdef HITLS_CRYPTO_CURVE_BP384R1
    {
        CONST_CAST("brainpoolP384r1"),
        CRYPT_ECC_BRAINPOOLP384R1, // CRYPT_ECC_BRAINPOOLP384R1
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        192, // secBits
        HITLS_EC_GROUP_BRAINPOOLP384R1, // groupId
        97, 48, 0, // pubkeyLen=97, sharedkeyLen=48 (384 bits)
        TLS10_VERSION_BIT | TLS11_VERSION_BIT | TLS12_VERSION_BIT | DTLS_VERSION_MASK, // versionBits
        false,
    },
#endif /* HITLS_CRYPTO_CURVE_BP384R1 */
#ifdef HITLS_CRYPTO_CURVE_BP512R1
    {
        CONST_CAST("brainpoolP512r1"),
        CRYPT_ECC_BRAINPOOLP512R1, // CRYPT_ECC_BRAINPOOLP512R1
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        256, // secBits
        HITLS_EC_GROUP_BRAINPOOLP512R1, // groupId
        129, 64, 0, // pubkeyLen=129, sharedkeyLen=64 (512 bits)
        TLS10_VERSION_BIT | TLS11_VERSION_BIT | TLS12_VERSION_BIT | DTLS_VERSION_MASK, // versionBits
        false,
    },
#endif /* HITLS_CRYPTO_CURVE_BP512R1 */
#ifdef HITLS_CRYPTO_SM2
    {
        CONST_CAST("curveSm2"),
        CRYPT_ECC_SM2, // CRYPT_ECC_SM2
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        128, // secBits
        HITLS_EC_GROUP_SM2, // groupId
        65, 32, 0, // pubkeyLen=65, sharedkeyLen=32 (256 bits)
        TLS13_VERSION_BIT, // versionBits
        false,
    },
    {
        CONST_CAST("sm2"),
        CRYPT_PKEY_PARAID_MAX, // CRYPT_PKEY_PARAID_MAX
        CRYPT_PKEY_SM2, // CRYPT_PKEY_SM2
        128, // secBits
        HITLS_EC_GROUP_SM2, // groupId
        65, 48, 0, // pubkeyLen=65, sharedkeyLen=48 (384 bits)
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT, // versionBits
        false,
    },
#endif /* HITLS_CRYPTO_SM2 */
#ifdef HITLS_CRYPTO_DH
    {
        CONST_CAST("ffdhe8192"),
        CRYPT_DH_RFC7919_8192, // CRYPT_DH_8192
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        192, // secBits
        HITLS_FF_DHE_8192, // groupId
        1024, 1024, 0, // pubkeyLen=1024, sharedkeyLen=1024 (8192 bits)
        TLS13_VERSION_BIT, // versionBits
        false,
    },
    {
        CONST_CAST("ffdhe6144"),
        CRYPT_DH_RFC7919_6144, // CRYPT_DH_6144
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        128, // secBits
        HITLS_FF_DHE_6144, // groupId
        768, 768, 0, // pubkeyLen=768, sharedkeyLen=768 (6144 bits)
        TLS13_VERSION_BIT, // versionBits
        false,
    },
    {
        CONST_CAST("ffdhe4096"),
        CRYPT_DH_RFC7919_4096, // CRYPT_DH_4096
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        128, // secBits
        HITLS_FF_DHE_4096, // groupId
        512, 512, 0, // pubkeyLen=512, sharedkeyLen=512 (4096 bits)
        TLS13_VERSION_BIT, // versionBits
        false,
    },
    {
        CONST_CAST("ffdhe3072"),
        CRYPT_DH_RFC7919_3072, // Fixed constant name
        CRYPT_PKEY_DH,
        128,
        HITLS_FF_DHE_3072,
        384, 384, 0, // pubkeyLen=384, sharedkeyLen=384 (3072 bits)
        TLS13_VERSION_BIT,
        false,
    },
    {
        CONST_CAST("ffdhe2048"),
        CRYPT_DH_RFC7919_2048, // CRYPT_DH_2048
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        112, // secBits
        HITLS_FF_DHE_2048, // groupId
        256, 256, 0, // pubkeyLen=256, sharedkeyLen=256 (2048 bits)
        TLS13_VERSION_BIT, // versionBits
        false,
    }
#endif /* HITLS_CRYPTO_DH */
};

static int32_t BuildTlsGroupParam(const TLS_GroupInfo *groupInfo, BSL_Param *param)
{
    int32_t ret = 0;
    int32_t i = 0;
#ifndef HITLS_TLS_CAP_NO_STR
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_NAME,
        BSL_PARAM_TYPE_OCTETS_PTR, (void *)(uintptr_t)groupInfo->name, (uint32_t)strlen(groupInfo->name)), ret);
#endif
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_ID,
        BSL_PARAM_TYPE_UINT16, (void *)(uintptr_t)&(groupInfo->groupId), sizeof(groupInfo->groupId)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_GROUP_PARA_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->paraId), sizeof(groupInfo->paraId)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_GROUP_ALG_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->algId), sizeof(groupInfo->algId)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_GROUP_SEC_BITS, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->secBits), sizeof(groupInfo->secBits)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_GROUP_VERSION_BITS,
        BSL_PARAM_TYPE_UINT32, (void *)(uintptr_t)&(groupInfo->versionBits), sizeof(groupInfo->versionBits)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_GROUP_IS_KEM, BSL_PARAM_TYPE_BOOL,
        (void *)(uintptr_t)&(groupInfo->isKem), sizeof(groupInfo->isKem)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_GROUP_PUBKEY_LEN, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->pubkeyLen), sizeof(groupInfo->pubkeyLen)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_GROUP_SHAREDKEY_LEN, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->sharedkeyLen), sizeof(groupInfo->sharedkeyLen)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_GROUP_CIPHERTEXT_LEN,
        BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&(groupInfo->ciphertextLen), sizeof(groupInfo->ciphertextLen)), ret);

    return ret;
}

static int32_t CryptGetGroupCaps(CRYPT_EAL_ProcessFuncCb cb, void *args)
{
    for (size_t i = 0; i < sizeof(g_tlsGroupInfo) / sizeof(g_tlsGroupInfo[0]); i++) {
        BSL_Param param[TLS_GROUP_PARAM_COUNT] = {0};
        int32_t ret = BuildTlsGroupParam(&g_tlsGroupInfo[i], param);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        ret = cb(param, args);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}
typedef struct {
    const char *name;                   // name
    uint16_t signatureScheme;           // HITLS_SignHashAlgo, IANA specified
    int32_t keyType;                    // HITLS_CERT_KeyType
    int32_t paraId;                     // CRYPT_PKEY_ParaId
    int32_t signHashAlgId;              // combined sign hash algorithm id
    int32_t signAlgId;                  // CRYPT_PKEY_AlgId
    int32_t hashAlgId;                  // CRYPT_MD_AlgId
    int32_t secBits;                    // security bits
    uint32_t certVersionBits;           // TLS_VERSION_MASK
    uint32_t chainVersionBits;          // TLS_VERSION_MASK
} TLS_SigSchemeInfo;

static const TLS_SigSchemeInfo g_signSchemeInfo[] = {
#ifdef HITLS_CRYPTO_CURVE_NISTP521
    {
        CONST_CAST("ecdsa_secp521r1_sha512"),
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
#endif /* HITLS_CRYPTO_CURVE_NISTP521 */
#ifdef HITLS_CRYPTO_CURVE_NISTP384
    {
        CONST_CAST("ecdsa_secp384r1_sha384"),
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
#endif /* HITLS_CRYPTO_CURVE_NISTP384 */
#ifdef HITLS_CRYPTO_ED25519
    {
        CONST_CAST("ed25519"),
        CERT_SIG_SCHEME_ED25519,
        TLS_CERT_KEY_TYPE_ED25519,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_ED25519,
        HITLS_SIGN_ED25519,
        HITLS_HASH_SHA_512,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
#endif /* HITLS_CRYPTO_ED25519 */
#ifdef HITLS_CRYPTO_CURVE_NISTP256
    {
        CONST_CAST("ecdsa_secp256r1_sha256"),
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
#endif /* HITLS_CRYPTO_CURVE_NISTP256 */
#ifdef HITLS_CRYPTO_SM2
    {
        CONST_CAST("sm2_sm3"),
        CERT_SIG_SCHEME_SM2_SM3,
        TLS_CERT_KEY_TYPE_SM2,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SM2DSAWITHSM3,
        HITLS_SIGN_SM2,
        HITLS_HASH_SM3,
        128,
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT | TLS13_VERSION_BIT,
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT | TLS13_VERSION_BIT,
    },
#endif /* HITLS_CRYPTO_SM2 */
#ifdef HITLS_CRYPTO_RSA
    {
        CONST_CAST("rsa_pss_pss_sha512"),
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_512,
        256,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pss_pss_sha384"),
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_384,
        192,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pss_pss_sha256"),
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_256,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pss_rsae_sha512"),
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_512,
        256,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pss_rsae_sha384"),
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_384,
        192,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pss_rsae_sha256"),
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_256,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        CONST_CAST("rsa_pkcs1_sha512"),
        CERT_SIG_SCHEME_RSA_PKCS1_SHA512,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA512WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_512,
        256,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
#endif /* HITLS_CRYPTO_RSA */
#ifdef HITLS_CRYPTO_DSA
    {
        CONST_CAST("dsa_sha512"),
        CERT_SIG_SCHEME_DSA_SHA512,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA512,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_512,
        256,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
#endif /* HITLS_CRYPTO_DSA */
#ifdef HITLS_CRYPTO_RSA
    {
        CONST_CAST("rsa_pkcs1_sha384"),
        CERT_SIG_SCHEME_RSA_PKCS1_SHA384,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA384WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_384,
        192,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
#endif /* HITLS_CRYPTO_RSA */
#ifdef HITLS_CRYPTO_DSA
    {
        CONST_CAST("dsa_sha384"),
        CERT_SIG_SCHEME_DSA_SHA384,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA384,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_384,
        192,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
#endif /* HITLS_CRYPTO_DSA */
#ifdef HITLS_CRYPTO_RSA
    {
        CONST_CAST("rsa_pkcs1_sha256"),
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA256WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_256,
        128,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
#endif /* HITLS_CRYPTO_RSA */
#ifdef HITLS_CRYPTO_DSA
    {
        CONST_CAST("dsa_sha256"),
        CERT_SIG_SCHEME_DSA_SHA256,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA256,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_256,
        128,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
#endif /* HITLS_CRYPTO_RSA */
#ifdef HITLS_CRYPTO_ECDSA
    {
        CONST_CAST("ecdsa_sha224"),
        CERT_SIG_SCHEME_ECDSA_SHA224,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_ECDSAWITHSHA224,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
#endif /* HITLS_CRYPTO_ECDSA */
#ifdef HITLS_CRYPTO_RSA
    {
        CONST_CAST("rsa_pkcs1_sha224"),
        CERT_SIG_SCHEME_RSA_PKCS1_SHA224,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA224WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
#endif /* HITLS_CRYPTO_RSA */
#ifdef HITLS_CRYPTO_DSA
    {
        CONST_CAST("dsa_sha224"),
        CERT_SIG_SCHEME_DSA_SHA224,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA224,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {
        CONST_CAST("ecdsa_sha1"),
        CERT_SIG_SCHEME_ECDSA_SHA1,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_ECDSAWITHSHA1,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA1,
        63,                 // https://eprint.iacr.org/2020/014
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
#endif
#ifdef HITLS_CRYPTO_RSA
    {
        CONST_CAST("rsa_pkcs1_sha1"),
        CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA1WITHRSA,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA1,
        63,                 // https://eprint.iacr.org/2020/014
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
#endif /* HITLS_CRYPTO_RSA */
#ifdef HITLS_CRYPTO_DSA
    {
        CONST_CAST("dsa_sha1"),
        CERT_SIG_SCHEME_DSA_SHA1,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA1,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA1,
        63,                 // https://eprint.iacr.org/2020/014
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
#endif /* HITLS_CRYPTO_DSA */
};

static int32_t BuildTlsSigAlgParam(const TLS_SigSchemeInfo *sigSchemeInfo, BSL_Param *param)
{
    int32_t ret = 0;
    int32_t i = 0;
#ifndef HITLS_TLS_CAP_NO_STR
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME,
        BSL_PARAM_TYPE_OCTETS_PTR, (void *)(uintptr_t)sigSchemeInfo->name, (uint32_t)strlen(sigSchemeInfo->name)), ret);
#endif
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_ID,
        BSL_PARAM_TYPE_UINT16, (void *)(uintptr_t)&(sigSchemeInfo->signatureScheme),
        sizeof(sigSchemeInfo->signatureScheme)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->keyType), sizeof(sigSchemeInfo->keyType)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->paraId), sizeof(sigSchemeInfo->paraId)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_ID,
        BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&(sigSchemeInfo->signHashAlgId), sizeof(sigSchemeInfo->signHashAlgId)),
        ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_SIGNALG_SIGN_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->signAlgId), sizeof(sigSchemeInfo->signAlgId)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_SIGNALG_MD_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->hashAlgId), sizeof(sigSchemeInfo->hashAlgId)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_SIGNALG_SEC_BITS, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->secBits), sizeof(sigSchemeInfo->secBits)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_SIGNALG_CERT_VERSION_BITS,
        BSL_PARAM_TYPE_UINT32, (void *)(uintptr_t)&(sigSchemeInfo->certVersionBits),
        sizeof(sigSchemeInfo->certVersionBits)), ret);
    RETURN_RET_IF_ERR_EX(BSL_PARAM_InitValue(&param[i++], CRYPT_PARAM_CAP_TLS_SIGNALG_CHAIN_VERSION_BITS,
        BSL_PARAM_TYPE_UINT32, (void *)(uintptr_t)&(sigSchemeInfo->chainVersionBits),
        sizeof(sigSchemeInfo->chainVersionBits)), ret);

    return ret;
}

static int32_t CryptGetSignAlgCaps(CRYPT_EAL_ProcessFuncCb cb, void *args)
{
    for (size_t i = 0; i < sizeof(g_signSchemeInfo) / sizeof(g_signSchemeInfo[0]); i++) {
        BSL_Param param[TLS_SIGN_SCHEME_PARAM_COUNT] = {0};
        int32_t ret = BuildTlsSigAlgParam(&g_signSchemeInfo[i], param);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        ret = cb(param, args);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_EAL_DefaultProvGetCaps(void *provCtx, int32_t cmd, CRYPT_EAL_ProcessFuncCb cb, void *args)
{
    (void)provCtx;
    if (cb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_EAL_GET_GROUP_CAP:
            return CryptGetGroupCaps(cb, args);
        case CRYPT_EAL_GET_SIGALG_CAP:
            return CryptGetSignAlgCaps(cb, args);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}
#endif

static CRYPT_EAL_Func g_defEalProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_DefaultProvQuery},
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_DefaultProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
#ifdef HITLS_TLS_FEATURE_PROVIDER
    {CRYPT_EAL_PROVCB_GETCAPS, CRYPT_EAL_DefaultProvGetCaps},
#endif
    CRYPT_EAL_FUNC_END
};

#ifdef HITLS_CRYPTO_ENTROPY
static void *g_providerSeedCtx = NULL;
static CRYPT_RandSeedMethod g_providerSeedMethod = {0};

int32_t CRYPT_EAL_ProviderGetSeed(CRYPT_RandSeedMethod **method, void **seedCtx)
{
    if (method == NULL || seedCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    *method = &g_providerSeedMethod;
    *seedCtx = g_providerSeedCtx;
    return CRYPT_SUCCESS;
}
#endif

int32_t CRYPT_EAL_DefaultProvInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    (void)param;
    void *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtrlCb mgrCtrl = NULL;
    int32_t index = 0;
    int32_t ret;
    while (capFuncs[index].id != 0) {
        switch (capFuncs[index].id) {
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
            case CRYPT_EAL_CAP_GETENTROPY:
                g_providerSeedMethod.getEntropy = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_CLEANENTROPY:
                g_providerSeedMethod.cleanEntropy = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_GETNONCE:
                g_providerSeedMethod.getNonce = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_CLEANNONCE:
                g_providerSeedMethod.cleanNonce = capFuncs[index].func;
                break;
#endif
            case CRYPT_EAL_CAP_MGRCTXCTRL:
            mgrCtrl = capFuncs[index].func;
                break;
            default:
                break;
        }
        index++;
    }
    if (mgrCtrl == NULL) {
        return CRYPT_PROVIDER_NOT_SUPPORT;
    }
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
    RETURN_RET_IF_ERR_EX(mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETSEEDCTX, &g_providerSeedCtx, 0), ret);
#endif
    RETURN_RET_IF_ERR_EX(mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETLIBCTX, &libCtx, 0), ret);
    CRYPT_EAL_DefProvCtx *temp = BSL_SAL_Malloc(sizeof(CRYPT_EAL_DefProvCtx));
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    temp->libCtx = libCtx;
    *provCtx = temp;
    *outFuncs = g_defEalProvOutFuncs;
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_PROVIDER */
