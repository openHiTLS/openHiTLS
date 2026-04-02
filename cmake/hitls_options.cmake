# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.


# ============================================================
# Current file defines all user-configurable options for the build.
# Tip: The indentation preceding the options may indicate the following relationships:
#   1. Parent-Child Relationships/Compilation Dependencies in Features:
#      For example, HITLS_CRYPTO_MD represents all HASH algorithms, HITLS_CRYPTO_MD5 represents the MD5 algorithm.
#      Enabling HITLS_CRYPTO_MD means enabling all hash algorithms, including MD5(HITLS_CRYPTO_MD5).
#      Conversely, HITLS_CRYPTO_MD5 depend on HITLS_CRYPTO_MD(For compilation), Therefore,
#      to enable and compile HITLS_CRYPTO_MD5, HITLS_CRYPTO_MD must also be enabled.
#      In our build system, when a user enables HITLS_CRYPTO_MD5, HITLS_CRYPTO_MD is automatically enabled.
#   2. Some Additional Features
#      For example, HITLS_CRYPTO_AES_PRECALC_TABLES is an additional feature for AES,
#      which enables the use of precalculated tables to improve performance.
# ============================================================

include_guard(GLOBAL)

# ============================================================
# Build Related Only Options
# ============================================================

option(HITLS_BUNDLE_LIB             "Bundle all libraries into single library"    OFF)
option(HITLS_BUILD_EXE              "Build executable"                            OFF)
option(HITLS_BUILD_GEN_INFO         "Generate build information files"            OFF)
option(HITLS_BUILD_STATIC           "Build static libraries"                      ON)
option(HITLS_BUILD_SHARED           "Build shared libraries"                      ON)

# Ignore feature dependencies check
option(HITLS_SKIP_CONFIG_CHECK "Skip configuration checks for unsatisfied dependencies" OFF)

# preset profile (full, iso19790)
set(HITLS_BUILD_PROFILE       "full" CACHE STRING "Build profile (full, iso19790)")

# Compile/link options (Will be initialized in hitls_compile_options.cmake)
set(HITLS_COMPILE_OPTIONS     "" CACHE STRING "Compile options applied to all HiTLS targets (via add_compile_options).")
set(HITLS_SHARED_LINKER_FLAGS "" CACHE STRING "Linker flags applied to dynamic libraries via target_link_options.")
set(HITLS_EXE_LINKER_FLAGS    "" CACHE STRING "Linker flags applied to executable targets via target_link_options.")

# Platform options
set(HITLS_PLATFORM_ENDIAN   "" CACHE STRING "Endianness of the target platform (little|big). Auto-detected if not set.")
set(HITLS_PLATFORM_BITS     "" CACHE STRING "Bitness of the target platform (32|64). Auto-detected if not set.")
option(HITLS_PLATFORM_INT128                "Target compiler supports 128-bit integers" ON)
option(HITLS_AARCH64_PACIASP                "AArch64 PACIASP support" ON)

# ============================================================
# Feature Options
# ============================================================

# Variable options 
set(HITLS_EAL_INIT_OPTS "" CACHE STRING "Eal init options")
set(HITLS_CRYPTO_DRBG_GM_LEVEL "" CACHE STRING "Drbg gm level")
set(HITLS_SEED_DRBG_INIT_RAND_ALG "" CACHE STRING "DRBG Initial Random Algorithm Configuration")
set(HITLS_CONFIG_FILE "" CACHE STRING "Configuration file for Provider Only")

# -- ASM options ---
option(HITLS_ASM        "Enable assembly optimizations"                 OFF)
option(HITLS_ASM_ARMV8  "Enable ARMv8 assembly optimizations"           OFF)
option(HITLS_ASM_ARMV7  "Enable ARMv7 assembly optimizations"           OFF)
option(HITLS_ASM_X8664  "Enable x86_64 assembly optimizations"          OFF)
option(HITLS_ASM_X8664_AVX512  "Enable x86_64 AVX512 assembly optimizations" OFF)
option(HITLS_CRYPTO_ASM_CHECK        "Check for assembly optimizations" OFF)

# --- Top-Level Components ---
option(HITLS_BSL    "Build BSL (Basic Support Library)"  OFF)
option(HITLS_CRYPTO "Build Crypto library "              OFF)
option(HITLS_PKI    "Build PKI library "                 OFF)
option(HITLS_TLS    "Build TLS library "                 OFF)
option(HITLS_AUTH   "Build Authentication library "      OFF)

# --- BSL Features ---
option(HITLS_BSL_SAL                                           "SAL" OFF)
option(HITLS_BSL_SAL_DL                                        "SAL DL" OFF)
option(HITLS_BSL_SAL_FILE                                      "SAL FILE" OFF)
option(HITLS_BSL_SAL_LOCK                                      "SAL LOCK" OFF)
option(HITLS_BSL_SAL_MEM                                       "SAL MEM" OFF)
option(HITLS_BSL_SAL_NET                                       "SAL NET" OFF)
option(HITLS_BSL_SAL_STR                                       "SAL STR" OFF)
option(HITLS_BSL_SAL_THREAD                                    "SAL THREAD" OFF)
option(HITLS_BSL_SAL_TIME                                      "SAL TIME" OFF)
option(HITLS_BSL_SAL_PID                                       "SAL PID" OFF)
option(HITLS_BSL_SAL_IP                                        "SAL IP" OFF)
option(HITLS_BSL_SAL_LINUX                                     "SAL Linux" OFF)
option(HITLS_BSL_SAL_DARWIN                                    "SAL Darwin" OFF)
option(HITLS_ATOMIC_THREAD_LOCK                                "Use atomic operations for thread locking" OFF)
option(HITLS_BSL_ASN1                                          "ASN1" OFF)
option(HITLS_BSL_BASE64                                        "BASE64" OFF)
option(HITLS_BSL_BUFFER                                        "BUFFER" OFF)
option(HITLS_BSL_CONF                                          "CONF" OFF)
option(HITLS_BSL_ERR                                           "ERR" OFF)
option(HITLS_BSL_HASH                                          "HASH" OFF)
option(HITLS_BSL_INIT                                          "INIT" OFF)
option(HITLS_BSL_LIST                                          "LIST" OFF)
option(HITLS_BSL_LOG                                           "LOG" OFF)
option(HITLS_BSL_LOG_NO_FORMAT_STRING                          "BSL_LOG_NO_FORMAT_STRING" OFF)
option(HITLS_BSL_OBJ                                           "OBJ" OFF)
option(HITLS_BSL_OBJ_DEFAULT                                   "OBJ DEFAULT" OFF)
option(HITLS_BSL_OBJ_CUSTOM                                    "OBJ CUSTOM" OFF)
option(HITLS_BSL_PARAMS                                        "PARAMS" OFF)
option(HITLS_BSL_PEM                                           "PEM" OFF)
option(HITLS_BSL_PRINT                                         "PRINT" OFF)
option(HITLS_BSL_TLV                                           "TLV" OFF)
option(HITLS_BSL_UI                                            "UI" OFF)
option(HITLS_BSL_UIO                                           "UIO" OFF)
  option(HITLS_BSL_UIO_BUFFER                                    "UIO BUFFER" OFF)
  option(HITLS_BSL_UIO_FILE                                      "UIO FILE" OFF)
  option(HITLS_BSL_UIO_MEM                                       "UIO MEM" OFF)
  option(HITLS_BSL_UIO_PLT                                       "UIO PLT" OFF)
  option(HITLS_BSL_UIO_SCTP                                      "UIO SCTP" OFF)
  option(HITLS_BSL_UIO_TCP                                       "UIO TCP" OFF)
  option(HITLS_BSL_UIO_UDP                                       "UIO UDP" OFF)
  option(HITLS_BSL_UIO_MTU_QUERY                                 "UIO MTU QUERY" OFF)

# --- CRYPTO Features ---
## Eal
option(HITLS_CRYPTO_EAL                                        "EAL" OFF)
  option(HITLS_CRYPTO_EAL_REPORT                                 "EAL Report" ON)
  option(HITLS_CRYPTO_RAND_CB                                    "Random Callback" OFF)
  option(HITLS_CRYPTO_ENTROPY_GM_CF                              "GM Entropy Configuration" OFF)

## EalInit
option(HITLS_CRYPTO_EALINIT                                    "EAL INIT" OFF)
  option(HITLS_CRYPTO_AUXVAL                                     "Auxiliary Vector" ON)

## Md(Hash)
option(HITLS_CRYPTO_MD                                         "MD" OFF)
  option(HITLS_CRYPTO_MD5                                        "MD5" OFF)
  option(HITLS_CRYPTO_SHA1                                       "SHA1" OFF)
  option(HITLS_CRYPTO_SHA1_SMALL_MEM                             "SHA1 Small Memory" OFF)
  option(HITLS_CRYPTO_SHA2                                       "SHA2" OFF)
    option(HITLS_CRYPTO_SHA224                                     "SHA224" OFF)
    option(HITLS_CRYPTO_SHA256                                     "SHA256" OFF)
    option(HITLS_CRYPTO_SHA256_SMALL_MEM                           "SHA256 Small Memory" OFF)
    option(HITLS_CRYPTO_SHA384                                     "SHA384" OFF)
    option(HITLS_CRYPTO_SHA512                                     "SHA512" OFF)
    option(HITLS_CRYPTO_SHA512_SMALL_MEM                           "SHA512 Small Memory" OFF)
  option(HITLS_CRYPTO_SHA3                                       "SHA3" OFF)
  option(HITLS_CRYPTO_SM3                                        "SM3" OFF)

## Md_mb
option(HITLS_CRYPTO_MD_MB                                      "Multi-Buffer MD" OFF)
  option(HITLS_CRYPTO_SHA2_MB                                    "SHA2 Multi-Buffer" OFF)
    option(HITLS_CRYPTO_SHA256_MB                                  "SHA256 Multi-Buffer" OFF)

## Mac
option(HITLS_CRYPTO_MAC                                        "MAC" OFF)
  option(HITLS_CRYPTO_HMAC                                       "HMAC" OFF)
  option(HITLS_CRYPTO_GMAC                                       "GMAC" OFF)
  option(HITLS_CRYPTO_CMAC                                       "CMAC" OFF)
    option(HITLS_CRYPTO_CMAC_AES                                   "CMAC AES" OFF)
    option(HITLS_CRYPTO_CMAC_SM4                                   "CMAC SM4" OFF)
  option(HITLS_CRYPTO_CBC_MAC                                    "CBC-MAC" OFF)
  option(HITLS_CRYPTO_SIPHASH                                    "SIPHASH" OFF)

## Hpke
option(HITLS_CRYPTO_HPKE                                       "HPKE" OFF)

## Kdf
option(HITLS_CRYPTO_KDF                                        "KDF" OFF)
  option(HITLS_CRYPTO_HKDF                                       "HKDF" OFF)
  option(HITLS_CRYPTO_PBKDF2                                     "PBKDF2" OFF)
  option(HITLS_CRYPTO_SCRYPT                                     "scrypt" OFF)
  option(HITLS_CRYPTO_KDFTLS12                                   "KDF TLS 1.2" OFF)

## Drbg
option(HITLS_CRYPTO_DRBG                                       "DRBG" OFF)
  option(HITLS_CRYPTO_DRBG_CTR                                   "DRBG CTR" OFF)
  option(HITLS_CRYPTO_DRBG_HASH                                  "DRBG HASH" OFF)
  option(HITLS_CRYPTO_DRBG_HMAC                                  "DRBG HMAC" OFF)
  option(HITLS_CRYPTO_DRBG_GM                                    "DRBG GM" OFF)

## Entropy
option(HITLS_CRYPTO_ENTROPY                                    "Entropy" OFF)
  option(HITLS_CRYPTO_ENTROPY_HARDWARE                           "Hardware Entropy" OFF)
  option(HITLS_CRYPTO_ENTROPY_DEVRANDOM                          "DevRandom Entropy" OFF)
  option(HITLS_CRYPTO_ENTROPY_GETENTROPY                         "getentropy() Entropy" OFF)
  option(HITLS_CRYPTO_ENTROPY_SYS                                "SysRandom Entropy" OFF)

## Modes
option(HITLS_CRYPTO_MODES                                      "Cipher Modes" OFF)
  option(HITLS_CRYPTO_GCM                                        "GCM" OFF)
  option(HITLS_CRYPTO_CBC                                        "CBC" OFF)
  option(HITLS_CRYPTO_CTR                                        "CTR" OFF)
  option(HITLS_CRYPTO_CCM                                        "CCM" OFF)
  option(HITLS_CRYPTO_ECB                                        "ECB" OFF)
  option(HITLS_CRYPTO_XTS                                        "XTS" OFF)
  option(HITLS_CRYPTO_CFB                                        "CFB" OFF)
    option(HITLS_CRYPTO_CFB128                                     "CFB128" OFF)
  option(HITLS_CRYPTO_OFB                                        "OFB" OFF)
  option(HITLS_CRYPTO_HCTR                                       "HCTR" OFF)
  option(HITLS_CRYPTO_CHACHA20POLY1305                           "CHACHA20-POLY1305" OFF)
  option(HITLS_CRYPTO_WRAP                                       "Key Wrap Mode" OFF)
  option(HITLS_CRYPTO_GHASH                                      "GHASH" OFF)

## Cipher
option(HITLS_CRYPTO_CIPHER                                     "Cipher" OFF)
  option(HITLS_CRYPTO_AES                                        "AES" OFF)
    option(HITLS_CRYPTO_AES_PRECALC_TABLES                         "AES Precalculated Tables" ON)
  option(HITLS_CRYPTO_SM4                                        "SM4" OFF)
  option(HITLS_CRYPTO_CHACHA20                                   "CHACHA20" OFF)

## Pkey
option(HITLS_CRYPTO_PKEY                                       "Public Key Cryptography" OFF)
  option(HITLS_CRYPTO_PKEY_CMP                                   "Public Key Compare" OFF)
  option(HITLS_CRYPTO_DSA                                        "DSA" OFF)
    option(HITLS_CRYPTO_DSA_CHECK                                  "DSA Check" OFF)
    option(HITLS_CRYPTO_DSA_CMP                                    "DSA Compare" OFF)
    option(HITLS_CRYPTO_DSA_GEN_PARA                               "DSA Parameter Generation" OFF)
  option(HITLS_CRYPTO_CURVE25519                                 "Curve25519" OFF)
    option(HITLS_CRYPTO_CURVE25519_CMP                             "Curve25519 Compare" OFF)
    option(HITLS_CRYPTO_ED25519                                    "Ed25519" OFF)
      option(HITLS_CRYPTO_ED25519_CHECK                              "Ed25519 Check" OFF)
    option(HITLS_CRYPTO_X25519                                     "X25519" OFF)
      option(HITLS_CRYPTO_X25519_CHECK                               "X25519 Check" OFF)
  option(HITLS_CRYPTO_RSA                                        "RSA" OFF)
    option(HITLS_CRYPTO_RSA_GEN                                    "RSA Generate" OFF)
    option(HITLS_CRYPTO_RSA_SIGN                                   "RSA Sign" OFF)
    option(HITLS_CRYPTO_RSA_VERIFY                                 "RSA Verify" OFF)
    option(HITLS_CRYPTO_RSA_RECOVER                                "RSA Recover" OFF)
    option(HITLS_CRYPTO_RSA_ENCRYPT                                "RSA Encrypt" OFF)
    option(HITLS_CRYPTO_RSA_DECRYPT                                "RSA Decrypt" OFF)
    option(HITLS_CRYPTO_RSA_PAD                                    "RSA Padding" OFF)
      option(HITLS_CRYPTO_RSA_NO_PAD                                 "RSA No Padding" OFF)
      option(HITLS_CRYPTO_RSAES_OAEP                                 "RSAES OAEP" OFF)
      option(HITLS_CRYPTO_RSAES_PKCSV15                              "RSAES PKCS#1 v1.5" OFF)
      option(HITLS_CRYPTO_RSAES_PKCSV15_TLS                          "RSAES PKCS#1 v1.5 TLS" OFF)
      option(HITLS_CRYPTO_RSA_EMSA_ISO9796_2                         "RSA EMSA ISO9796-2" OFF)
      option(HITLS_CRYPTO_RSA_EMSA_PKCSV15                           "RSA EMSA PKCS#1 v1.5" OFF)
      option(HITLS_CRYPTO_RSA_EMSA_PSS                               "RSA EMSA PSS" OFF)
    option(HITLS_CRYPTO_RSA_BLINDING                               "RSA Blinding" OFF)
    option(HITLS_CRYPTO_RSA_BSSA                                   "RSA BSSA" OFF)
    option(HITLS_CRYPTO_RSA_CMP                                    "RSA Compare" OFF)
    option(HITLS_CRYPTO_RSA_CHECK                                  "RSA Check" OFF)
    option(HITLS_CRYPTO_SP800_STRICT_CHECK                         "SP800-56B Strict Check" OFF)
  option(HITLS_CRYPTO_DH                                         "Diffie-Hellman" OFF)
    option(HITLS_CRYPTO_DH_CMP                                     "Diffie-Hellman Compare" OFF)
    option(HITLS_CRYPTO_DH_CHECK                                   "Diffie-Hellman Check" OFF)
  option(HITLS_CRYPTO_ECC                                        "Elliptic Curve Cryptography" OFF)
    option(HITLS_CRYPTO_ECC_CMP                                    "Elliptic Curve Compare" OFF)
    option(HITLS_CRYPTO_ECC_CHECK                                  "Elliptic Curve Check" OFF)
    option(HITLS_CRYPTO_CURVE_MONT                                 "Montgomery Curve" OFF)
      option(HITLS_CRYPTO_CURVE_MONT_NIST                            "Montgomery NIST Curve" OFF)
      option(HITLS_CRYPTO_CURVE_MONT_PRIME                           "Montgomery Prime Curve" OFF)
    option(HITLS_CRYPTO_CURVE_BP256R1                              "Brainpool P256r1" OFF)
    option(HITLS_CRYPTO_CURVE_BP384R1                              "Brainpool P384r1" OFF)
    option(HITLS_CRYPTO_CURVE_BP512R1                              "Brainpool P512r1" OFF)
    option(HITLS_CRYPTO_CURVE_NISTP192                             "NIST P-192" OFF)
    option(HITLS_CRYPTO_CURVE_NISTP224                             "NIST P-224" OFF)
    option(HITLS_CRYPTO_CURVE_NISTP256                             "NIST P-256" OFF)
    option(HITLS_CRYPTO_CURVE_NISTP384                             "NIST P-384" OFF)
    option(HITLS_CRYPTO_CURVE_NISTP521                             "NIST P-521" OFF)
    option(HITLS_CRYPTO_CURVE_SM2                                  "SM2 Curve" OFF)
    option(HITLS_CRYPTO_NIST_ECC_ACCELERATE                        "NIST ECC Accelerate" ON)
    option(HITLS_CRYPTO_NIST_USE_ACCEL                             "Use NIST ECC Accelerate" OFF)
  option(HITLS_CRYPTO_ECDSA                                      "Elliptic Curve Digital Signature Algorithm" OFF)
    option(HITLS_CRYPTO_ECDSA_CMP                                  "ECDSA Compare" OFF)
    option(HITLS_CRYPTO_ECDSA_CHECK                                "ECDSA Check" OFF)
  option(HITLS_CRYPTO_ECDH                                       "Elliptic Curve Diffie-Hellman" OFF)
    option(HITLS_CRYPTO_ECDH_CMP                                   "ECDH Compare" OFF)
    option(HITLS_CRYPTO_ECDH_CHECK                                 "ECDH Check" OFF)
  option(HITLS_CRYPTO_SM2                                        "SM2" OFF)
    option(HITLS_CRYPTO_SM2_SIGN                                   "SM2 Sign" OFF)
    option(HITLS_CRYPTO_SM2_CRYPT                                  "SM2 Cryptography" OFF)
    option(HITLS_CRYPTO_SM2_EXCH                                   "SM2 Key Exchange" OFF)
    option(HITLS_CRYPTO_SM2_CMP                                    "SM2 Compare" OFF)
    option(HITLS_CRYPTO_SM2_CHECK                                  "SM2 Check" OFF)
  option(HITLS_CRYPTO_SM9                                        "SM9 Public Key Encryption" OFF)
    option(HITLS_CRYPTO_SM9_CRYPT                                  "SM9 Cryptography" OFF)
    option(HITLS_CRYPTO_SM9_EXCH                                   "SM9 Key Exchange" OFF)
    option(HITLS_CRYPTO_SM9_SIGN                                   "SM9 Sign" OFF)
    option(HITLS_CRYPTO_SM9_CMP                                    "SM9 Compare" OFF)
    option(HITLS_CRYPTO_SM9_CHECK                                  "SM9 Check" OFF)
  option(HITLS_CRYPTO_PAILLIER                                   "Paillier Cryptosystem" OFF)
  option(HITLS_CRYPTO_ELGAMAL                                    "ElGamal Public Key Encryption" OFF)
  option(HITLS_CRYPTO_XMSS                                       "XMSS" OFF)
    option(HITLS_CRYPTO_XMSS_CHECK                                 "XMSS Check" OFF)
  option(HITLS_CRYPTO_SLH_DSA                                    "SLH DSA" OFF)
    option(HITLS_CRYPTO_SLH_DSA_CHECK                              "SLH DSA Check" OFF)
  option(HITLS_CRYPTO_MLKEM                                      "MLKEM" OFF)
    option(HITLS_CRYPTO_MLKEM_CMP                                  "MLKEM Compare" OFF)
    option(HITLS_CRYPTO_MLKEM_CHECK                                "MLKEM Check" OFF)
  option(HITLS_CRYPTO_FRODOKEM                                   "FrodoKEM" OFF)
    option(HITLS_CRYPTO_FRODOKEM_CMP                               "FrodoKEM Compare" OFF)
  option(HITLS_CRYPTO_MCELIECE                                   "Classic McEliece" OFF)
    option(HITLS_CRYPTO_MCELIECE_CMP                               "Classic McEliece Compare" OFF)
  option(HITLS_CRYPTO_HYBRIDKEM                                  "Hybrid Key Encapsulation Mechanism" OFF)
  option(HITLS_CRYPTO_MLDSA                                      "MLDSA" OFF)
    option(HITLS_CRYPTO_MLDSA_CMP                                  "MLDSA Compare" OFF)
    option(HITLS_CRYPTO_MLDSA_CHECK                                "MLDSA Check" OFF)
  option(HITLS_CRYPTO_ACVP_TESTS                                 "ACVP Tests" OFF)
  option(HITLS_SM2_PRECOMPUTE_512K_TBL                           "SM2 512K Precomputation Table" OFF)
## Provider
option(HITLS_CRYPTO_PROVIDER                                   "Provider" OFF)
  option(HITLS_CRYPTO_CMVP                                       "CMVP" OFF)
  option(HITLS_CRYPTO_CMVP_FIPS                                  "CMVP FIPS" OFF)
  option(HITLS_CRYPTO_CMVP_ISO19790                              "CMVP ISO 19790" OFF)
  option(HITLS_CRYPTO_CMVP_SM                                    "CMVP SM" OFF)
## Bn
option(HITLS_CRYPTO_BN                                         "BigNum" OFF)
  option(HITLS_CRYPTO_BN_BASIC                                   "BigNum Basic" OFF)
  option(HITLS_CRYPTO_BN_RAND                                    "BigNum Random" OFF)
  option(HITLS_CRYPTO_BN_PRIME                                   "BigNum Prime Generation" OFF)
  option(HITLS_CRYPTO_BN_RFC_PRIME                               "BigNum RFC Prime Generation" OFF)
  option(HITLS_CRYPTO_BN_COMBA                                   "BigNum Comba Multiplication" ON)
  option(HITLS_CRYPTO_BN_SMALL_MEM                               "BigNum Small Memory" OFF)
  option(HITLS_CRYPTO_BN_STR_CONV                                "BigNum String Conversion" OFF)
  option(HITLS_CRYPTO_BN_CB                                      "BigNum CB Multiplication" OFF)
  option(HITLS_CRYPTO_EAL_BN                                     "EAL BigNum" OFF)

## CodecsKey
option(HITLS_CRYPTO_CODECSKEY                                  "Key encoding/decoding (PKCS#8, etc.)" OFF)
  option(HITLS_CRYPTO_KEY_DECODE                                 "Key decoding" OFF)
  option(HITLS_CRYPTO_KEY_ENCODE                                 "Key encoding" OFF)
  option(HITLS_CRYPTO_KEY_EPKI                                   "Key EPKI" OFF)
  option(HITLS_CRYPTO_KEY_INFO                                   "Key info" OFF)

## DecodeChain
option(HITLS_CRYPTO_KEY_DECODE_CHAIN                           "Key decoding chain" OFF)

## Codecs
option(HITLS_CRYPTO_CODECS                                     "Codecs" OFF)

# --- Crypto Assembling Options ---
## BN
option(HITLS_CRYPTO_BN_ASM                                     "BigNum ASM" OFF)
option(HITLS_CRYPTO_BN_ARMV8                                   "BigNum ARMv8" OFF)
option(HITLS_CRYPTO_BN_X8664                                   "BigNum x86_64" OFF)
## Cipher
option(HITLS_CRYPTO_AES_ASM                                    "AES ASM" OFF)
option(HITLS_CRYPTO_AES_ARMV8                                  "AES ARMv8" OFF)
option(HITLS_CRYPTO_AES_X8664                                  "AES x86_64" OFF)
option(HITLS_CRYPTO_SM4_ASM                                    "SM4 ASM" OFF)
option(HITLS_CRYPTO_SM4_ARMV8                                  "SM4 ARMv8" OFF)
option(HITLS_CRYPTO_SM4_X8664                                  "SM4 x86_64" OFF)
option(HITLS_CRYPTO_CHACHA20_ASM                               "ChaCha20 ASM" OFF)
option(HITLS_CRYPTO_CHACHA20_ARMV8                             "ChaCha20 ARMv8" OFF)
option(HITLS_CRYPTO_CHACHA20_X8664                             "ChaCha20 x86_64" OFF)
option(HITLS_CRYPTO_CHACHA20_X8664_AVX512                      "ChaCha20 x86_64 AVX512" OFF)
## Cipher Modes
option(HITLS_CRYPTO_MODES_ASM                                  "Cipher Modes ASM" OFF)
option(HITLS_CRYPTO_MODES_ARMV8                                "Cipher Modes ARMv8" OFF)
option(HITLS_CRYPTO_MODES_X8664                                "Cipher Modes x86_64" OFF)
option(HITLS_CRYPTO_MODES_X8664_AVX512                         "Cipher Modes x86_64 AVX512" OFF)
option(HITLS_CRYPTO_GCM_ASM                                    "GCM ASM" OFF)
option(HITLS_CRYPTO_GCM_ARMV8                                  "GCM ARMv8" OFF)
option(HITLS_CRYPTO_GCM_X8664                                  "GCM x86_64" OFF)
option(HITLS_CRYPTO_CHACHA20POLY1305_ASM                       "ChaCha20-Poly1305 ASM" OFF)
option(HITLS_CRYPTO_CHACHA20POLY1305_X8664                     "ChaCha20-Poly1305 x86_64" OFF)
option(HITLS_CRYPTO_CHACHA20POLY1305_X8664_AVX512              "ChaCha20-Poly1305 x86_64 AVX512" OFF)
option(HITLS_CRYPTO_GHASH_ASM                                  "GHASH ASM" OFF)
option(HITLS_CRYPTO_GHASH_ARMV8                                "GHASH ARMv8" OFF)
option(HITLS_CRYPTO_GHASH_X8664                                "GHASH x86_64" OFF)
## HASH
option(HITLS_CRYPTO_MD5_ASM                                    "MD5 ASM" OFF)
option(HITLS_CRYPTO_MD5_X8664                                  "MD5 x86_64" OFF)
option(HITLS_CRYPTO_SHA1_ASM                                   "SHA1 ASM" OFF)
option(HITLS_CRYPTO_SHA1_ARMV8                                 "SHA1 ARMv8" OFF)
option(HITLS_CRYPTO_SHA1_X8664                                 "SHA1 x86_64" OFF)
option(HITLS_CRYPTO_SHA2_ASM                                   "SHA2 ASM" OFF)
option(HITLS_CRYPTO_SHA2_ARMV8                                 "SHA2 ARMv8" OFF)
option(HITLS_CRYPTO_SHA2_X8664                                 "SHA2 x86_64" OFF)
option(HITLS_CRYPTO_SHA256_ARMV8                               "SHA256 ARMv8" OFF)
option(HITLS_CRYPTO_SHA256_X8664                               "SHA256 x86_64" OFF)
option(HITLS_CRYPTO_SHA512_ARMV8                               "SHA512 ARMv8" OFF)
option(HITLS_CRYPTO_SHA512_X8664                               "SHA512 x86_64" OFF)
option(HITLS_CRYPTO_SHA3_ASM                                   "SHA3 ASM" OFF)
option(HITLS_CRYPTO_SHA3_ARMV8                                 "SHA3 ARMv8" OFF)
option(HITLS_CRYPTO_SM3_ASM                                    "SM3 ASM" OFF)
option(HITLS_CRYPTO_SM3_ARMV8                                  "SM3 ARMv8" OFF)
option(HITLS_CRYPTO_SM3_ARMV7                                  "SM3 ARMv7" OFF)
option(HITLS_CRYPTO_SM3_X8664                                  "SM3 x86_64" OFF)
## ECC
option(HITLS_CRYPTO_ECC_ASM                                    "ECC ASM" OFF)
option(HITLS_CRYPTO_ECC_ARMV8                                  "ECC ARMv8" OFF)
option(HITLS_CRYPTO_ECC_ARMV7                                  "ECC ARMv7" OFF)
option(HITLS_CRYPTO_ECC_X8664                                  "ECC x86_64" OFF)
option(HITLS_CRYPTO_CURVE_NISTP256_ASM                         "Curve NIST P-256 ASM" OFF)
option(HITLS_CRYPTO_CURVE_NISTP256_ARMV8                       "Curve NIST P-256 ARMv8" OFF)
option(HITLS_CRYPTO_CURVE_NISTP256_X8664                       "Curve NIST P-256 x86_64" OFF)
option(HITLS_CRYPTO_CURVE_NISTP384_ASM                         "Curve NIST P-384 ASM" OFF)
option(HITLS_CRYPTO_CURVE_NISTP384_ARMV8                       "Curve NIST P-384 ARMv8" OFF)
option(HITLS_CRYPTO_CURVE_NISTP384_X8664                       "Curve NIST P-384 x86_64" OFF)
option(HITLS_CRYPTO_CURVE_SM2_ASM                              "Curve SM2 ASM" OFF)
option(HITLS_CRYPTO_CURVE_SM2_ARMV8                            "Curve SM2 ARMv8" OFF)
option(HITLS_CRYPTO_CURVE_SM2_ARMV7                            "Curve SM2 ARMv7" OFF)
option(HITLS_CRYPTO_CURVE_SM2_X8664                            "Curve SM2 x86_64" OFF)
option(HITLS_CRYPTO_X25519_ASM                                 "X25519 ASM" OFF)
option(HITLS_CRYPTO_X25519_ARMV8                               "X25519 ARMv8" OFF)
option(HITLS_CRYPTO_X25519_X8664                               "X25519 x86_64" OFF)

# --- PKI Features ---
## X509
option(HITLS_PKI_X509                                          "X509" OFF)
  option(HITLS_PKI_X509_CRT                                      "X509 Certificate" OFF)
    option(HITLS_PKI_X509_CRT_GEN                                  "X509 Certificate Generation" OFF)
    option(HITLS_PKI_X509_CRT_PARSE                                "X509 Certificate Parse" OFF)
    option(HITLS_PKI_X509_CRT_AUTH                                 "X509 Certificate Authority" OFF)
  option(HITLS_PKI_X509_CSR                                      "X509 CSR" OFF)
    option(HITLS_PKI_X509_CSR_GEN                                  "X509 CSR Generation" OFF)
    option(HITLS_PKI_X509_CSR_PARSE                                "X509 CSR Parse" OFF)
    option(HITLS_PKI_X509_CSR_ATTR                                 "X509 CSR Attribute" OFF)
    option(HITLS_PKI_X509_CSR_GET                                  "X509 CSR Get" OFF)
  option(HITLS_PKI_X509_CRL                                      "X509 CRL" OFF)
    option(HITLS_PKI_X509_CRL_GEN                                  "X509 CRL Generation" OFF)
    option(HITLS_PKI_X509_CRL_PARSE                                "X509 CRL Parse" OFF)
  option(HITLS_PKI_X509_VFY                                      "X509 Verify" OFF)
    option(HITLS_PKI_X509_VFY_DEFAULT                              "X509 Verify Default" OFF)
    option(HITLS_PKI_X509_VFY_CB                                   "X509 Verify Callback" OFF)
    option(HITLS_PKI_X509_VFY_LOCATION                             "X509 Verify Location" OFF)
    option(HITLS_PKI_X509_VFY_IDENTITY                             "X509 Verify Hostname" OFF)

## CMS
option(HITLS_PKI_CMS                                           "CMS" OFF)
  option(HITLS_PKI_CMS_DATA                                      "CMS Data" OFF)
  option(HITLS_PKI_CMS_DIGESTINFO                                "CMS DigestInfo" OFF)
  option(HITLS_PKI_CMS_SIGNEDDATA                                "CMS SignedData" OFF)
  option(HITLS_PKI_CMS_ENCRYPTDATA                               "CMS EncryptedData" OFF)

## PKCS12
option(HITLS_PKI_PKCS12                                        "PKCS12" OFF)
  option(HITLS_PKI_PKCS12_GEN                                    "PKCS12 Generation" OFF)
  option(HITLS_PKI_PKCS12_PARSE                                  "PKCS12 Parse" OFF)

## Info/Print
option(HITLS_PKI_INFO                                          "PKI Info" OFF)
  option(HITLS_PKI_INFO_DN_CONF                                  "PKI Info DN Config" OFF)
  option(HITLS_PKI_INFO_DN_HASH                                  "PKI Info DN Hash" OFF)
  option(HITLS_PKI_INFO_CRT                                      "PKI Info Certificate" OFF)
  option(HITLS_PKI_INFO_CSR                                      "PKI Info CSR" OFF)
  option(HITLS_PKI_INFO_CRL                                      "PKI Info CRL" OFF)

# --- TLS Features ---
option(HITLS_TLS_PROTO_TLS                                     "TLS Protocol TLS" OFF)
option(HITLS_TLS_PROTO_TLS_BASIC                               "TLS Protocol TLS Basic" OFF)
option(HITLS_TLS_PROTO_DTLS                                    "TLS Protocol DTLS" OFF)

## TLS Proto Version
option(HITLS_TLS_PROTO_VERSION                                 "TLS Protocol Versions" OFF)
  option(HITLS_TLS_PROTO_TLS12                                   "TLS Protocol TLS 1.2" OFF)
  option(HITLS_TLS_PROTO_TLS13                                   "TLS Protocol TLS 1.3" OFF)
  option(HITLS_TLS_PROTO_TLCP11                                  "TLS Protocol TLCP 1.1" OFF)
  option(HITLS_TLS_PROTO_DTLS12                                  "TLS Protocol DTLS 1.2" OFF)
  option(HITLS_TLS_PROTO_DTLCP11                                 "TLS Protocol DTLCP 1.1" OFF)

## TLS Host
option(HITLS_TLS_HOST                                          "TLS Host" OFF)
  option(HITLS_TLS_HOST_CLIENT                                   "TLS Host Client" OFF)
  option(HITLS_TLS_HOST_SERVER                                   "TLS Host Server" OFF)

## TLS Callback / Provider
option(HITLS_TLS_CALLBACK                                      "TLS Callback" OFF)
  option(HITLS_TLS_FEATURE_PROVIDER                              "TLS Feature Provider" OFF)
    option(HITLS_TLS_FEATURE_PROVIDER_HARD_CODING                  "TLS Feature Provider Hard Coding" OFF)
    option(HITLS_TLS_FEATURE_PROVIDER_DYNAMIC                      "TLS Feature Provider Dynamic" OFF)
  option(HITLS_TLS_CALLBACK_SAL                                  "TLS Callback SAL" OFF)
  option(HITLS_TLS_CALLBACK_CERT                                 "TLS Callback Cert" OFF)
  option(HITLS_TLS_CALLBACK_CRYPT                                "TLS Callback Crypt" OFF)
  option(HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES                "TLS Callback Crypt HMAC Primitives" OFF)

## TLS Features
option(HITLS_TLS_FEATURE                                       "TLS Feature" OFF)
  option(HITLS_TLS_FEATURE_RENEGOTIATION                         "TLS Feature Renegotiation" OFF)
  option(HITLS_TLS_FEATURE_ALPN                                  "TLS Feature ALPN" OFF)
  option(HITLS_TLS_FEATURE_SNI                                   "TLS Feature SNI" OFF)
  option(HITLS_TLS_FEATURE_PHA                                   "TLS Feature Post-Handshake Authentication" OFF)
  option(HITLS_TLS_FEATURE_PSK                                   "TLS Feature PSK" OFF)
  option(HITLS_TLS_FEATURE_SECURITY                              "TLS Feature Security" OFF)
  option(HITLS_TLS_FEATURE_INDICATOR                             "TLS Feature Indicator" OFF)
  option(HITLS_TLS_FEATURE_SESSION                               "TLS Feature Session" OFF)
    option(HITLS_TLS_FEATURE_SESSION_TICKET                        "TLS Feature Session Ticket" OFF)
    option(HITLS_TLS_FEATURE_SESSION_ID                            "TLS Feature Session ID" OFF)
    option(HITLS_TLS_FEATURE_SESSION_CACHE_CB                      "TLS Feature Session Cache Callback" OFF)
    option(HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET                 "TLS Feature Session Custom Ticket" OFF)
  option(HITLS_TLS_FEATURE_EXPORT_KEY_MATERIAL                   "TLS Feature Export Key Material" OFF)
  option(HITLS_TLS_FEATURE_MODE                                  "TLS Feature Mode" OFF)
    option(HITLS_TLS_FEATURE_MODE_FALL_BACK_SCSV                   "TLS Feature Mode Fall Back SCSV" OFF)
    option(HITLS_TLS_FEATURE_MODE_AUTO_RETRY                       "TLS Feature Mode Auto Retry" OFF)
    option(HITLS_TLS_FEATURE_MODE_ACCEPT_MOVING_WRITE_BUFFER       "TLS Feature Mode Accept Moving Write Buffer" OFF)
    option(HITLS_TLS_FEATURE_MODE_RELEASE_BUFFERS                  "TLS Feature Mode Release Buffers" OFF)
  option(HITLS_TLS_FEATURE_KEY_UPDATE                            "TLS Feature Key Update" OFF)
  option(HITLS_TLS_FEATURE_FLIGHT                                "TLS Feature Flight" OFF)
  option(HITLS_TLS_FEATURE_CERT_MODE                             "TLS Feature Cert Mode" OFF)
    option(HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY               "TLS Feature Cert Mode Client Verify" OFF)
    option(HITLS_TLS_FEATURE_CERT_MODE_VERIFY_PEER                 "TLS Feature Cert Mode Verify Peer" OFF)
  option(HITLS_TLS_FEATURE_ANTI_REPLAY                           "TLS Feature Anti-Replay" OFF)
  option(HITLS_TLS_FEATURE_EXTENDED_MASTER_SECRET                "TLS Feature Extended Master Secret" OFF)
  option(HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT                     "TLS Feature Record Size Limit" OFF)
  option(HITLS_TLS_FEATURE_KEM                                   "TLS Feature KEM" OFF)
  option(HITLS_TLS_FEATURE_CLIENT_HELLO_CB                       "TLS Feature Client Hello Callback" OFF)
  option(HITLS_TLS_FEATURE_CERT_CB                               "TLS Feature Cert Callback" OFF)
  option(HITLS_TLS_FEATURE_MAX_SEND_FRAGMENT                     "TLS Feature Max Send Fragment" OFF)
  option(HITLS_TLS_FEATURE_REC_INBUFFER_SIZE                     "TLS Feature Record Inbuffer Size" OFF)
  option(HITLS_TLS_FEATURE_CUSTOM_EXTENSION                      "TLS Feature Custom Extension" OFF)
  option(HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES               "TLS Feature Certificate Authorities" OFF)
  option(HITLS_TLS_FEATURE_MTU_QUERY                             "TLS Feature MTU Query" OFF)
  option(HITLS_TLS_FEATURE_SM_TLS13                              "TLS Feature SM TLS 1.3" OFF)
  option(HITLS_TLS_FEATURE_DEFAULT_COOKIE                        "TLS Feature Default Cookie" OFF)
  option(HITLS_TLS_FEATURE_ETM                                   "TLS Feature Encrypt-Then-MAC" OFF)

## TLS Proto Module
option(HITLS_TLS_PROTO                                         "TLS Proto Module" OFF)
  option(HITLS_TLS_PROTO_CLOSE_STATE                             "TLS Proto Close State" OFF)
  option(HITLS_TLS_PROTO_DFX                                     "TLS Proto DFX" OFF)
    option(HITLS_TLS_PROTO_DFX_CHECK                               "TLS Proto DFX Check" OFF)
    option(HITLS_TLS_PROTO_DFX_INFO                                "TLS Proto DFX Info" OFF)
    option(HITLS_TLS_PROTO_DFX_ALERT_NUMBER                        "TLS Proto DFX Alert Number" OFF)
    option(HITLS_TLS_PROTO_DFX_SERVER_PREFER                       "TLS Proto DFX Server Prefer" OFF)

## TLS Config
option(HITLS_TLS_CONFIG                                        "TLS Config" OFF)
  option(HITLS_TLS_CONFIG_MANUAL_DH                              "TLS Config Manual DH" OFF)
  option(HITLS_TLS_CONFIG_CERT                                   "TLS Config Cert" OFF)
    option(HITLS_TLS_CONFIG_CERT_LOAD_FILE                         "TLS Config Cert Load File" OFF)
    option(HITLS_TLS_CONFIG_CERT_CALLBACK                          "TLS Config Cert Callback" OFF)
    option(HITLS_TLS_CONFIG_CERT_BUILD_CHAIN                       "TLS Config Cert Build Chain" OFF)
    option(HITLS_TLS_CONFIG_CERT_VERIFY_LOCATION                   "TLS Config Cert Verify Location" OFF)
    option(HITLS_TLS_CONFIG_CERT_CRL                               "TLS Config Cert CRL" OFF)
  option(HITLS_TLS_CONFIG_KEY_USAGE                              "TLS Config Key Usage" OFF)
  option(HITLS_TLS_CONFIG_STATE                                  "TLS Config State" OFF)
  option(HITLS_TLS_CONFIG_RECORD_PADDING                         "TLS Config Record Padding" OFF)
  option(HITLS_TLS_CONFIG_USER_DATA                              "TLS Config User Data" OFF)
  option(HITLS_TLS_CONFIG_CIPHER_SUITE                           "TLS Config Cipher Suite" OFF)
  option(HITLS_TLS_CONFIG_VERSION                                "TLS Config Version" OFF)

## TLS Connection
option(HITLS_TLS_CONNECTION                                    "TLS Connection" OFF)
  option(HITLS_TLS_CONNECTION_INFO_NEGOTIATION                   "TLS Connection Info Negotiation" OFF)

## TLS Cipher Suites
option(HITLS_TLS_SUITE                                         "TLS Cipher Suites" OFF)
  option(HITLS_TLS_SUITE_AES_128_GCM_SHA256                      "TLS Suite AES-128-GCM-SHA256 (TLS 1.3)" OFF)
  option(HITLS_TLS_SUITE_AES_256_GCM_SHA384                      "TLS Suite AES-256-GCM-SHA384 (TLS 1.3)" OFF)
  option(HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256                "TLS Suite CHACHA20-POLY1305-SHA256 (TLS 1.3)" OFF)
  option(HITLS_TLS_SUITE_AES_128_CCM_SHA256                      "TLS Suite AES-128-CCM-SHA256 (TLS 1.3)" OFF)
  option(HITLS_TLS_SUITE_AES_128_CCM_8_SHA256                    "TLS Suite AES-128-CCM-8-SHA256 (TLS 1.3)" OFF)
  option(HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA                "TLS Suite RSA-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA                "TLS Suite RSA-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA256             "TLS Suite RSA-AES-128-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA256             "TLS Suite RSA-AES-256-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_RSA_WITH_AES_128_GCM_SHA256             "TLS Suite RSA-AES-128-GCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_RSA_WITH_AES_256_GCM_SHA384             "TLS Suite RSA-AES-256-GCM-SHA384" OFF)
  option(HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM                    "TLS Suite RSA-AES-128-CCM" OFF)
  option(HITLS_TLS_SUITE_RSA_WITH_AES_128_CCM_8                  "TLS Suite RSA-AES-128-CCM-8" OFF)
  option(HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM                    "TLS Suite RSA-AES-256-CCM" OFF)
  option(HITLS_TLS_SUITE_RSA_WITH_AES_256_CCM_8                  "TLS Suite RSA-AES-256-CCM-8" OFF)
  option(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256         "TLS Suite DHE-RSA-AES-128-GCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384         "TLS Suite DHE-RSA-AES-256-GCM-SHA384" OFF)
  option(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA            "TLS Suite DHE-RSA-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA            "TLS Suite DHE-RSA-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256         "TLS Suite DHE-RSA-AES-128-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256         "TLS Suite DHE-RSA-AES-256-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CCM                "TLS Suite DHE-RSA-AES-128-CCM" OFF)
  option(HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CCM                "TLS Suite DHE-RSA-AES-256-CCM" OFF)
  option(HITLS_TLS_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256   "TLS Suite DHE-RSA-CHACHA20-POLY1305-SHA256" OFF)
  option(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_GCM_SHA256         "TLS Suite DHE-DSS-AES-128-GCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_GCM_SHA384         "TLS Suite DHE-DSS-AES-256-GCM-SHA384" OFF)
  option(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA            "TLS Suite DHE-DSS-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA            "TLS Suite DHE-DSS-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA256         "TLS Suite DHE-DSS-AES-128-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA256         "TLS Suite DHE-DSS-AES-256-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA        "TLS Suite ECDHE-ECDSA-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA        "TLS Suite ECDHE-ECDSA-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256     "TLS Suite ECDHE-ECDSA-AES-128-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384     "TLS Suite ECDHE-ECDSA-AES-256-CBC-SHA384" OFF)
  option(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256     "TLS Suite ECDHE-ECDSA-AES-128-GCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384     "TLS Suite ECDHE-ECDSA-AES-256-GCM-SHA384" OFF)
  option(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM            "TLS Suite ECDHE-ECDSA-AES-128-CCM" OFF)
  option(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM            "TLS Suite ECDHE-ECDSA-AES-256-CCM" OFF)
  option(HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 "TLS Suite ECDHE-ECDSA-CHACHA20-POLY1305-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA          "TLS Suite ECDHE-RSA-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA          "TLS Suite ECDHE-RSA-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256       "TLS Suite ECDHE-RSA-AES-128-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384       "TLS Suite ECDHE-RSA-AES-256-CBC-SHA384" OFF)
  option(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256       "TLS Suite ECDHE-RSA-AES-128-GCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384       "TLS Suite ECDHE-RSA-AES-256-GCM-SHA384" OFF)
  option(HITLS_TLS_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 "TLS Suite ECDHE-RSA-CHACHA20-POLY1305-SHA256" OFF)
  option(HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA            "TLS Suite DH-ANON-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA            "TLS Suite DH-ANON-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_CBC_SHA256         "TLS Suite DH-ANON-AES-128-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_CBC_SHA256         "TLS Suite DH-ANON-AES-256-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_DH_ANON_WITH_AES_128_GCM_SHA256         "TLS Suite DH-ANON-AES-128-GCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_DH_ANON_WITH_AES_256_GCM_SHA384         "TLS Suite DH-ANON-AES-256-GCM-SHA384" OFF)
  option(HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_128_CBC_SHA          "TLS Suite ECDH-ANON-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_ECDH_ANON_WITH_AES_256_CBC_SHA          "TLS Suite ECDH-ANON-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA                "TLS Suite PSK-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA                "TLS Suite PSK-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA256             "TLS Suite PSK-AES-128-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA384             "TLS Suite PSK-AES-256-CBC-SHA384" OFF)
  option(HITLS_TLS_SUITE_PSK_WITH_AES_128_GCM_SHA256             "TLS Suite PSK-AES-128-GCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_PSK_WITH_AES_256_GCM_SHA384             "TLS Suite PSK-AES-256-GCM-SHA384" OFF)
  option(HITLS_TLS_SUITE_PSK_WITH_AES_256_CCM                    "TLS Suite PSK-AES-256-CCM" OFF)
  option(HITLS_TLS_SUITE_PSK_WITH_CHACHA20_POLY1305_SHA256       "TLS Suite PSK-CHACHA20-POLY1305-SHA256" OFF)
  option(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA            "TLS Suite DHE-PSK-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA            "TLS Suite DHE-PSK-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA256         "TLS Suite DHE-PSK-AES-128-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA384         "TLS Suite DHE-PSK-AES-256-CBC-SHA384" OFF)
  option(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_GCM_SHA256         "TLS Suite DHE-PSK-AES-128-GCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_GCM_SHA384         "TLS Suite DHE-PSK-AES-256-GCM-SHA384" OFF)
  option(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CCM                "TLS Suite DHE-PSK-AES-128-CCM" OFF)
  option(HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CCM                "TLS Suite DHE-PSK-AES-256-CCM" OFF)
  option(HITLS_TLS_SUITE_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256   "TLS Suite DHE-PSK-CHACHA20-POLY1305-SHA256" OFF)
  option(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA            "TLS Suite RSA-PSK-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA            "TLS Suite RSA-PSK-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA256         "TLS Suite RSA-PSK-AES-128-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA384         "TLS Suite RSA-PSK-AES-256-CBC-SHA384" OFF)
  option(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_GCM_SHA256         "TLS Suite RSA-PSK-AES-128-GCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_GCM_SHA384         "TLS Suite RSA-PSK-AES-256-GCM-SHA384" OFF)
  option(HITLS_TLS_SUITE_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256   "TLS Suite RSA-PSK-CHACHA20-POLY1305-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA          "TLS Suite ECDHE-PSK-AES-128-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA          "TLS Suite ECDHE-PSK-AES-256-CBC-SHA" OFF)
  option(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA256       "TLS Suite ECDHE-PSK-AES-128-CBC-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA384       "TLS Suite ECDHE-PSK-AES-256-CBC-SHA384" OFF)
  option(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256       "TLS Suite ECDHE-PSK-AES-128-GCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384       "TLS Suite ECDHE-PSK-AES-256-GCM-SHA384" OFF)
  option(HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256       "TLS Suite ECDHE-PSK-AES-128-CCM-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 "TLS Suite ECDHE-PSK-CHACHA20-POLY1305-SHA256" OFF)
  option(HITLS_TLS_SUITE_ECDHE_SM4_CBC_SM3                       "TLS Suite ECDHE-SM4-CBC-SM3" OFF)
  option(HITLS_TLS_SUITE_ECC_SM4_CBC_SM3                         "TLS Suite ECC-SM4-CBC-SM3" OFF)
  option(HITLS_TLS_SUITE_ECDHE_SM4_GCM_SM3                       "TLS Suite ECDHE-SM4-GCM-SM3" OFF)
  option(HITLS_TLS_SUITE_ECC_SM4_GCM_SM3                         "TLS Suite ECC-SM4-GCM-SM3" OFF)
  option(HITLS_TLS_SUITE_SM4_GCM_SM3                             "TLS Suite SM4-GCM-SM3" OFF)
  option(HITLS_TLS_SUITE_SM4_CCM_SM3                             "TLS Suite SM4-CCM-SM3" OFF)

## TLS Suite Cipher type
option(HITLS_TLS_SUITE_CIPHER                                  "TLS Suite Cipher" OFF)
  option(HITLS_TLS_SUITE_CIPHER_AEAD                             "TLS Suite Cipher AEAD" OFF)
  option(HITLS_TLS_SUITE_CIPHER_CBC                              "TLS Suite Cipher CBC" OFF)

## TLS Suite Key Exchange
option(HITLS_TLS_SUITE_KX                                      "TLS Suite Key Exchange" OFF)
  option(HITLS_TLS_SUITE_KX_ECDHE                                "TLS Suite Key Exchange ECDHE" OFF)
  option(HITLS_TLS_SUITE_KX_DHE                                  "TLS Suite Key Exchange DHE" OFF)
  option(HITLS_TLS_SUITE_KX_RSA                                  "TLS Suite Key Exchange RSA" OFF)

## TLS Suite Authentication
option(HITLS_TLS_SUITE_AUTH                                    "TLS Suite Authentication" OFF)
  option(HITLS_TLS_SUITE_AUTH_RSA                                "TLS Suite Auth RSA" OFF)
  option(HITLS_TLS_SUITE_AUTH_ECDSA                              "TLS Suite Auth ECDSA" OFF)
  option(HITLS_TLS_SUITE_AUTH_DSS                                "TLS Suite Auth DSS" OFF)
  option(HITLS_TLS_SUITE_AUTH_PSK                                "TLS Suite Auth PSK" OFF)
  option(HITLS_TLS_SUITE_AUTH_SM2                                "TLS Suite Auth SM2" OFF)

## TLS Maintain
option(HITLS_TLS_MAINTAIN                                      "TLS Maintain" OFF)
  option(HITLS_TLS_MAINTAIN_KEYLOG                               "TLS Maintain Key Log" OFF)

## TLS OTHER
option(HITLS_TLS_CAP_NO_STR                                    "TLS Capability No STR" OFF)
option(HITLS_TLS_EXTENSION_COOKIE                              "TLS Extension Cookie" OFF)

# --- AUTH Features ---
## PrivPass Token
option(HITLS_AUTH_PRIVPASS_TOKEN                               "PrivPass Token" OFF)
## OTP
option(HITLS_AUTH_OTP                                          "OTP" OFF)
## PAKE
option(HITLS_AUTH_PAKE                                         "PAKE" OFF)
  option(HITLS_AUTH_PAKE_CORE                                    "PAKE Core" OFF)
  option(HITLS_AUTH_SPAKE2PLUS                                   "SPAKE2+" OFF)

# --- APPS Features ---
option(HITLS_APP_SM_MODE                                       "SM Mode" OFF)