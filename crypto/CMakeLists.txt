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


if(NOT HITLS_CRYPTO)
    message(STATUS "[Crypto] Skipping Crypto (HITLS_CRYPTO=OFF)")
    return()
endif()

message(STATUS "[Crypto] Configuring Crypto modules")

# Include helper functions
include(helpers/hitls_target_helpers)

# ==============================================================================
# Common include directories for all Crypto modules (INTERFACE target)
# ==============================================================================
# Modern CMake: Use INTERFACE target instead of global variables
# Subdirectories can use: target_link_libraries(xxx PUBLIC _hitls_crypto_common_include)
# ==============================================================================
add_library(_hitls_crypto_common_include INTERFACE)
target_include_directories(_hitls_crypto_common_include INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/crypto
    ${PROJECT_SOURCE_DIR}/include/bsl
    ${PROJECT_SOURCE_DIR}/bsl/include
    ${PROJECT_SOURCE_DIR}/bsl/err/include
)
# Crypto common inherits BSL common (if available)
target_link_libraries(_hitls_crypto_common_include INTERFACE
    $<TARGET_NAME_IF_EXISTS:_hitls_bsl_common_include>
)


# ==============================================================================
# Foundation modules (always needed when crypto is enabled)
# ==============================================================================

# EAL - Encryption Algorithm Layer (core crypto abstraction)
if(HITLS_CRYPTO_EAL)
    add_subdirectory(eal)
endif()

# EAL Init
if(HITLS_CRYPTO_EALINIT)
    add_subdirectory(ealinit)
endif()

# Util - Common utilities
add_subdirectory(util)

# ==============================================================================
# Block Cipher Algorithms
# ==============================================================================

if(HITLS_CRYPTO_AES)
    add_subdirectory(aes)
endif()

if(HITLS_CRYPTO_SM4)
    add_subdirectory(sm4)
endif()

# ==============================================================================
# Cipher Modes (depends on block ciphers)
# ==============================================================================
if(HITLS_CRYPTO_MODES)
    add_subdirectory(modes)
endif()

# ==============================================================================
# Stream Ciphers
# ==============================================================================

if(HITLS_CRYPTO_CHACHA20)
    add_subdirectory(chacha20)
endif()

# ==============================================================================
# Hash Algorithms
# ==============================================================================

if(HITLS_CRYPTO_MD5)
    add_subdirectory(md5)
endif()

if(HITLS_CRYPTO_SHA1)
    add_subdirectory(sha1)
endif()

if(HITLS_CRYPTO_SHA2)
    add_subdirectory(sha2)
endif()

if(HITLS_CRYPTO_SHA3)
    add_subdirectory(sha3)
endif()

if(HITLS_CRYPTO_SM3)
    add_subdirectory(sm3)
endif()

# ==============================================================================
# MAC Algorithms
# ==============================================================================

if(HITLS_CRYPTO_HMAC)
    add_subdirectory(hmac)
endif()

# CMAC module is needed if umbrella or any specific variant is enabled
if(HITLS_CRYPTO_CMAC OR HITLS_CRYPTO_CBC_MAC)
    add_subdirectory(cmac)
endif()

if(HITLS_CRYPTO_GMAC)
    add_subdirectory(gmac)
endif()

if(HITLS_CRYPTO_SIPHASH)
    add_subdirectory(siphash)
endif()

# ==============================================================================
# Big Number (foundation for asymmetric crypto)
# ==============================================================================

if(HITLS_CRYPTO_BN)
    add_subdirectory(bn)
endif()

# ==============================================================================
# Data Encoding/Decoding (needed by asymmetric algorithms like DSA)
# ==============================================================================
if(HITLS_CRYPTO_SM2_SIGN OR HITLS_CRYPTO_SM2_CRYPT OR HITLS_CRYPTO_DSA OR HITLS_CRYPTO_ECDSA)
    add_subdirectory(codecsdata)
endif()

# ==============================================================================
# Elliptic Curve Cryptography
# ==============================================================================

if(HITLS_CRYPTO_ECC)
    add_subdirectory(ecc)
endif()

if(HITLS_CRYPTO_ECDH)
    add_subdirectory(ecdh)
endif()

if(HITLS_CRYPTO_ECDSA)
    add_subdirectory(ecdsa)
endif()

if(HITLS_CRYPTO_CURVE25519)
    add_subdirectory(curve25519)
endif()

if(HITLS_CRYPTO_SM2)
    add_subdirectory(sm2)
endif()

if(HITLS_CRYPTO_SM9)
    add_subdirectory(sm9)
endif()

# ==============================================================================
# Other Asymmetric Algorithms
# ==============================================================================

# RSA: include if umbrella OR any sub-option is enabled
if(HITLS_CRYPTO_RSA OR
   HITLS_CRYPTO_RSA_SIGN OR HITLS_CRYPTO_RSA_VERIFY OR
   HITLS_CRYPTO_RSA_ENCRYPT OR HITLS_CRYPTO_RSA_DECRYPT OR
   HITLS_CRYPTO_RSA_GEN OR HITLS_CRYPTO_RSA_BSSA)
    add_subdirectory(rsa)
endif()

if(HITLS_CRYPTO_DSA)
    add_subdirectory(dsa)
endif()

if(HITLS_CRYPTO_DH)
    add_subdirectory(dh)
endif()

if(HITLS_CRYPTO_ELGAMAL)
    add_subdirectory(elgamal)
endif()

if(HITLS_CRYPTO_PAILLIER)
    add_subdirectory(paillier)
endif()

# ==============================================================================
# Post-Quantum Cryptography
# ==============================================================================

if(HITLS_CRYPTO_MLKEM)
    add_subdirectory(mlkem)
endif()

if(HITLS_CRYPTO_FRODOKEM)
    add_subdirectory(frodokem)
endif()

if(HITLS_CRYPTO_MCELIECE)
    add_subdirectory(mceliece)
endif()

if(HITLS_CRYPTO_MLDSA)
    add_subdirectory(mldsa)
endif()

if(HITLS_CRYPTO_SLH_DSA)
    add_subdirectory(slh_dsa)
endif()

if(HITLS_CRYPTO_XMSS)
    add_subdirectory(xmss)
endif()

if(HITLS_CRYPTO_HYBRIDKEM)
    add_subdirectory(hybridkem)
endif()

# ==============================================================================
# Key Derivation Functions
# ==============================================================================

if(HITLS_CRYPTO_HKDF)
    add_subdirectory(hkdf)
endif()

if(HITLS_CRYPTO_PBKDF2)
    add_subdirectory(pbkdf2)
endif()

if(HITLS_CRYPTO_SCRYPT)
    add_subdirectory(scrypt)
endif()

if(HITLS_CRYPTO_KDFTLS12)
    add_subdirectory(kdf)
endif()

# ==============================================================================
# Random Number Generation
# ==============================================================================

# Check for any DRBG type enabled (not just DRBG umbrella) to avoid umbrella expansion issue
if(HITLS_CRYPTO_DRBG OR HITLS_CRYPTO_DRBG_HASH OR HITLS_CRYPTO_DRBG_HMAC OR HITLS_CRYPTO_DRBG_CTR)
    add_subdirectory(drbg)
endif()

if(HITLS_CRYPTO_ENTROPY)
    add_subdirectory(entropy)
endif()

# ==============================================================================
# Key Encoding/Decoding (needs all key types to be defined first)
# ==============================================================================

if(HITLS_CRYPTO_CODECSKEY)
    add_subdirectory(codecskey)
endif()

# ==============================================================================
# Provider
# ==============================================================================

if(HITLS_CRYPTO_PROVIDER)
    add_subdirectory(provider)
endif()

# ==============================================================================
# HPKE - Hybrid Public Key Encryption
# ==============================================================================

if(HITLS_CRYPTO_HPKE)
    add_subdirectory(hpke)
endif()

message(STATUS "[Crypto] Crypto configuration complete")
