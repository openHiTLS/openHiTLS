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


set(_eal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_common.c)
if(HITLS_CRYPTO_CIPHER)
    list(APPEND _eal_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_cipher.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_cipher_method.c
    )
endif()
if(HITLS_CRYPTO_ENTROPY)
    list(APPEND _eal_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_entropy.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_entropyPool.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_entropy_ecf.c
    )
endif()
if(HITLS_CRYPTO_KDF)
    list(APPEND _eal_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_kdf.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_kdf_method.c
    )
endif()
if(HITLS_CRYPTO_CODECSKEY AND HITLS_CRYPTO_PROVIDER)
    list(APPEND _eal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_keymgmt_util.c)
endif()
if(HITLS_CRYPTO_MAC)
    list(APPEND _eal_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_mac.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_mac_method.c
    )
endif()
if(HITLS_CRYPTO_MD)
    list(APPEND _eal_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_md.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_md_method.c
    )
endif()
if(HITLS_CRYPTO_PKEY)
    list(APPEND _eal_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_computesharekey.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_crypt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_gen.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_method.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_params.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_sign.c
    )
endif()
if(HITLS_CRYPTO_PKEY_KEM)
    list(APPEND _eal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_kem.c)
endif()
if(HITLS_CRYPTO_DRBG)
    list(APPEND _eal_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_rand.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_rand_method.c
    )
endif()

add_library(_hitls_crypto_eal OBJECT ${_eal_sources})

target_link_libraries(_hitls_crypto_eal
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_eal
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/crypto/ealinit/include
        ${PROJECT_SOURCE_DIR}/crypto/modes/include
        ${PROJECT_SOURCE_DIR}/crypto/provider/include
        ${PROJECT_SOURCE_DIR}/crypto/aes/include
        ${PROJECT_SOURCE_DIR}/crypto/sm4/include
        ${PROJECT_SOURCE_DIR}/crypto/chacha20/include
        ${PROJECT_SOURCE_DIR}/crypto/entropy/include
        ${PROJECT_SOURCE_DIR}/crypto/drbg/include
        ${PROJECT_SOURCE_DIR}/crypto/md5/include
        ${PROJECT_SOURCE_DIR}/crypto/sha1/include
        ${PROJECT_SOURCE_DIR}/crypto/sha2/include
        ${PROJECT_SOURCE_DIR}/crypto/sha3/include
        ${PROJECT_SOURCE_DIR}/crypto/sm3/include
        ${PROJECT_SOURCE_DIR}/crypto/hmac/include
        ${PROJECT_SOURCE_DIR}/crypto/cmac/include
        ${PROJECT_SOURCE_DIR}/crypto/gmac/include
        ${PROJECT_SOURCE_DIR}/crypto/siphash/include
        ${PROJECT_SOURCE_DIR}/crypto/hkdf/include
        ${PROJECT_SOURCE_DIR}/crypto/pbkdf2/include
        ${PROJECT_SOURCE_DIR}/crypto/scrypt/include
        ${PROJECT_SOURCE_DIR}/crypto/kdf/include
        ${PROJECT_SOURCE_DIR}/crypto/kdftls12/include
        ${PROJECT_SOURCE_DIR}/crypto/bn/include
        ${PROJECT_SOURCE_DIR}/crypto/rsa/include
        ${PROJECT_SOURCE_DIR}/crypto/dsa/include
        ${PROJECT_SOURCE_DIR}/crypto/dh/include
        ${PROJECT_SOURCE_DIR}/crypto/ecc/include
        ${PROJECT_SOURCE_DIR}/crypto/ecdh/include
        ${PROJECT_SOURCE_DIR}/crypto/ecdsa/include
        ${PROJECT_SOURCE_DIR}/crypto/curve25519/include
        ${PROJECT_SOURCE_DIR}/crypto/sm2/include
        ${PROJECT_SOURCE_DIR}/crypto/sm9/include
        ${PROJECT_SOURCE_DIR}/crypto/elgamal/include
        ${PROJECT_SOURCE_DIR}/crypto/paillier/include
        ${PROJECT_SOURCE_DIR}/crypto/mlkem/include
        ${PROJECT_SOURCE_DIR}/crypto/mldsa/include
        ${PROJECT_SOURCE_DIR}/crypto/composite/include
        ${PROJECT_SOURCE_DIR}/crypto/hbs/include
        ${PROJECT_SOURCE_DIR}/crypto/hybridkem/include
        ${PROJECT_SOURCE_DIR}/crypto/frodokem/include
        ${PROJECT_SOURCE_DIR}/crypto/mceliece/include
        ${PROJECT_SOURCE_DIR}/crypto/codecsdata/include
        ${PROJECT_SOURCE_DIR}/crypto/codecskey/include
)

hitls_register_objects(CRYPTO _hitls_crypto_eal)
