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


file(GLOB _eal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

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
        ${PROJECT_SOURCE_DIR}/crypto/slh_dsa/include
        ${PROJECT_SOURCE_DIR}/crypto/xmss/include
        ${PROJECT_SOURCE_DIR}/crypto/hybridkem/include
        ${PROJECT_SOURCE_DIR}/crypto/frodokem/include
        ${PROJECT_SOURCE_DIR}/crypto/mceliece/include
        ${PROJECT_SOURCE_DIR}/crypto/codecsdata/include
        ${PROJECT_SOURCE_DIR}/crypto/codecskey/include
)

hitls_register_objects(CRYPTO _hitls_crypto_eal)
