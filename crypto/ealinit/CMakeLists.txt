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


set(_ealinit_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cpucap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_asmcap.c
)

if(HITLS_CRYPTO_ASM_CHECK AND (
    HITLS_CRYPTO_AES_ASM OR
    HITLS_CRYPTO_CHACHA20_ASM OR
    HITLS_CRYPTO_CHACHA20POLY1305_ASM OR
    HITLS_CRYPTO_SM4_ASM OR
    HITLS_CRYPTO_GHASH_ASM OR
    HITLS_CRYPTO_MD5_ASM OR
    HITLS_CRYPTO_SHA1_ASM OR
    HITLS_CRYPTO_SHA2_ASM OR
    HITLS_CRYPTO_SM3_ASM OR
    HITLS_CRYPTO_BN_ASM OR
    HITLS_CRYPTO_CURVE_NISTP256_ASM
))
    list(APPEND _ealinit_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asmcap_alg_asm.c
    )
endif()

add_library(_hitls_crypto_ealinit OBJECT ${_ealinit_sources})

target_link_libraries(_hitls_crypto_ealinit
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_ealinit
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/crypto/provider/include
)

hitls_register_objects(CRYPTO _hitls_crypto_ealinit)
