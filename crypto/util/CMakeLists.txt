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


set(_util_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_ctrl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_pkey.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypt_utils.c
)
if(HITLS_CRYPTO_PROVIDER AND HITLS_CRYPTO_MD)
    list(APPEND _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_md.c)
endif()
if(HITLS_CRYPTO_RSA_EMSA_PSS OR HITLS_CRYPTO_RSAES_OAEP OR HITLS_CRYPTO_SLH_DSA OR HITLS_CRYPTO_LMS)
    list(APPEND _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_mgf.c)
endif()
if(HITLS_CRYPTO_DRBG OR HITLS_CRYPTO_CURVE25519 OR HITLS_CRYPTO_RSA OR HITLS_CRYPTO_BN_RAND OR HITLS_CRYPTO_SM9)
    list(APPEND _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_rand.c)
endif()

add_library(_hitls_crypto_util OBJECT ${_util_sources})

target_link_libraries(_hitls_crypto_util
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_util
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include/crypto>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/crypto/bn/include
        ${PROJECT_SOURCE_DIR}/crypto/ecc/include
        ${PROJECT_SOURCE_DIR}/crypto/eal/include
        ${PROJECT_SOURCE_DIR}/crypto/modes/include
        ${PROJECT_SOURCE_DIR}/crypto/drbg/include
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
)


hitls_register_objects(CRYPTO _hitls_crypto_util)
