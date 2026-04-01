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


set(_drbg_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/drbg.c)
if(HITLS_CRYPTO_DRBG_CTR)
    list(APPEND _drbg_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/drbg_ctr.c)
endif()
if(HITLS_CRYPTO_DRBG_HASH)
    list(APPEND _drbg_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/drbg_hash.c)
endif()
if(HITLS_CRYPTO_DRBG_HMAC)
    list(APPEND _drbg_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/drbg_hmac.c)
endif()

add_library(_hitls_crypto_drbg OBJECT ${_drbg_sources})

target_link_libraries(_hitls_crypto_drbg
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_drbg
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
)

hitls_register_objects(CRYPTO _hitls_crypto_drbg)
