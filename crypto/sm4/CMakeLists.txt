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


set(_sm4_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_sm4.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_sm4_public.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sm4_key.c
)

if(HITLS_CRYPTO_SM4_X8664)
    list(APPEND _sm4_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_sm4_x86_64.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_sm4_x86_64.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_sm4_macro_x86_64.s
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_sm4_modes_x86_64.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_sm4_modes_macro_x86_64.s
    )
elseif(HITLS_CRYPTO_SM4_ARMV8)
    list(APPEND _sm4_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_sm4_armv8.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_sm4_armv8.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_sm4_ex_armv8.S
    )
endif()

add_library(_hitls_crypto_sm4 OBJECT ${_sm4_sources})

target_link_libraries(_hitls_crypto_sm4
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_sm4
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)


hitls_register_objects(CRYPTO _hitls_crypto_sm4)
