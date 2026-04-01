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


set(_aes_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_aes_setkey.c
)

if(HITLS_CRYPTO_AES_X8664)
    list(APPEND _aes_sources 
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_x86_64.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_ecb_x86_64.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_cbc_x86_64.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_ctr_x86_64.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_xts_x86_64.S
    )

elseif(HITLS_CRYPTO_AES_ARMV8)
    list(APPEND _aes_sources 
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_armv8.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_ecb_armv8.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_cbc_armv8.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_ctr_armv8.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_xts_armv8.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/crypt_aes_cfb_armv8.S
    )
else()
    list(APPEND _aes_sources 
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_aes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_aes_tbox.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_aes_sbox.c
    ) 
endif()

add_library(_hitls_crypto_aes OBJECT ${_aes_sources})

target_link_libraries(_hitls_crypto_aes
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_aes
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)


hitls_register_objects(CRYPTO _hitls_crypto_aes)
