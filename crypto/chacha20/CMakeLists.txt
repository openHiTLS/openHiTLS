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


set(_chacha20_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/chacha20.c
)

if(HITLS_CRYPTO_CHACHA20_X8664_AVX512)
    list(APPEND _chacha20_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/chacha20block_x8664_avx512.S)
elseif(HITLS_CRYPTO_CHACHA20_X8664)
    list(APPEND _chacha20_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/chacha20block_x8664_avx2.S)
elseif(HITLS_CRYPTO_CHACHA20_ARMV8)
    list(APPEND _chacha20_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/chacha20_aarch64.S)
else()
    list(APPEND _chacha20_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/chacha20block.c)
endif()

add_library(_hitls_crypto_chacha20 OBJECT ${_chacha20_sources})

target_link_libraries(_hitls_crypto_chacha20
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_chacha20
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

hitls_register_objects(CRYPTO _hitls_crypto_chacha20)
