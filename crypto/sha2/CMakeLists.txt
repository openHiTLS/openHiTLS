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


set(_sha2_sources "")
if(HITLS_CRYPTO_SHA256)
    list(APPEND _sha2_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/sha2_256.c)
    if(HITLS_CRYPTO_SHA256_ARMV8)
        list(APPEND _sha2_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/sha2_256_armv8.S)
    elseif(HITLS_CRYPTO_SHA256_X8664)
        list(APPEND _sha2_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/sha2_256_x86_64.S)
    elseif(HITLS_CRYPTO_SHA256_SMALL_MEM)
        list(APPEND _sha2_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sha256_small.c)
    else()
        list(APPEND _sha2_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sha256.c)
    endif()
endif()
if(HITLS_CRYPTO_SHA512)
    list(APPEND _sha2_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/sha2_512.c)
    if(HITLS_CRYPTO_SHA512_ARMV8)
        list(APPEND _sha2_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/sha2_512_armv8.S)
    elseif(HITLS_CRYPTO_SHA512_X8664)
        list(APPEND _sha2_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/sha2_512_x86_64.S)
    elseif(HITLS_CRYPTO_SHA512_SMALL_MEM)
        list(APPEND _sha2_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sha512_small.c)
    else()
        list(APPEND _sha2_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sha512.c)
    endif()
endif()

add_library(_hitls_crypto_sha2 OBJECT ${_sha2_sources})

target_link_libraries(_hitls_crypto_sha2
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_sha2
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

hitls_register_objects(CRYPTO _hitls_crypto_sha2)
