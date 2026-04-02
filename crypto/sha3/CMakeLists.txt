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


set(_sha3_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sha3.c
)
if(HITLS_CRYPTO_SHA3_ARMV8)
    list(APPEND _sha3_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/sha3_armv8.S ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sha3.c)
else()
    list(APPEND _sha3_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sha3.c)
endif()

add_library(_hitls_crypto_sha3 OBJECT ${_sha3_sources})

target_link_libraries(_hitls_crypto_sha3
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_sha3
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

hitls_register_objects(CRYPTO _hitls_crypto_sha3)
