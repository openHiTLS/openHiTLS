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


set(_mlkem_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/ml_kem.c
                   ${CMAKE_CURRENT_SOURCE_DIR}/src/ml_kem_pke.c)

if(HITLS_CRYPTO_MLKEM_ARMV8)
    file(GLOB _mlkem_armv8_cglues ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_*.c)
    file(GLOB _mlkem_armv8 ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/*.S)
    list(APPEND _mlkem_sources ${_mlkem_armv8} ${_mlkem_armv8_cglues})
else()
    list(APPEND _mlkem_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/ml_kem_poly.c ${CMAKE_CURRENT_SOURCE_DIR}/src/ml_kem_ntt.c)
endif()

add_library(_hitls_crypto_mlkem OBJECT ${_mlkem_sources})

target_link_libraries(_hitls_crypto_mlkem
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_mlkem
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
        ${PROJECT_SOURCE_DIR}/crypto/sha3/include
        ${PROJECT_SOURCE_DIR}/crypto/sha3/src
)

hitls_register_objects(CRYPTO _hitls_crypto_mlkem)
