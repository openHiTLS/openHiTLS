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


file(GLOB _ecc_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ecc*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ecp*.c
)

if(HITLS_CRYPTO_ECC_X8664)
    list(APPEND _ecc_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_ecp_sm2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_ecp_nistp256.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_ecp_sm2_table.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm64_ecp_nistp256.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/ecp256_x86_64.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/ecp_sm2_x86_64.S
    )
elseif(HITLS_CRYPTO_ECC_ARMV8)
    list(APPEND _ecc_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_ecp_sm2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_ecp_nistp256.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_ecp_sm2_table.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm64_ecp_nistp256.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/ecp256_armv8.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/ecp_sm2_armv8.S
    )
elseif(HITLS_CRYPTO_ECC_ARMV7)
    list(APPEND _ecc_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_ecp_sm2_armv7.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/ecp_sm2_armv7.S
    )
else()
    list(APPEND _ecc_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_ecp_nistp256.c)
endif()

add_library(_hitls_crypto_ecc OBJECT ${_ecc_sources})

target_link_libraries(_hitls_crypto_ecc
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_ecc
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/sm9/inc
        ${PROJECT_SOURCE_DIR}/crypto/bn/include
)

hitls_register_objects(CRYPTO _hitls_crypto_ecc)
