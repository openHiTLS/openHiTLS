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


set(_curve25519_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/curve25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/curve25519_op.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/curve25519_table.c
)

if(HITLS_CRYPTO_X25519_X8664)
    list(APPEND _curve25519_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_curve25519_ops.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/x25519_x86_64.S
    )
elseif(HITLS_CRYPTO_X25519_ARMV8)
    list(APPEND _curve25519_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_curve25519_ops.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/x25519_armv8.S
    )
else()
    list(APPEND _curve25519_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_curve25519_fp51_ops.c
    )
endif()

add_library(_hitls_crypto_curve25519 OBJECT ${_curve25519_sources})

target_link_libraries(_hitls_crypto_curve25519
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_curve25519
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
)

hitls_register_objects(CRYPTO _hitls_crypto_curve25519)
