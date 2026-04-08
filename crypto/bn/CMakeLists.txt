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


set(_bn_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_basic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_bincal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_gcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_mont.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_operation.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_optimizer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_ucal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_utils.c
)
if(HITLS_CRYPTO_BN_COMBA)
    list(APPEND _bn_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_comba.c)
endif()
if(HITLS_CRYPTO_BN_RFC_PRIME)
    list(APPEND _bn_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_const.c)
endif()
if(HITLS_CRYPTO_ECC)
    list(APPEND _bn_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_nistmod.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_sqrt.c
    )
endif()
if(HITLS_CRYPTO_BN_PRIME)
    list(APPEND _bn_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_prime.c)
endif()
if(HITLS_CRYPTO_BN_RAND)
    list(APPEND _bn_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/bn_rand.c)
endif()

if(HITLS_CRYPTO_BN_X8664)
    list(APPEND _bn_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_bn_mont.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/x8664_bn_bincal.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/bn_mont_x86_64.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/bn_montx_x86_64.S
    )
elseif(HITLS_CRYPTO_BN_ARMV8)
    list(APPEND _bn_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_bn_mont.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/armv8_bn_bincal.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/bn_mont_armv8.S
    )
else()
    list(APPEND _bn_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_bn_bincal.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_bn_mont.c
    )
endif()

add_library(_hitls_crypto_bn OBJECT ${_bn_sources})

target_link_libraries(_hitls_crypto_bn
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_bn
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

hitls_register_objects(CRYPTO _hitls_crypto_bn)
