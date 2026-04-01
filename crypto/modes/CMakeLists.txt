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


file(GLOB _modes_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/modes*.c)

set(_modes_x8664_common_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_ctr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_gcm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/aes_gcm_16block_x86_64.S
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/aes_gcm_64block_x86_64.S
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_cbc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_ecb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_xts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/ghash_x86_64.S
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_ccm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/aes_ccm_x86_64.S
    ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_aes_cfb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_xts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_ecb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_cbc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_cfb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_ofb_x86_64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_ctr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_setkey.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_gcm.c
)

if(HITLS_CRYPTO_MODES_X8664_AVX512)
    list(APPEND _modes_sources
        ${_modes_x8664_common_sources}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/poly1305_x86_64_avx512.S
    )
elseif(HITLS_CRYPTO_MODES_X8664)
    list(APPEND _modes_sources
        ${_modes_x8664_common_sources}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/poly1305_x86_64_avx2.S
    )
elseif(HITLS_CRYPTO_MODES_ARMV8)
    list(APPEND _modes_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/poly1305_armv8.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_gcm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_cbc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_ecb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_ctr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_xts.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/aes_gcm_16block_aarch64.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/aes_gcm_64block_aarch64.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/ghash_armv8.S
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_aes_ccm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_aes_cfb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_xts.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_ecb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_cbc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_cfb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_ofb_armv8.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_ctr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_setkey.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm_sm4_gcm.c
    )
else()
    list(APPEND _modes_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_aes_cbc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_aes_ccm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_aes_cfb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_aes_ctr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_aes_ecb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_aes_gcm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_aes_xts.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_ghash.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_poly1305.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sm4_cbc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sm4_cfb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sm4_ctr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sm4_ecb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sm4_gcm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sm4_hctr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sm4_ofb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sm4_xts.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sm4_setkey.c
    )
endif()

add_library(_hitls_crypto_modes OBJECT ${_modes_sources})

target_link_libraries(_hitls_crypto_modes
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_modes
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
        ${PROJECT_SOURCE_DIR}/crypto/aes/include
        ${PROJECT_SOURCE_DIR}/crypto/sm4/include
)

hitls_register_objects(CRYPTO _hitls_crypto_modes)
