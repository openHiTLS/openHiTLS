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


function(append_sources_if list_var condition)
    if(${condition})
        list(APPEND ${list_var} ${ARGN})
        set(${list_var} ${${list_var}} PARENT_SCOPE)
    endif()
endfunction()

set(_source_dir ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(_modes_sources ${_source_dir}/modes.c)

# Base modes sources
append_sources_if(_modes_sources HITLS_CRYPTO_CBC ${_source_dir}/modes_cbc.c)
append_sources_if(_modes_sources HITLS_CRYPTO_CCM ${_source_dir}/modes_ccm.c)
append_sources_if(_modes_sources HITLS_CRYPTO_CFB ${_source_dir}/modes_cfb.c)
append_sources_if(_modes_sources HITLS_CRYPTO_CTR ${_source_dir}/modes_ctr.c)
append_sources_if(_modes_sources HITLS_CRYPTO_ECB ${_source_dir}/modes_ecb.c)
append_sources_if(_modes_sources HITLS_CRYPTO_GCM ${_source_dir}/modes_gcm.c)
append_sources_if(_modes_sources HITLS_CRYPTO_OFB ${_source_dir}/modes_ofb.c)
append_sources_if(_modes_sources HITLS_CRYPTO_XTS ${_source_dir}/modes_xts.c)
append_sources_if(_modes_sources HITLS_CRYPTO_HCTR ${_source_dir}/modes_hctr.c)
append_sources_if(_modes_sources HITLS_CRYPTO_WRAP ${_source_dir}/modes_aes_wrap.c)
if(HITLS_CRYPTO_CHACHA20 AND HITLS_CRYPTO_CHACHA20POLY1305)
    list(APPEND _modes_sources ${_source_dir}/modes_chacha20_poly1305.c)
endif()

# common X86_64 specific sources
set(_modes_x8664_cm_sources "")
if(HITLS_CRYPTO_AES)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_CTR ${_source_dir}/asm_aes_ctr.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_CBC ${_source_dir}/asm_aes_cbc.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_ECB ${_source_dir}/asm_aes_ecb.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_XTS ${_source_dir}/asm_aes_xts.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_CFB ${_source_dir}/noasm_aes_cfb.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_GCM
        ${_source_dir}/asm_aes_gcm.c
        ${_source_dir}/asm/aes_gcm_16block_x86_64.S
        ${_source_dir}/asm/aes_gcm_64block_x86_64.S
    )
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_CCM
        ${_source_dir}/asm_aes_ccm.c
        ${_source_dir}/asm/aes_ccm_x86_64.S
    )
endif()
if(HITLS_CRYPTO_SM4)
    list(APPEND _modes_x8664_cm_sources ${_source_dir}/asm_sm4_setkey.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_XTS ${_source_dir}/asm_sm4_xts.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_ECB ${_source_dir}/asm_sm4_ecb.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_CBC ${_source_dir}/asm_sm4_cbc.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_CFB ${_source_dir}/asm_sm4_cfb.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_OFB ${_source_dir}/asm_sm4_ofb_x86_64.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_CTR ${_source_dir}/asm_sm4_ctr.c)
    append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_GCM ${_source_dir}/asm_sm4_gcm.c)
endif()
append_sources_if(_modes_x8664_cm_sources HITLS_CRYPTO_GHASH ${_source_dir}/asm/ghash_x86_64.S)


# Add assembly files according to the assembly type
if(HITLS_CRYPTO_MODES_X8664_AVX512)
    list(APPEND _modes_sources ${_modes_x8664_cm_sources})
    append_sources_if(_modes_sources HITLS_CRYPTO_CHACHA20POLY1305 ${_source_dir}/asm/poly1305_x86_64_avx512.S)
elseif(HITLS_CRYPTO_MODES_X8664)
    list(APPEND _modes_sources ${_modes_x8664_cm_sources})
    append_sources_if(_modes_sources HITLS_CRYPTO_CHACHA20POLY1305 ${_source_dir}/asm/poly1305_x86_64_avx2.S)
elseif(HITLS_CRYPTO_MODES_ARMV8)
    if(HITLS_CRYPTO_AES)
        append_sources_if(_modes_sources HITLS_CRYPTO_CBC ${_source_dir}/asm_aes_cbc.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_ECB ${_source_dir}/asm_aes_ecb.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CTR ${_source_dir}/asm_aes_ctr.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_XTS ${_source_dir}/asm_aes_xts.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CFB ${_source_dir}/asm_aes_cfb.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CCM ${_source_dir}/noasm_aes_ccm.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_GCM
            ${_source_dir}/asm_aes_gcm.c
            ${_source_dir}/asm/aes_gcm_16block_aarch64.S
            ${_source_dir}/asm/aes_gcm_64block_aarch64.S
        )
    endif()
    if(HITLS_CRYPTO_SM4)
        list(APPEND _modes_sources ${_source_dir}/asm_sm4_setkey.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_XTS ${_source_dir}/asm_sm4_xts.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_ECB ${_source_dir}/asm_sm4_ecb.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CBC ${_source_dir}/asm_sm4_cbc.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CFB ${_source_dir}/asm_sm4_cfb.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_OFB ${_source_dir}/asm_sm4_ofb_armv8.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CTR ${_source_dir}/asm_sm4_ctr.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_GCM ${_source_dir}/asm_sm4_gcm.c)
    endif()
    if(HITLS_CRYPTO_CHACHA20 AND HITLS_CRYPTO_CHACHA20POLY1305)
        list(APPEND _modes_sources ${_source_dir}/asm/poly1305_armv8.S)
    endif()
    append_sources_if(_modes_sources HITLS_CRYPTO_GHASH ${_source_dir}/asm/ghash_armv8.S)
else() # No assembly optimizations
    if(HITLS_CRYPTO_AES)
        append_sources_if(_modes_sources HITLS_CRYPTO_CBC ${_source_dir}/noasm_aes_cbc.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CCM ${_source_dir}/noasm_aes_ccm.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CFB ${_source_dir}/noasm_aes_cfb.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CTR ${_source_dir}/noasm_aes_ctr.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_ECB ${_source_dir}/noasm_aes_ecb.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_GCM ${_source_dir}/noasm_aes_gcm.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_XTS ${_source_dir}/noasm_aes_xts.c)
    endif()
    if(HITLS_CRYPTO_SM4)
        list(APPEND _modes_sources ${_source_dir}/noasm_sm4_setkey.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CBC ${_source_dir}/noasm_sm4_cbc.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CFB ${_source_dir}/noasm_sm4_cfb.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_CTR ${_source_dir}/noasm_sm4_ctr.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_ECB ${_source_dir}/noasm_sm4_ecb.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_GCM ${_source_dir}/noasm_sm4_gcm.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_XTS ${_source_dir}/noasm_sm4_xts.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_OFB ${_source_dir}/noasm_sm4_ofb.c)
        append_sources_if(_modes_sources HITLS_CRYPTO_HCTR ${_source_dir}/noasm_sm4_hctr.c)
    endif()
    if(HITLS_CRYPTO_CHACHA20 AND HITLS_CRYPTO_CHACHA20POLY1305)
        list(APPEND _modes_sources ${_source_dir}/noasm_poly1305.c)
    endif()
    append_sources_if(_modes_sources HITLS_CRYPTO_GHASH ${_source_dir}/noasm_ghash.c)
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
