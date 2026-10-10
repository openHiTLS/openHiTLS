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

cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(openHiTLS_ASYNC_SIM_PROVIDER)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Werror")
if(APPLE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-command-line-argument -Wno-pointer-sign -Wno-tautological-pointer-compare")
endif()

set(TESTCODE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
set(SIM_PROV_OUTPUT_DIR "${TESTCODE_ROOT}/output/async_sim_provider" CACHE PATH "Provider output directory")
file(MAKE_DIRECTORY "${SIM_PROV_OUTPUT_DIR}")

set(OPENHITLS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../..")
set(OPENHITLS_BUILD_DIR "${OPENHITLS_ROOT}/build" CACHE PATH "Matching openHiTLS library build")
# Sanity: from testcode/framework/async/provider, four levels up is the repo root.
if(NOT EXISTS "${OPENHITLS_ROOT}/include/bsl/bsl_sal.h")
    message(FATAL_ERROR "openHiTLS root not found at ${OPENHITLS_ROOT}")
endif()

# The simulation provider is an independent project (D1): it does not consume
# the main build's hitls_build_config.h. It fixes its own feature macros:
#  - the provider machinery requires the crypto provider framework;
#  - HITLS_BSL_ASYNC selects the pause path (D3: the OFF build of the main
#    library does not export BSL_ASYNC_* symbols, so this macro must be
#    controllable here to keep the .so linkable against both builds).
option(SIM_PROV_ASYNC "Build the provider with the async pause path" ON)

set(SIM_PROV_SOURCES
    sim_prov_init.c
    sim_prov_ctrl.c
    sim_prov_scenario.c
    sim_prov_delegate.c
    sim_prov_decode.c
    sim_prov_device.c
    sim_prov_crypto.c
    sim_prov_notifyfd.c
)

add_library(async_sim_provider SHARED ${SIM_PROV_SOURCES})
set_source_files_properties(sim_prov_decode.c PROPERTIES
    COMPILE_DEFINITIONS "__FILENAME__=\"sim_prov_decode.c\"")
target_include_directories(async_sim_provider PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${OPENHITLS_ROOT}/include/bsl
    ${OPENHITLS_ROOT}/include/crypto
    ${OPENHITLS_ROOT}/config/macro_config
    ${OPENHITLS_ROOT}/bsl/sal/include
    ${OPENHITLS_ROOT}/bsl/err/include
    ${OPENHITLS_ROOT}/bsl/list/include
    ${OPENHITLS_ROOT}/bsl/params/include
    ${OPENHITLS_ROOT}/bsl/log/include
    ${OPENHITLS_ROOT}/bsl/hash/include
    ${OPENHITLS_ROOT}/bsl/include
    ${OPENHITLS_ROOT}/crypto/include
    ${OPENHITLS_ROOT}/crypto/eal/include
    ${OPENHITLS_ROOT}/crypto/eal/src
    ${OPENHITLS_ROOT}/crypto/modes/include
)
target_compile_definitions(async_sim_provider PRIVATE
    HITLS_CRYPTO_PROVIDER
    HITLS_CRYPTO_PKEY
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_CODECSKEY
    HITLS_CRYPTO_KEY_DECODE
    HITLS_CRYPTO_ECDH
    HITLS_CRYPTO_ECDSA
    HITLS_CRYPTO_RSA
    HITLS_CRYPTO_DSA
    HITLS_CRYPTO_DH
    HITLS_CRYPTO_X25519
    HITLS_CRYPTO_ED25519
    HITLS_CRYPTO_SM2
    HITLS_CRYPTO_MLKEM
    HITLS_CRYPTO_HYBRIDKEM
    HITLS_CRYPTO_MLDSA
    HITLS_CRYPTO_MD
    HITLS_CRYPTO_HMAC
    HITLS_CRYPTO_MD5
    HITLS_CRYPTO_SHA1
    HITLS_CRYPTO_SHA2
    HITLS_CRYPTO_SHA224
    HITLS_CRYPTO_SHA256
    HITLS_CRYPTO_SHA384
    HITLS_CRYPTO_SHA512
    HITLS_CRYPTO_SM3
    HITLS_CRYPTO_HKDF
    HITLS_CRYPTO_KDFTLS12
    HITLS_CRYPTO_KDF
    HITLS_CRYPTO_AES
    HITLS_CRYPTO_GCM
    HITLS_CRYPTO_CBC
    HITLS_CRYPTO_CCM
    HITLS_CRYPTO_CHACHA20POLY1305
    HITLS_CRYPTO_CHACHA20
    HITLS_CRYPTO_SM4
    HITLS_CRYPTO_CIPHER
    HITLS_CRYPTO_MODES
    HITLS_BSL
    HITLS_BSL_SAL
    HITLS_BSL_ERR
    HITLS_BSL_PARAMS
)
if(SIM_PROV_ASYNC)
    target_compile_definitions(async_sim_provider PRIVATE HITLS_BSL_ASYNC)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(async_sim_provider PRIVATE HITLS_BSL_SAL_LINUX _GNU_SOURCE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_compile_definitions(async_sim_provider PRIVATE HITLS_BSL_SAL_DARWIN)
endif()
target_link_directories(async_sim_provider PUBLIC ${OPENHITLS_BUILD_DIR})
target_link_libraries(async_sim_provider hitls_crypto hitls_bsl)
set_target_properties(async_sim_provider PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${SIM_PROV_OUTPUT_DIR}"
)
if(APPLE)
    target_link_options(async_sim_provider PRIVATE
        -Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/sim_prov_exports.txt)
else()
    target_link_options(async_sim_provider PRIVATE
        -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/sim_prov.map)
endif()
