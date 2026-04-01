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


set(_cmac_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/cipher_mac_common.c)
if(HITLS_CRYPTO_CMAC)
    list(APPEND _cmac_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/cmac.c)
endif()
if(HITLS_CRYPTO_CBC_MAC)
    list(APPEND _cmac_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/cbc_mac.c)
endif()

add_library(_hitls_crypto_cmac OBJECT ${_cmac_sources})

target_link_libraries(_hitls_crypto_cmac
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_cmac
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
)

hitls_register_objects(CRYPTO _hitls_crypto_cmac)
