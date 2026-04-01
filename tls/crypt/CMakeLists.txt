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


file(GLOB _crypt_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/crypt_adapt/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypt_self/*.c
)

add_library(_hitls_tls_crypt OBJECT ${_crypt_sources})

# Use INTERFACE targets for common includes (modern CMake pattern)
target_link_libraries(_hitls_tls_crypt
    PUBLIC
        _hitls_tls_common_include)

# Module-specific includes
target_include_directories(_hitls_tls_crypt
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crypt_adapt>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crypt_self>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crypt_self/hkdf>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crypt_self/rsa>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crypt_self/aead>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crypt_self/crypt_common>
    PRIVATE
        ${PROJECT_SOURCE_DIR}/tls/config/include
)

hitls_register_objects(TLS _hitls_tls_crypt)
