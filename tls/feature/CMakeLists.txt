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


file(GLOB _feature_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/alpn/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/custom_extensions/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/indicator/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/security/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/session/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sni/src/*.c
)

add_library(_hitls_tls_feature OBJECT ${_feature_sources})

# Use INTERFACE targets for common includes (modern CMake pattern)
target_link_libraries(_hitls_tls_feature
    PUBLIC
        _hitls_tls_common_include)

# Module-specific includes
target_include_directories(_hitls_tls_feature
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/alpn/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/custom_extensions/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/indicator/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/security/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/session/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sni/include>
    PRIVATE
        ${PROJECT_SOURCE_DIR}/tls/alert/include
        ${PROJECT_SOURCE_DIR}/tls/cert/include
        ${PROJECT_SOURCE_DIR}/tls/config/include
        ${PROJECT_SOURCE_DIR}/tls/crypt/include
        ${PROJECT_SOURCE_DIR}/tls/record/include
        ${PROJECT_SOURCE_DIR}/tls/handshake/include
        ${PROJECT_SOURCE_DIR}/tls/handshake/common/include
        ${PROJECT_SOURCE_DIR}/tls/handshake/pack/include
        ${PROJECT_SOURCE_DIR}/tls/handshake/parse/src
        ${PROJECT_SOURCE_DIR}/bsl/tlv/include
)

hitls_register_objects(TLS _hitls_tls_feature)
