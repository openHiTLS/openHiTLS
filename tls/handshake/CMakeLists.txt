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


file(GLOB _handshake_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/common/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cookie/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pack/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/parse/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/reass/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/recv/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/send/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sm/src/*.c
)

add_library(_hitls_tls_handshake OBJECT ${_handshake_sources})

target_link_libraries(_hitls_tls_handshake
    PUBLIC
        _hitls_tls_common_include)

target_include_directories(_hitls_tls_handshake
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/common/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cookie/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/pack/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/parse/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/reass/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/recv/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/send/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sm/include>
    PRIVATE
        ${PROJECT_SOURCE_DIR}/tls/alert/include
        ${PROJECT_SOURCE_DIR}/tls/cert/include
        ${PROJECT_SOURCE_DIR}/tls/config/include
        ${PROJECT_SOURCE_DIR}/tls/crypt/include
        ${PROJECT_SOURCE_DIR}/tls/record/include
        ${PROJECT_SOURCE_DIR}/tls/record/src
        ${CMAKE_CURRENT_SOURCE_DIR}/parse/src
)

hitls_register_objects(TLS _hitls_tls_handshake)
