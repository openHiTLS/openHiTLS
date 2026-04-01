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


file(GLOB _cm_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

add_library(_hitls_tls_cm OBJECT ${_cm_sources})

target_link_libraries(_hitls_tls_cm
    PUBLIC
        _hitls_tls_common_include)

target_include_directories(_hitls_tls_cm
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/tls/alert/include
        ${PROJECT_SOURCE_DIR}/tls/app/include
        ${PROJECT_SOURCE_DIR}/tls/ccs/include
        ${PROJECT_SOURCE_DIR}/tls/cert/include
        ${PROJECT_SOURCE_DIR}/tls/config/include
        ${PROJECT_SOURCE_DIR}/tls/crypt/include
        ${PROJECT_SOURCE_DIR}/tls/handshake/include
        ${PROJECT_SOURCE_DIR}/tls/handshake/common/include
        ${PROJECT_SOURCE_DIR}/tls/handshake/recv/include
        ${PROJECT_SOURCE_DIR}/tls/handshake/send/include
        ${PROJECT_SOURCE_DIR}/tls/record/include
        ${PROJECT_SOURCE_DIR}/tls/record/src
)

hitls_register_objects(TLS _hitls_tls_cm)
