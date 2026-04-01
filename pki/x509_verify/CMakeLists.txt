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


file(GLOB _x509_verify_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

add_library(_hitls_pki_x509_verify OBJECT ${_x509_verify_sources})

target_link_libraries(_hitls_pki_x509_verify
    PUBLIC
        _hitls_pki_common_include
)

target_include_directories(_hitls_pki_x509_verify
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/pki/x509_common/include
        ${PROJECT_SOURCE_DIR}/pki/x509_cert/include
        ${PROJECT_SOURCE_DIR}/pki/x509_crl/include
        ${PROJECT_SOURCE_DIR}/bsl/list/include
)

hitls_register_objects(PKI _hitls_pki_x509_verify)
