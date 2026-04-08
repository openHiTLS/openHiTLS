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


set(_cms_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hitls_cms_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hitls_cms_util.c
)
if(HITLS_PKI_CMS_SIGNEDDATA)
    list(APPEND _cms_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hitls_cms_pqc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hitls_cms_signdata.c
    )
endif()

add_library(_hitls_pki_cms OBJECT ${_cms_sources})

target_link_libraries(_hitls_pki_cms
    PUBLIC
        _hitls_pki_common_include
)

target_include_directories(_hitls_pki_cms
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/pki/x509_common/include
        ${PROJECT_SOURCE_DIR}/pki/x509_cert/include
        ${PROJECT_SOURCE_DIR}/pki/x509_verify/include
        ${PROJECT_SOURCE_DIR}/pki/x509_crl/include
        ${PROJECT_SOURCE_DIR}/crypto/codecskey/include
)

hitls_register_objects(PKI _hitls_pki_cms)
