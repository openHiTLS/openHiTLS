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


file(GLOB _cert_sources ${CMAKE_CURRENT_SOURCE_DIR}/cert_adapt/*.c)

list(APPEND _cert_sources ${CMAKE_CURRENT_SOURCE_DIR}/hitls_x509_adapt/hitls_x509_init.c)
if(HITLS_TLS_CALLBACK_CERT OR HITLS_TLS_FEATURE_PROVIDER)
    list(APPEND _cert_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/hitls_x509_adapt/hitls_x509_cert_chain.c
        ${CMAKE_CURRENT_SOURCE_DIR}/hitls_x509_adapt/hitls_x509_cert_magr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/hitls_x509_adapt/hitls_x509_cert_store.c
        ${CMAKE_CURRENT_SOURCE_DIR}/hitls_x509_adapt/hitls_x509_crypto.c
        ${CMAKE_CURRENT_SOURCE_DIR}/hitls_x509_adapt/hitls_x509_pkey_magr.c
    )
    if(HITLS_TLS_CONFIG_CERT_CRL)
        list(APPEND _cert_sources ${CMAKE_CURRENT_SOURCE_DIR}/hitls_x509_adapt/hitls_x509_crl_magr.c)
    endif()
endif()

add_library(_hitls_tls_cert OBJECT ${_cert_sources})

# Use INTERFACE targets for common includes (modern CMake pattern)
target_link_libraries(_hitls_tls_cert
    PUBLIC
        _hitls_tls_common_include)

# Module-specific includes
target_include_directories(_hitls_tls_cert
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cert_adapt>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/hitls_x509_adapt>
    PRIVATE
        ${PROJECT_SOURCE_DIR}/tls/config/include
        ${PROJECT_SOURCE_DIR}/tls/handshake/pack/include
        ${PROJECT_SOURCE_DIR}/tls/handshake/common/include
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
        ${PROJECT_SOURCE_DIR}/pki/x509_cert/include
        ${PROJECT_SOURCE_DIR}/pki/x509_common/include
        ${PROJECT_SOURCE_DIR}/bsl/asn1/include
)

hitls_register_objects(TLS _hitls_tls_cert)
