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


if(NOT HITLS_BUILD_EXE)
    message(STATUS "[APPS] Skipping hitls executable (HITLS_BUILD_EXE=OFF)")
    return()
endif()

message(STATUS "[APPS] Configuring apps modules")

# Include helper functions
include(helpers/hitls_target_helpers)

file(GLOB _apps_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

add_library(_hitls_apps OBJECT ${_apps_sources})

target_include_directories(_hitls_apps
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${PROJECT_SOURCE_DIR}/bsl/uio/include
        ${PROJECT_SOURCE_DIR}/bsl/obj/include
        ${PROJECT_SOURCE_DIR}/bsl/ui/include
        ${PROJECT_SOURCE_DIR}/bsl/pem/include
        ${PROJECT_SOURCE_DIR}/bsl/conf/include
        ${PROJECT_SOURCE_DIR}/bsl/print/include
        ${PROJECT_SOURCE_DIR}/bsl/list/include
        ${PROJECT_SOURCE_DIR}/bsl/asn1/include
        ${PROJECT_SOURCE_DIR}/bsl/buffer/include
        ${PROJECT_SOURCE_DIR}/bsl/sal/include
        ${PROJECT_SOURCE_DIR}/crypto/bn/include
        ${PROJECT_SOURCE_DIR}/crypto/codecskey/include
        ${PROJECT_SOURCE_DIR}/crypto/provider/src/cmvp/cmvp_utils
        ${PROJECT_SOURCE_DIR}/pki/x509_cert/include
        ${PROJECT_SOURCE_DIR}/pki/x509_crl/include
        ${PROJECT_SOURCE_DIR}/pki/pkcs12/include
        ${PROJECT_SOURCE_DIR}/pki/x509_csr/include
        ${PROJECT_SOURCE_DIR}/pki/x509_common/include
        ${PROJECT_SOURCE_DIR}/include/pki
        ${PROJECT_SOURCE_DIR}/include/tls
        ${PROJECT_SOURCE_DIR}/include/crypto
        ${PROJECT_SOURCE_DIR}/include/bsl
        ${PROJECT_SOURCE_DIR}/tls/include
        ${PROJECT_SOURCE_DIR}/crypto/include
        ${PROJECT_SOURCE_DIR}/bsl/include
)

hitls_register_objects(APPS _hitls_apps)

message(STATUS "[APPS] Created target _hitls_apps")
