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


if(NOT HITLS_PKI)
    message(STATUS "[PKI] Skipping PKI (HITLS_PKI=OFF)")
    return()
endif()

message(STATUS "[PKI] Configuring PKI modules")

# Include helper functions
include(helpers/hitls_target_helpers)

# ==============================================================================
# Common include directories for all PKI modules (INTERFACE target)
# ==============================================================================
# Modern CMake: Use INTERFACE target instead of global variables
# Subdirectories can use: target_link_libraries(xxx PUBLIC _hitls_pki_common_include)
# ==============================================================================
add_library(_hitls_pki_common_include INTERFACE)
target_include_directories(_hitls_pki_common_include INTERFACE
    ${PROJECT_SOURCE_DIR}/include/pki
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/bsl
    ${PROJECT_SOURCE_DIR}/include/crypto
    ${PROJECT_SOURCE_DIR}/crypto/bn/include
    ${PROJECT_SOURCE_DIR}/crypto/codecskey/include
    ${PROJECT_SOURCE_DIR}/bsl/include
    ${PROJECT_SOURCE_DIR}/bsl/err/include
    ${PROJECT_SOURCE_DIR}/bsl/pem/include
    ${PROJECT_SOURCE_DIR}/bsl/asn1/include
    ${PROJECT_SOURCE_DIR}/bsl/obj/include
)
# PKI common inherits BSL and Crypto common (if available)
target_link_libraries(_hitls_pki_common_include INTERFACE
    $<TARGET_NAME_IF_EXISTS:_hitls_bsl_common_include>
    $<TARGET_NAME_IF_EXISTS:_hitls_crypto_common_include>
)

# ==============================================================================
# PKI Sub-modules
# (add in dependency order: foundation first, higher-level last)
# ==============================================================================

# X509 Common - Foundation types and utilities shared by cert/crl/csr
if(HITLS_PKI_X509)
    add_subdirectory(x509_common)
endif()

# X509 Certificate
if(HITLS_PKI_X509_CRT)
    add_subdirectory(x509_cert)
endif()

# X509 CRL (Certificate Revocation List)
if(HITLS_PKI_X509_CRL)
    add_subdirectory(x509_crl)
endif()

# X509 CSR (Certificate Signing Request)
if(HITLS_PKI_X509_CSR)
    add_subdirectory(x509_csr)
endif()

# X509 Verify - Certificate chain verification
if(HITLS_PKI_X509_VFY_DEFAULT OR HITLS_PKI_X509_VFY_CB OR HITLS_PKI_X509_VFY_LOCATION)
    add_subdirectory(x509_verify)
endif()

# CMS - Cryptographic Message Syntax
if(HITLS_PKI_CMS)
    add_subdirectory(cms)
endif()

# PKCS12 - Personal Information Exchange Syntax
if(HITLS_PKI_PKCS12)
    add_subdirectory(pkcs12)
endif()

# Print - Human-readable output for PKI objects
if(HITLS_PKI_INFO)
    add_subdirectory(print)
endif()

message(STATUS "[PKI] PKI configuration complete")
