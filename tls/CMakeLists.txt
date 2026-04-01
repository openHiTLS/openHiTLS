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


if(NOT HITLS_TLS)
    message(STATUS "[TLS] Skipping TLS (HITLS_TLS=OFF)")
    return()
endif()

message(STATUS "[TLS] Configuring TLS modules")

include(helpers/hitls_target_helpers)

# ==============================================================================
# Common include directories for all TLS modules (INTERFACE target)
# ==============================================================================
# Modern CMake: Use INTERFACE target instead of global variables
# Subdirectories can use: target_link_libraries(xxx PUBLIC _hitls_tls_common_include)
# ==============================================================================
add_library(_hitls_tls_common_include INTERFACE)
target_include_directories(_hitls_tls_common_include INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/tls
    ${PROJECT_SOURCE_DIR}/include/pki
    ${PROJECT_SOURCE_DIR}/bsl/hash/include
)

# TLS common inherits BSL common and Crypto common (if available)
target_link_libraries(_hitls_tls_common_include INTERFACE
    $<TARGET_NAME_IF_EXISTS:_hitls_bsl_common_include>
    $<TARGET_NAME_IF_EXISTS:_hitls_crypto_common_include>
)

# ==============================================================================
# TLS Sub-modules in dependency order
# ==============================================================================

# Config - Configuration (foundation)
add_subdirectory(config)

# Alert - Alert handling
add_subdirectory(alert)

# CCS - Change Cipher Spec
add_subdirectory(ccs)

# Record - Record layer
add_subdirectory(record)

# Crypt - TLS crypto operations
add_subdirectory(crypt)

# Feature - Feature negotiation (extensions, versions, etc.)
# Build feature module if umbrella macro OR any individual feature is enabled
add_subdirectory(feature)

# Cert - Certificate handling
add_subdirectory(cert)

# Handshake - TLS handshake protocol
add_subdirectory(handshake)

# CM - Connection management
add_subdirectory(cm)

# App - Application layer
add_subdirectory(app)

message(STATUS "[TLS] TLS configuration complete")
