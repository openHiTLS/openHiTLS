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

if(NOT HITLS_AUTH)
    message(STATUS "[AUTH] Skipping AUTH (HITLS_AUTH=OFF)")
    return()
endif()

message(STATUS "[AUTH] Configuring AUTH modules")

# Include helper functions
include(helpers/hitls_target_helpers)

# ==============================================================================
# Common include directories for all AUTH modules (INTERFACE target)
# ==============================================================================
# Modern CMake: Use INTERFACE target instead of global variables
# Subdirectories can use: target_link_libraries(xxx PUBLIC _hitls_auth_common_include)
# ==============================================================================
add_library(_hitls_auth_common_include INTERFACE)
target_include_directories(_hitls_auth_common_include INTERFACE
    ${PROJECT_SOURCE_DIR}/include/auth               # auth public headers
    ${PROJECT_SOURCE_DIR}/include                    # top-level public headers (hitls_build.h)
    ${PROJECT_SOURCE_DIR}/include/bsl                # bsl public headers
    ${PROJECT_SOURCE_DIR}/include/crypto             # crypto public headers
    ${PROJECT_SOURCE_DIR}/bsl/include                # bsl internal headers
    ${PROJECT_SOURCE_DIR}/bsl/err/include            # bsl_err_internal.h
)
# AUTH common inherits BSL and Crypto common (if available)
target_link_libraries(_hitls_auth_common_include INTERFACE
    $<TARGET_NAME_IF_EXISTS:_hitls_bsl_common_include>
    $<TARGET_NAME_IF_EXISTS:_hitls_crypto_common_include>
)

# ==============================================================================
# AUTH Sub-modules
# (add in dependency order: foundation first, higher-level last)
# ==============================================================================

# PrivPass Token
if(HITLS_AUTH_PRIVPASS_TOKEN)
    add_subdirectory(privpass_token)
endif()

# OTP
if(HITLS_AUTH_OTP)
    add_subdirectory(otp)
endif()

# PAKE (pake_core / spake2plus)
if(HITLS_AUTH_PAKE)
    add_subdirectory(pake)
endif()

message(STATUS "[AUTH] AUTH configuration complete")
