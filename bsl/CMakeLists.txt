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


if(NOT HITLS_BSL)
    message(STATUS "[BSL] Skipping BSL (HITLS_BSL=OFF)")
    return()
endif()

message(STATUS "[BSL] Configuring BSL modules")

# Include helper functions
include(helpers/hitls_target_helpers)

# ==============================================================================
# Common include directories for all BSL modules (INTERFACE target)
# ==============================================================================
# Modern CMake: Use INTERFACE target instead of global variables
# Subdirectories can use: target_link_libraries(xxx PUBLIC _hitls_bsl_common_include)
# ==============================================================================
add_library(_hitls_bsl_common_include INTERFACE)
target_include_directories(_hitls_bsl_common_include INTERFACE
    ${PROJECT_SOURCE_DIR}/include/bsl               # expose bsl public headers
    ${PROJECT_SOURCE_DIR}/bsl/list/include
    ${PROJECT_SOURCE_DIR}/bsl/err/include
    ${PROJECT_SOURCE_DIR}/bsl/log/include
    ${PROJECT_SOURCE_DIR}/bsl/sal/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ==============================================================================
# Add BSL sub-modules in dependency order
# ==============================================================================

# ASN1 - ASN.1 encoding/decoding
if(HITLS_BSL_ASN1)
    add_subdirectory(asn1)
endif()

# BASE64 - Base64 encoding/decoding
if(HITLS_BSL_BASE64)
    add_subdirectory(base64)
endif()

# BUFFER - Buffer management
if(HITLS_BSL_BUFFER)
    add_subdirectory(buffer)
endif()

# CONF - Configuration
if(HITLS_BSL_CONF)
    add_subdirectory(conf)
endif()

# ERR - Error handling
if(HITLS_BSL_ERR)
    add_subdirectory(err)
endif()

# HASH - Hash table
if(HITLS_BSL_HASH)
    add_subdirectory(hash)
endif()

# INIT - Initialization
if(HITLS_BSL_INIT)
    add_subdirectory(init)
endif()

# LIST - Linked list utilities
if(HITLS_BSL_LIST)
    add_subdirectory(list)
endif()

# LOG - Logging
if(HITLS_BSL_LOG)
    add_subdirectory(log)
endif()

# OBJ - Object identifiers
if(HITLS_BSL_OBJ)
    add_subdirectory(obj)
endif()

# PARAMS - Parameter handling
if(HITLS_BSL_PARAMS)
    add_subdirectory(params)
endif()

# PEM - PEM file handling
if(HITLS_BSL_PEM)
    add_subdirectory(pem)
endif()

# PRINT - Print utilities
if(HITLS_BSL_PRINT)
    add_subdirectory(print)
endif()

# SAL - System Abstraction Layer
if(HITLS_BSL_SAL OR HITLS_BSL_SAL_DL OR HITLS_BSL_SAL_FILE OR HITLS_BSL_SAL_LOCK OR
    HITLS_BSL_SAL_MEM OR HITLS_BSL_SAL_NET OR HITLS_BSL_SAL_STR OR HITLS_BSL_SAL_THREAD OR
    HITLS_BSL_SAL_TIME OR HITLS_BSL_SAL_PID OR HITLS_BSL_SAL_IP)
    add_subdirectory(sal)
endif()

# TLV - Tag-Length-Value encoding
if(HITLS_BSL_TLV)
    add_subdirectory(tlv)
endif()

# UI - User interface
if(HITLS_BSL_UI)
    add_subdirectory(ui)
endif()

# UIO - Universal I/O 
# Check any UIO feature to determine if we need to build UIO module
if(HITLS_BSL_UIO)
    add_subdirectory(uio)
endif()

message(STATUS "[BSL] BSL configuration complete")
