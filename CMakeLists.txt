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


cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(openHiTLS)
include(GNUInstallDirs)

# Version info and other global definitions
set(OPENHITLS_VERSION_S "openHiTLS 0.4.0 31 Mar. 2026"  CACHE STRING "openHiTLS version string")
set(OPENHITLS_VERSION_I "4194304"                       CACHE STRING "openHiTLS version integer")
set(CMVP_INTEGRITYKEY   "b8fc4931453af3285f0f"          CACHE STRING "CMVP integrity key")

# Set CMAKE_MODULE_PATH to include our custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
# Include helper functions
include(helpers/hitls_depends_helpers)
include(helpers/hitls_lib_helpers)
# Defined dependencies - Define all dependencies between features
include(hitls_define_dependencies)

# Load preset (if not already loaded) to set options based on selected profile
include(hitls_load_preset)

# Detect platform and set platform-specific options
include(hitls_platform)

# Set compile options and link flags
include(hitls_compile_options)

# Derive all children for each enabled option
hitls_feature_children_derive()

# Derive TLS suite options based on cipher, key exchange and authentication method selections
hitls_tls_suites_derive()

# Derive all dependencies for each enabled option
hitls_feature_dependencies_derive()

# Options - Define all user-configurable options 
#   (fills in defaults for anything not already set by the preset / -D command-line arguments)
include(hitls_options)

# Auto-enable any required ASM features based on enabled options
hitls_auto_enable_asm_features()

# Handle special dependencies(Complex conditions)
# must be handled after all options and dependencies are defined, because it depends on some default options
hitls_special_depends_handle()

# Generate config/hitls_build_config.h to build directory based on template and enabled options 
include(hitls_generate_config_h_file)

# Collect all feature macros to _HITLS_ALL_FEATURE_MACROS
include(hitls_collect_feature_macros)

# Check for any warnings about unsatisfied dependencies and print them to the user
include(hitls_config_check)

# Apply all enabled macros as global compile definitions
add_compile_definitions(${_HITLS_ALL_FEATURE_MACROS})
# Define OPENHITLSDIR macro for runtime use (e.g. cert lookup paths)
add_compile_definitions(OPENHITLSDIR="${CMAKE_INSTALL_PREFIX}/")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENHITLS_VERSION_S='\"${OPENHITLS_VERSION_S}\"'")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENHITLS_VERSION_I=${OPENHITLS_VERSION_I}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCMVP_INTEGRITYKEY='\"${CMVP_INTEGRITYKEY}\"'")
# Define common include directories for all targets
include_directories(
    ${PROJECT_SOURCE_DIR}/config/macro_config
    ${PROJECT_SOURCE_DIR}/platform/Secure_C/include
)

# Build all targets
include(hitls_build_targets)

# Generate build information files if enabled
if(HITLS_BUILD_GEN_INFO)
    include(hitls_gen_info)
endif()

# Install public headers
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hitls
        FILES_MATCHING PATTERN "*.h")
