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

set(HiTLS_SOURCE_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})

if(DEFINED BUILD_DIR)
    set(HiTLS_BUILD_DIR ${BUILD_DIR})
else()
    set(HiTLS_BUILD_DIR ${HiTLS_SOURCE_ROOT_DIR}/build)
endif()

# Include toolchain file before project() to control compiler selection
set(TOOLCHAIN_FILE "${HiTLS_BUILD_DIR}/toolchain.cmake")
if(EXISTS ${TOOLCHAIN_FILE})
    include(${TOOLCHAIN_FILE})
endif()

project(openHiTLS)

# ============================================================
# Build Secure C (libboundscheck) dependency
# ============================================================
# Note: This builds the securec submodule using CMake instead of Makefile
# for better cross-platform support (especially macOS and Windows).
# The SecureC.cmake file is maintained in openHiTLS (not in the submodule)
# to avoid git conflicts with upstream libboundscheck repository.
message(STATUS "Configuring securec dependency...")
include(${HiTLS_SOURCE_ROOT_DIR}/platform/SecureC.cmake)

# ============================================================
# Generate modules.cmake from configure.py
# ============================================================
execute_process(COMMAND python3 ${HiTLS_SOURCE_ROOT_DIR}/configure.py -m --build_dir ${HiTLS_BUILD_DIR})

include(${HiTLS_BUILD_DIR}/modules.cmake)

install(DIRECTORY ${HiTLS_SOURCE_ROOT_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include/hitls/
        FILES_MATCHING PATTERN "*.h")
