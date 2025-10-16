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

PROJECT(openHiTLS_TEST)

set(openHiTLS_SRC "${PROJECT_SOURCE_DIR}/..")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    option(__x86_64__ "x86" ON)
endif()

# Base compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wformat=2 -Wno-format-nonliteral -Wno-deprecated-declarations -Wno-unused-but-set-variable")

# Add macOS-specific warning suppression for generated code
if(APPLE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-sometimes-uninitialized")
    # Fix linker warning: "reducing alignment of section __DATA,__common from 0x8000 to 0x4000"
    # Apple Clang still defaults to -fcommon (unlike GCC 10+ and LLVM Clang 11+)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-common")
endif()

# Detect platform-specific shared library extension
if(APPLE)
    set(SHARED_LIB_EXT ".dylib")
else()
    set(SHARED_LIB_EXT ".so")
endif()

# Dynamically determine provider library name based on CMVP mode
# This allows testing of ISO19790, FIPS, SM, or standard providers
if(CUSTOM_CFLAGS MATCHES "-DHITLS_CRYPTO_CMVP_ISO19790")
    set(HITLS_PROVIDER_LIB_NAME "libhitls_iso${SHARED_LIB_EXT}")
    message(STATUS "Provider library: ISO19790 mode (${HITLS_PROVIDER_LIB_NAME})")
elseif(CUSTOM_CFLAGS MATCHES "-DHITLS_CRYPTO_CMVP_FIPS")
    set(HITLS_PROVIDER_LIB_NAME "libhitls_fips${SHARED_LIB_EXT}")
    message(STATUS "Provider library: FIPS mode (${HITLS_PROVIDER_LIB_NAME})")
elseif(CUSTOM_CFLAGS MATCHES "-DHITLS_CRYPTO_CMVP_SM")
    set(HITLS_PROVIDER_LIB_NAME "libhitls_sm${SHARED_LIB_EXT}")
    message(STATUS "Provider library: SM mode (${HITLS_PROVIDER_LIB_NAME})")
else()
    set(HITLS_PROVIDER_LIB_NAME "libhitls${SHARED_LIB_EXT}")
    message(STATUS "Provider library: Standard mode (${HITLS_PROVIDER_LIB_NAME})")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHITLS_PROVIDER_LIB_NAME=\\\"${HITLS_PROVIDER_LIB_NAME}\\\"")

# Add GNU ld-specific wrap flags only on Linux (not supported on macOS)
if(NOT APPLE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--wrap=REC_Read -Wl,--wrap=REC_Write")
endif()

message(STATUS "System processor :${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Enable bsl uio sctp :${ENABLE_UIO_SCTP}")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "System architecture: 64")
else()
    message(STATUS "System architecture: 32")
endif()

if(ENABLE_GCOV)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage -lgcov")
endif()

if(ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-stack-protector -fno-omit-frame-pointer")
endif()

if(CUSTOM_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CUSTOM_CFLAGS}")
endif()

if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g")
endif()

if(PRINT_TO_TERMINAL)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPRINT_TO_TERMINAL=${PRINT_TO_TERMINAL}")
endif()

if(ENABLE_FAIL_REPEAT)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_FAIL_REPEAT=${ENABLE_FAIL_REPEAT}")
endif()

if(OS_BIG_ENDIAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mbig-endian")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64")

string(FIND "${CUSTOM_CFLAGS}" "-DHITLS_PKI" BUILD_PKI)
string(FIND "${CUSTOM_CFLAGS}" "-DHITLS_AUTH" BUILD_AUTH)
string(FIND "${CUSTOM_CFLAGS}" "-DHITLS_CRYPTO" BUILD_CRYPTO)
string(FIND "${CUSTOM_CFLAGS}" "-DHITLS_TLS" BUILD_TLS)

include(ExternalProject)
ExternalProject_Add(gen_testcase
    SOURCE_DIR            ${openHiTLS_SRC}
    PREFIX                ""
    BINARY_DIR            ${openHiTLS_SRC}/testcode/framework/gen_test/build/
    INSTALL_DIR           ""
    UPDATE_COMMAND        ""
    CONFIGURE_COMMAND     cmake -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} -DPRINT_TO_TERMINAL=${ENABLE_PRINT} ..
    BUILD_COMMAND         make
    INSTALL_COMMAND       ""
    BUILD_ALWAYS          FALSE
    LOG_BUILD             TRUE
    LOG_DOWNLOAD          TRUE
    EXCLUDE_FROM_ALL      TRUE
    LOG_OUTPUT_ON_FAILURE TRUE
)

add_subdirectory(${openHiTLS_SRC}/testcode/sdv)

if(ENABLE_TLS AND ${BUILD_TLS} GREATER -1)
    add_subdirectory(${openHiTLS_SRC}/testcode/framework/tls)
    add_subdirectory(${openHiTLS_SRC}/testcode/framework/process)
    add_dependencies(gen_testcase process)
endif()
