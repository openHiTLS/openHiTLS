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

project(GEN_TEST)

set(GEN_TESTCASE "gen_testcase")
set(HITLS_SRC ${PROJECT_SOURCE_DIR}/../../..)
set(EXECUTABLE_OUTPUT_PATH ${HITLS_SRC}/testcode/output)
set(SECURTE_INCLUDE ${HITLS_SRC}/platform/Secure_C/include)
set(GEN_SOURCE_SRC
    ${PROJECT_SOURCE_DIR}/main.c
    ${PROJECT_SOURCE_DIR}/helper.c
    ${PROJECT_SOURCE_DIR}/test.c
)

include_directories(${SECURTE_INCLUDE}
    ${HITLS_SRC}/testcode/framework/include
    ${HITLS_SRC}/testcode/framework/crypto
    ${HITLS_SRC}/config/macro_config
    ${HITLS_SRC}/crypto/include
    ${HITLS_SRC}/include/crypto
    ${HITLS_SRC}/include/bsl
    ${HITLS_SRC}/bsl/err/include
)

add_executable(${GEN_TESTCASE} ${GEN_SOURCE_SRC})

if(PRINT_TO_TERMINAL)
    target_compile_options(${GEN_TESTCASE} PRIVATE -DPRINT_TO_TERMINAL)
endif()

# Use find_library to support cross-platform static library extensions (.a on Unix, .lib on Windows)
find_library(BOUNDSCHECK_STATIC_LIB
    NAMES libboundscheck.a boundscheck  # Try .a explicitly first, then let CMake find static version
    PATHS ${HITLS_SRC}/platform/Secure_C/lib
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
)
if(NOT BOUNDSCHECK_STATIC_LIB)
    message(FATAL_ERROR "Could not find static boundscheck library at ${HITLS_SRC}/platform/Secure_C/lib")
endif()
target_link_libraries(${GEN_TESTCASE} ${BOUNDSCHECK_STATIC_LIB})
