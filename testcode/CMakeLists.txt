# ---------------------------------------------------------------------------------------------
#  This file is part of the openHiTLS project.
#  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
#  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
#  for license information.
# ---------------------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

PROJECT(openHiTLS_TEST)

set(openHiTLS_SRC "${PROJECT_SOURCE_DIR}/..")
set(PROCESS PROCESS)
set(GEN_TESTCASE GEN_TESTCASE)
set(TESTCASE TESTCASE)
set(LIB_TEST_TLS LIB_TEST_TLS)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    option(__x86_64__ "x86" ON)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat=2 -Wno-format-nonliteral -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wl,--wrap=REC_Read -Wl,--wrap=REC_Write")

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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64 -D_POSIX_C_SOURCE=200809L")

include(ExternalProject)

ExternalProject_Add(${GEN_TESTCASE}
    SOURCE_DIR            ${openHiTLS_SRC}
    PREFIX                ""
    BINARY_DIR            ${openHiTLS_SRC}/testcode/framework/gen_test/build/${TESTFILE}
    INSTALL_DIR           ""
    UPDATE_COMMAND        ""
    CONFIGURE_COMMAND     cmake -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} -DPRINT_TO_TERMINAL=${ENABLE_PRINT} ../..
    BUILD_COMMAND         make
    INSTALL_COMMAND       ""
    BUILD_ALWAYS          FALSE
    LOG_BUILD             TRUE
    LOG_DOWNLOAD          TRUE
    EXCLUDE_FROM_ALL      TRUE
    LOG_OUTPUT_ON_FAILURE TRUE
)

ExternalProject_Add(${TESTCASE}
    SOURCE_DIR            ${openHiTLS_SRC}
    PREFIX                ""
    BINARY_DIR            ${openHiTLS_SRC}/testcode/sdv/build/${TESTFILE}
    INSTALL_DIR           ""
    UPDATE_COMMAND        ""
    CONFIGURE_COMMAND     cmake -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} -DENABLE_CRYPTO=${ENABLE_CRYPTO}
                                -DGEN_TEST_FILES=${GEN_TEST_FILES} -DENABLE_UIO_SCTP=${ENABLE_UIO_SCTP} ../..
    BUILD_COMMAND         make
    INSTALL_COMMAND       ""
    DEPENDS               ${GEN_TESTCASE}
    BUILD_ALWAYS          FALSE
    LOG_BUILD             TRUE
    LOG_DOWNLOAD          TRUE
    EXCLUDE_FROM_ALL      TRUE
    LOG_OUTPUT_ON_FAILURE TRUE
)

