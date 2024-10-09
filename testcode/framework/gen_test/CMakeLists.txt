# ---------------------------------------------------------------------------------------------
#  This file is part of the openHiTLS project.
#  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
#  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
#  for license information.
# ---------------------------------------------------------------------------------------------
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
    ${HITLS_SRC}/crypto/include
    ${HITLS_SRC}/include/crypto
    ${HITLS_SRC}/include/bsl
)

add_executable(${GEN_TESTCASE} ${GEN_SOURCE_SRC})

if(PRINT_TO_TERMINAL)
    target_compile_options(${GEN_TESTCASE} PUBLIC -DPRINT_TO_TERMINAL)
endif()

target_link_directories(${GEN_TESTCASE}
    PUBLIC
        ${HITLS_SRC}/platform/Secure_C/lib
)
target_link_libraries(${GEN_TESTCASE}
    -lboundscheck
)
