# ---------------------------------------------------------------------------------------------
#  This file is part of the openHiTLS project.
#  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
#  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
#  for license information.
# ---------------------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(TLS_PROCESS)

set(PROCESS "process")
set(HITLS_SRC ${PROJECT_SOURCE_DIR}/../../..)
set(EXECUTABLE_OUTPUT_PATH ${HITLS_SRC}/testcode/output)
set(SECUREC_INCLUDE ${HITLS_SRC}/platform/Secure_C/include)

include_directories(
    ${SECUREC_INCLUDE}
    ${HITLS_SRC}/testcode/framework/tls/resource/include
    ${HITLS_SRC}/testcode/framework/tls/base/include
    ${HITLS_SRC}/testcode/framework/tls/process/include
    ${HITLS_SRC}/testcode/framework/tls/include
    ${HITLS_SRC}/testcode/framework/tls/transfer/include
    ${HITLS_SRC}/testcode/framework/tls/rpc/include
    ${HITLS_SRC}/include/bsl
    ${HITLS_SRC}/bsl/sal/include
    ${HITLS_SRC}/bsl/uio/src
    ${HITLS_SRC}/bsl/uio/include
    ${HITLS_SRC}/include/tls
    ${HITLS_SRC}/tls/include
    ${HITLS_SRC}/config/macro_config
)

add_executable(${PROCESS} ${PROJECT_SOURCE_DIR}/process.c)

if(PRINT_TO_TERMINAL)
    target_compile_options(${PROCESS} PUBLIC -DPRINT_TO_TERMINAL)
endif()

if(ENABLE_FAIL_REPEAT)
    target_compile_options(${PROCESS} PUBLIC -DFAIL_REPEAT_RUN)
endif()

target_link_directories(${PROCESS}
    PUBLIC
        ${HITLS_SRC}/build
        ${HITLS_SRC}/testcode/framework/tls/lib
        ${HITLS_SRC}/platform/Secure_C/lib
)
target_link_libraries(${PROCESS}
    tls_hlt    
    tls_frame
    hitls_tls
    hitls_crypto
    hitls_x509
    hitls_bsl
    boundscheck
    pthread
    sctp
    rec_wrapper
)
