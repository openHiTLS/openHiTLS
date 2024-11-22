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
    hitls_pki
    hitls_crypto
    hitls_bsl
    boundscheck
    pthread
    dl
    sctp
    rec_wrapper
)
