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

PROJECT(TLS_FRAME)
set(CMAKE_VERBOSE_MAKEFILEON ON)
SET(DT_LIBNAME "tls_frame")
SET(HLT_LIBNAME "tls_hlt")
SET(WRAPPER_LIBNAME "rec_wrapper")

if(ENABLE_TLS_DEBUG)
    add_compile_definitions(TLS_DEBUG)
endif()
SET(HITLS_SRC ${PROJECT_SOURCE_DIR}/../../../)
set(SECUREC_INCLUDE ${HITLS_SRC}/platform/Secure_C/include)

include_directories(${SECUREC_INCLUDE}
                    ${HITLS_SRC}/include
                    ${HITLS_SRC}/include/tls
                    ${HITLS_SRC}/include/bsl
                    ${HITLS_SRC}/include/crypto
                    ${HITLS_SRC}/config/macro_config
                    ${HITLS_SRC}/bsl/list/include
                    ${HITLS_SRC}/bsl/obj/include
                    ${HITLS_SRC}/bsl/include
                    ${HITLS_SRC}/bsl/sal/include
                    ${HITLS_SRC}/bsl/log/include
                    ${HITLS_SRC}/bsl/time/include
                    ${HITLS_SRC}/bsl/async/include
                    ${HITLS_SRC}/bsl/uio/include
                    ${HITLS_SRC}/bsl/uio/src
                    ${HITLS_SRC}/pki/x509_cert/include
                    ${HITLS_SRC}/tls/cert/hitls_x509_adapt
                    ${HITLS_SRC}/tls/include
                    ${HITLS_SRC}/tls/cert/cert_self
                    ${HITLS_SRC}/tls/cert/include
                    ${HITLS_SRC}/tls/config/include
                    ${HITLS_SRC}/tls/cm/include
                    ${HITLS_SRC}/tls/record/include
                    ${HITLS_SRC}/tls/record/src
                    ${HITLS_SRC}/tls/handshake/cookie/include
                    ${HITLS_SRC}/tls/handshake/common/include
                    ${HITLS_SRC}/tls/crypt/include/
                    ${HITLS_SRC}/tls/handshake/parse/include
                    ${HITLS_SRC}/tls/handshake/pack/src
                    ${HITLS_SRC}/tls/handshake/pack/include
                    ${HITLS_SRC}/tls/ccs/include
                    ${HITLS_SRC}/tls/alert/include
                    ${HITLS_SRC}/testcode/framework/stub
                    ${PROJECT_SOURCE_DIR}/include
                    ${PROJECT_SOURCE_DIR}/io/include
                    ${PROJECT_SOURCE_DIR}/cert/include
                    ${PROJECT_SOURCE_DIR}/crypt/include
                    ${PROJECT_SOURCE_DIR}/msg/include
                    ${PROJECT_SOURCE_DIR}/base/include
                    ${PROJECT_SOURCE_DIR}/resource/include
                    ${PROJECT_SOURCE_DIR}/rpc/include
                    ${PROJECT_SOURCE_DIR}/process/include
                    ${PROJECT_SOURCE_DIR}/transfer/include
                    ${PROJECT_SOURCE_DIR}/frame/src
                    ${PROJECT_SOURCE_DIR}/io/src
                    ${PROJECT_SOURCE_DIR}/func_wrapper/include
                    ${PROJECT_SOURCE_DIR}/callback/include)

aux_source_directory(${PROJECT_SOURCE_DIR}/cert/src CERT_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/crypt/src CRYPT_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/io/src IO_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/frame/src FRAME_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/msg/src MSG_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/base/src BASE_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/resource/src RESOURCE_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/process/src PROCESS_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/rpc/src RPC_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/transfer/src TRANSFER_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/callback/src CALLBACK_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/func_wrapper/src WRAPPER_SRC)
SET(WRAPPER_SRC ${WRAPPER_SRC} ${HITLS_SRC}/testcode/framework/stub/stub_replace.c)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
add_compile_options(-g)
add_definitions(${CUSTOM_CFLAGS})
add_library(${HLT_LIBNAME}
    STATIC
    ${BASE_SRC} ${RESOURCE_SRC} ${CALLBACK_SRC} ${PROCESS_SRC} ${RPC_SRC} ${TRANSFER_SRC})
add_library(${DT_LIBNAME}
    STATIC
    ${BASE_SRC}  ${CALLBACK_SRC} ${CRYPT_SRC} ${IO_SRC} ${FRAME_SRC} ${MSG_SRC})
add_library(${WRAPPER_LIBNAME}
    STATIC
    ${WRAPPER_SRC})
   