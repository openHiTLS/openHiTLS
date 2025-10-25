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

SET(DT_LIBNAME "tls_frame")
SET(HLT_LIBNAME "tls_hlt")
SET(WRAPPER_LIBNAME "rec_wrapper")

add_library(TLS_TEST_INTF INTERFACE)
if(TLS_DEBUG)
    add_compile_definitions(TLS_TEST_INTF INTERFACE TLS_DEBUG)
endif()

target_include_directories(TLS_TEST_INTF INTERFACE
    ${openHiTLS_SRC}/platform/Secure_C/include
    ${openHiTLS_SRC}/include
    ${openHiTLS_SRC}/include/tls
    ${openHiTLS_SRC}/include/bsl
    ${openHiTLS_SRC}/include/crypto
    ${openHiTLS_SRC}/include/pki
    ${openHiTLS_SRC}/config/macro_config
    ${openHiTLS_SRC}/bsl/list/include
    ${openHiTLS_SRC}/bsl/obj/include
    ${openHiTLS_SRC}/bsl/include
    ${openHiTLS_SRC}/bsl/sal/include
    ${openHiTLS_SRC}/bsl/log/include
    ${openHiTLS_SRC}/bsl/time/include
    ${openHiTLS_SRC}/bsl/async/include
    ${openHiTLS_SRC}/bsl/hash/include
    ${openHiTLS_SRC}/bsl/uio/include
    ${openHiTLS_SRC}/bsl/uio/src
    ${openHiTLS_SRC}/pki/x509_cert/include
    ${openHiTLS_SRC}/tls/cert/hitls_x509_adapt
    ${openHiTLS_SRC}/tls/include
    ${openHiTLS_SRC}/tls/cert/cert_self
    ${openHiTLS_SRC}/tls/cert/include
    ${openHiTLS_SRC}/tls/config/include
    ${openHiTLS_SRC}/tls/cm/include
    ${openHiTLS_SRC}/tls/record/include
    ${openHiTLS_SRC}/tls/record/src
    ${openHiTLS_SRC}/tls/handshake/cookie/include
    ${openHiTLS_SRC}/tls/handshake/common/include
    ${openHiTLS_SRC}/tls/crypt/include/
    ${openHiTLS_SRC}/tls/handshake/parse/include
    ${openHiTLS_SRC}/tls/handshake/pack/src
    ${openHiTLS_SRC}/tls/handshake/pack/include
    ${openHiTLS_SRC}/tls/ccs/include
    ${openHiTLS_SRC}/tls/alert/include
    ${openHiTLS_SRC}/tls/crypt/crypt_self
    ${openHiTLS_SRC}/testcode/framework/stub
    ${openHiTLS_SRC}/testcode/framework/tls/include
    ${openHiTLS_SRC}/testcode/framework/tls/io/include
    ${openHiTLS_SRC}/testcode/framework/tls/cert/include
    ${openHiTLS_SRC}/testcode/framework/tls/crypt/include
    ${openHiTLS_SRC}/testcode/framework/tls/msg/include
    ${openHiTLS_SRC}/testcode/framework/tls/base/include
    ${openHiTLS_SRC}/testcode/framework/tls/resource/include
    ${openHiTLS_SRC}/testcode/framework/tls/rpc/include
    ${openHiTLS_SRC}/testcode/framework/tls/process/include
    ${openHiTLS_SRC}/testcode/framework/tls/transfer/include
    ${openHiTLS_SRC}/testcode/framework/tls/frame/src
    ${openHiTLS_SRC}/testcode/framework/tls/io/src
    ${openHiTLS_SRC}/testcode/framework/tls/func_wrapper/include
    ${openHiTLS_SRC}/testcode/framework/tls/callback/include
    ${openHiTLS_SRC}/tls/feature/custom_extensions/include
)

aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/crypt/src CRYPT_SRC)
aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/io/src IO_SRC)
aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/frame/src FRAME_SRC)
aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/msg/src MSG_SRC)
aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/base/src BASE_SRC)
aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/resource/src RESOURCE_SRC)
aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/process/src PROCESS_SRC)
aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/rpc/src RPC_SRC)
aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/transfer/src TRANSFER_SRC)
aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/callback/src CALLBACK_SRC)
aux_source_directory(${openHiTLS_SRC}/testcode/framework/tls/func_wrapper/src WRAPPER_SRC)

target_compile_options(TLS_TEST_INTF INTERFACE -g)

add_library(${HLT_LIBNAME}
    STATIC
    ${BASE_SRC} ${RESOURCE_SRC} ${CALLBACK_SRC} ${PROCESS_SRC} ${RPC_SRC} ${TRANSFER_SRC})
target_link_libraries(${HLT_LIBNAME} PRIVATE TLS_TEST_INTF)
add_library(${DT_LIBNAME}
    STATIC
    ${BASE_SRC}  ${CALLBACK_SRC} ${CRYPT_SRC} ${IO_SRC} ${FRAME_SRC} ${MSG_SRC})
target_link_libraries(${DT_LIBNAME} PRIVATE TLS_TEST_INTF)

# compile wrapper source directly into test executables use cmake library type INTERFACE
# This ensures REC_Write/REC_Read wrappers can override library symbols on all platforms
add_library(${WRAPPER_LIBNAME} INTERFACE)
target_sources(${WRAPPER_LIBNAME} INTERFACE ${WRAPPER_SRC})
target_link_libraries(${WRAPPER_LIBNAME} INTERFACE TLS_TEST_INTF)

set_target_properties(${HLT_LIBNAME} ${DT_LIBNAME}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${openHiTLS_SRC}/testcode/output/lib"
)
