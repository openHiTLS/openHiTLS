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

add_executable(process ${openHiTLS_SRC}/testcode/framework/process/process.c)
set_target_properties(process PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${openHiTLS_SRC}/testcode/output"
)

target_include_directories(process PRIVATE
    ${openHiTLS_SRC}/testcode/framework/tls/resource/include
    ${openHiTLS_SRC}/testcode/framework/tls/base/include
    ${openHiTLS_SRC}/testcode/framework/tls/process/include
    ${openHiTLS_SRC}/testcode/framework/tls/include
    ${openHiTLS_SRC}/testcode/framework/tls/transfer/include
    ${openHiTLS_SRC}/testcode/framework/tls/rpc/include
    ${openHiTLS_SRC}/include/bsl
    ${openHiTLS_SRC}/include/crypto
    ${openHiTLS_SRC}/bsl/sal/include
    ${openHiTLS_SRC}/bsl/hash/include
    ${openHiTLS_SRC}/bsl/uio/src
    ${openHiTLS_SRC}/bsl/uio/include
    ${openHiTLS_SRC}/include/tls
    ${openHiTLS_SRC}/include/crypto
    ${openHiTLS_SRC}/include/pki
    ${openHiTLS_SRC}/tls/include
    ${openHiTLS_SRC}/config/macro_config
)

target_link_directories(process
    PRIVATE
    ${openHiTLS_SRC}/build
    ${openHiTLS_SRC}/testcode/output/lib
)

set(PROCESS_LIBS tls_hlt tls_frame hitls_tls)

# tls_hlt references HITLS_X509_* symbols through its cert callbacks, so the
# PKI library must be linked whenever it was built, mirroring TEST_INTF in
# sdv/CMakeLists.txt; ENABLE_PKI only controls testcase suite generation.
set(HITLS_PKI_LIB_BASE "${openHiTLS_SRC}/build/libhitls_pki")
if(${BUILD_PKI} GREATER -1 AND
   (EXISTS "${HITLS_PKI_LIB_BASE}${CMAKE_SHARED_LIBRARY_SUFFIX}" OR
    EXISTS "${HITLS_PKI_LIB_BASE}${CMAKE_STATIC_LIBRARY_SUFFIX}"))
    list(APPEND PROCESS_LIBS hitls_pki)
endif()

list(APPEND PROCESS_LIBS hitls_crypto hitls_bsl pthread dl rec_wrapper)

target_link_libraries(process ${PROCESS_LIBS})
