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

project(demo)

message(status "HITLS_ROOT: ${HITLS_ROOT}")
set(HITLS_ROOT ../..)
set(HITLS_INCLUDE ${HITLS_ROOT}/include/bsl
                  ${HITLS_ROOT}/include/crypto
                  ${HITLS_ROOT}/include/tls
                  ${HITLS_ROOT}/include/pki
                  ${HITLS_ROOT}/platform/Secure_C/include)

add_library(DEMO_INTF INTERFACE)
target_compile_options(DEMO_INTF INTERFACE -g)
target_link_directories(DEMO_INTF INTERFACE ${HITLS_ROOT}/build 
                                            ${HITLS_ROOT}/platform/Secure_C/lib/)
target_link_libraries(DEMO_INTF INTERFACE  hitls_tls hitls_x509 hitls_crypto hitls_bsl boundscheck)
target_include_directories(DEMO_INTF INTERFACE ${HITLS_INCLUDE})

set(TESTS client.c server.c drbg.c ecdh.c pbkdf2.c sm2enc.c sm2sign.c sm4cbc.c)
foreach(testcase ${TESTS})
    get_filename_component(testname ${testcase} NAME_WLE)
    add_executable(${testname} ${testcase})
    target_link_libraries(${testname} PRIVATE DEMO_INTF)
endforeach()
