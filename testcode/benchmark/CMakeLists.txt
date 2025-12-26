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

PROJECT(openHiTLS_BENCHMARK)

set(OPENHITLS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(BENCHS sm2_bench.c slh_dsa_bench.c ecdsa_bench.c md_bench.c cipher_bench.c mac_bench.c
           dh_bench.c ecdh_bench.c 25519_bench.c mldsa_bench.c mlkem_bench.c sm9_bench.c)

add_compile_options(-g)
# -z noexecstack: Mark the stack as non-executable (ELF security feature)
# Supported by: GNU ld (all versions), LLVM lld 7.0+
# Not needed on: macOS (ld64 defaults to non-executable stack), Windows (uses /NXCOMPAT)
if(UNIX AND NOT APPLE)
    add_link_options(-z noexecstack)
endif()
add_executable(openhitls_benchmark benchmark.c ${BENCHS})


# target_link_options(openhitls_benchmark PRIVATE -fsanitize=address)
target_link_directories(openhitls_benchmark PRIVATE ${OPENHITLS_ROOT}/build
                                                    ${OPENHITLS_ROOT}/platform/Secure_C/lib)
target_include_directories(openhitls_benchmark PRIVATE ${OPENHITLS_ROOT}/include/crypto
                                                       ${OPENHITLS_ROOT}/include/bsl
                                                       ${OPENHITLS_ROOT}/platform/Secure_C/include
                                                       ${OPENHITLS_ROOT}/bsl/include
                                                       ${OPENHITLS_ROOT}/crypto/include
                                                       ${OPENHITLS_ROOT}/config/macro_config)
target_link_libraries(openhitls_benchmark PRIVATE hitls_crypto hitls_bsl boundscheck)