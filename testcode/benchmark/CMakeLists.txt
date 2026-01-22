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
file(GLOB BENCHS "*_bench.c")

add_compile_options(-g)
add_executable(openhitls_benchmark benchmark.c ${BENCHS})


# target_link_options(openhitls_benchmark PRIVATE -fsanitize=address)
target_link_directories(openhitls_benchmark PRIVATE ${OPENHITLS_ROOT}/build
                                                    ${OPENHITLS_ROOT}/platform/Secure_C/lib)
target_include_directories(openhitls_benchmark PRIVATE ${OPENHITLS_ROOT}/include/crypto
                                                       ${OPENHITLS_ROOT}/include/bsl
                                                       ${OPENHITLS_ROOT}/platform/Secure_C/include)
target_link_libraries(openhitls_benchmark PRIVATE hitls_crypto hitls_bsl boundscheck)