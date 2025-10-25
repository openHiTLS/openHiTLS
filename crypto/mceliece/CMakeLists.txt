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

cmake_minimum_required(VERSION 3.10)
project(pqcp_provider C)

# 新增：自定义库路径变量
set(PQCP_LIB_DIR "" CACHE PATH "Custom library search path")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)

# 调试选项设置
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -march=native")

# ASAN配置
if(ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

# Find OpenHiTLS
# find_package(OpenHiTLS REQUIRED)

# Set source files
set(PROVIDER_SOURCES
    src/provider/pqcp_provider.c
    src/provider/pqcp_kem.c
    src/scloudplus/src/scloudplus.c
    src/scloudplus/src/scloudplus_util.c
    src/frodokem/src/frodo_core_ref.c
    src/frodokem/src/frodo_noise.c
    src/frodokem/src/frodo_params.c
    src/frodokem/src/frodo_util.c
    src/frodokem/src/frodokem_api.c
    src/frodokem/src/frodokem.c
    src/frodokem/src/frodokem_pke.c
    src/classic_mceliece/src/mceliece_params.c
    src/classic_mceliece/src/mceliece_api.c
    src/classic_mceliece/src/mceliece_shake.c
    src/classic_mceliece/src/mceliece_vector.c
    src/classic_mceliece/src/mceliece_rng.c
    src/classic_mceliece/src/mceliece_poly.c
    src/classic_mceliece/src/mceliece_matrix_ops.c
    src/classic_mceliece/src/mceliece_keygen.c
    src/classic_mceliece/src/mceliece_kem.c
    src/classic_mceliece/src/mceliece_gf.c
    src/classic_mceliece/src/mceliece_genpoly.c
    src/classic_mceliece/src/mceliece_encode.c
    src/classic_mceliece/src/mceliece_decode.c
    src/classic_mceliece/src/mceliece_controlbits.c
)

# 添加链接目录
if(PQCP_LIB_DIR)
    link_directories(${PQCP_LIB_DIR})
endif()

# Create shared library
add_library(pqcp_provider SHARED ${PROVIDER_SOURCES})

target_include_directories(pqcp_provider
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/provider
        ${CMAKE_CURRENT_SOURCE_DIR}/src/scloudplus/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/classic_mceliece/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/frodokem/include
        ${OPENHITLS_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/include/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/include/bsl
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/platform/Secure_C/include
)

# 新增：目标链接目录
target_link_directories(pqcp_provider PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/build
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/platform/Secure_C/lib
)

message(STATUS "hitls_crypto: ${HITLS_CRYPTO_LIB}")
message(STATUS "hitls_bsl: ${HITLS_BSL_LIB}")
message(STATUS "boundscheck: ${SECUREC_LIB}")

target_link_libraries(pqcp_provider
    hitls_bsl
    hitls_crypto
    boundscheck
)

# 在文件末尾添加以下内容
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove
        *.log
        *.tmp
        *.bak
    COMMENT "Cleaning all build artifacts and temporary files"
)

# 可选：添加文档说明
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES
    "*.log"
    "*.tmp"
    "*.bak"
)
