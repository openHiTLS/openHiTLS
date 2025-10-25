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
project(pqcp_test C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(Threads REQUIRED)

# 设置编译选项
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3 -O0 -Wall -Wextra")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra")
endif()

# 启用AddressSanitizer（如果需要）
if(ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

# 启用代码覆盖率分析（如果需要）
if(ENABLE_GCOV)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgcov --coverage")
endif()

# 设置依赖库搜索路径
set(PQCP_DEPENDENCY_DIRS
        ${CMAKE_SOURCE_DIR}/../platform/openhitls/build
        ${CMAKE_SOURCE_DIR}/../platform/openhitls/platform/Secure_C/lib
        ${CMAKE_SOURCE_DIR}/../build
    CACHE STRING "PQCP dependency library paths")

# 查找依赖库
find_library(HITLS_CRYPTO_LIB hitls_crypto 
    PATHS ${PQCP_DEPENDENCY_DIRS}
    NO_DEFAULT_PATH)
find_library(HITLS_BSL_LIB hitls_bsl 
    PATHS ${PQCP_DEPENDENCY_DIRS}
    NO_DEFAULT_PATH)
find_library(SECUREC_LIB boundscheck
    PATHS ${PQCP_DEPENDENCY_DIRS}
    NO_DEFAULT_PATH)
find_library(PQCP_PROVIDER_LIB pqcp_provider
    PATHS ${PQCP_DEPENDENCY_DIRS}
    NO_DEFAULT_PATH)

# 验证库是否存在
foreach(LIB IN ITEMS 
    HITLS_CRYPTO_LIB 
    HITLS_BSL_LIB 
    SECUREC_LIB
    PQCP_PROVIDER_LIB)
    if(NOT ${LIB})
        message(FATAL_ERROR "Required library ${LIB} not found in: ${PQCP_DEPENDENCY_DIRS}")
    endif()
endforeach()

# 包含目录
include_directories(
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../src/scloudplus/include
    ${CMAKE_SOURCE_DIR}/../src/scloudplus/src
    ${CMAKE_SOURCE_DIR}/../src/classic_mceliece/include
    ${CMAKE_SOURCE_DIR}/../src/classic_mceliece/src
    ${CMAKE_SOURCE_DIR}/../src/frodokem/include
    ${CMAKE_SOURCE_DIR}/../src/frodokem/src
    ${CMAKE_SOURCE_DIR}/../platform/openhitls/include/bsl
    ${CMAKE_SOURCE_DIR}/../platform/openhitls/include/crypto
    ${CMAKE_SOURCE_DIR}/../platform/openhitls/platform/Secure_C/include
)

# 添加公共测试框架源文件
set(COMMON_SOURCES
    common/pqcp_test.c
    common/pqcp_perf.c
    common/pqcp_fuzz.c
)

# 添加SDV测试源文件
file(GLOB_RECURSE SDV_SOURCES
    "sdv/*.c"
)

# 添加性能测试源文件
file(GLOB_RECURSE PERF_SOURCES
    "perf/*.c"
)

# 添加模糊测试源文件
file(GLOB_RECURSE FUZZ_SOURCES
    "fuzz/*.c"
)

# 添加示例源文件
file(GLOB_RECURSE DEMO_SOURCES
    "demo/*.c"
)

# 根据构建目标选择要构建的测试
if(NOT DEFINED BUILD_TARGETS OR BUILD_TARGETS STREQUAL "all")
    set(BUILD_SDV ON)
    set(BUILD_PERF ON)
    set(BUILD_FUZZ ON)
    set(BUILD_DEMO ON)
else()
    string(FIND "${BUILD_TARGETS}" "sdv" SDV_POS)
    if(NOT SDV_POS EQUAL -1)
        set(BUILD_SDV ON)
    endif()
    
    string(FIND "${BUILD_TARGETS}" "perf" PERF_POS)
    if(NOT PERF_POS EQUAL -1)
        set(BUILD_PERF ON)
    endif()
    
    string(FIND "${BUILD_TARGETS}" "fuzz" FUZZ_POS)
    if(NOT FUZZ_POS EQUAL -1)
        set(BUILD_FUZZ ON)
    endif()
    
    string(FIND "${BUILD_TARGETS}" "demo" DEMO_POS)
    if(NOT DEMO_POS EQUAL -1)
        set(BUILD_DEMO ON)
    endif()
endif()

# 构建SDV测试
if(BUILD_SDV)
    add_executable(pqcp_sdv_test ${COMMON_SOURCES} ${SDV_SOURCES} sdv/main.c)
    target_link_libraries(pqcp_sdv_test 
        ${PQCP_LIBRARY}
        ${HITLS_CRYPTO_LIB}
        ${HITLS_BSL_LIB}
        ${PQCP_PROVIDER_LIB}
        Threads::Threads
        ${SECUREC_LIB})
    install(TARGETS pqcp_sdv_test DESTINATION bin)
endif()

# 构建性能测试
if(BUILD_PERF)
    add_executable(pqcp_perf_test ${COMMON_SOURCES} ${PERF_SOURCES} perf/perf_test.c)
    target_link_libraries(pqcp_perf_test 
        ${PQCP_LIBRARY}
        ${HITLS_CRYPTO_LIB}
        ${HITLS_BSL_LIB}
        ${PQCP_PROVIDER_LIB}
        Threads::Threads
        ${SECUREC_LIB})
    install(TARGETS pqcp_perf_test DESTINATION bin)
endif()

# 构建模糊测试
if(BUILD_FUZZ)
    add_executable(pqcp_fuzz_test ${COMMON_SOURCES} ${FUZZ_SOURCES} fuzz/fuzz_test.c)
    target_link_libraries(pqcp_fuzz_test 
        ${PQCP_LIBRARY}
        ${HITLS_CRYPTO_LIB}
        ${HITLS_BSL_LIB}
        ${PQCP_PROVIDER_LIB}
        Threads::Threads
        ${SECUREC_LIB})
    install(TARGETS pqcp_fuzz_test DESTINATION bin)
endif()

# 构建示例
if(BUILD_DEMO)
    # 为每个示例创建可执行文件
    file(GLOB DEMO_FILES "demo/*.c")
    foreach(DEMO_FILE ${DEMO_FILES})
        get_filename_component(DEMO_NAME ${DEMO_FILE} NAME_WE)
        add_executable(${DEMO_NAME} ${DEMO_FILE} ${COMMON_SOURCES})
        target_link_libraries(${DEMO_NAME} 
            ${PQCP_LIBRARY}
            ${HITLS_CRYPTO_LIB}
            ${HITLS_BSL_LIB}
            ${PQCP_PROVIDER_LIB}
            Threads::Threads
            ${SECUREC_LIB})
        install(TARGETS ${DEMO_NAME} DESTINATION bin)
    endforeach()
endif()

# 安装脚本
install(PROGRAMS
    script/build.sh
    script/run_sdv.sh
    script/run_perf.sh
    script/run_fuzz.sh
    DESTINATION bin
)

# 创建测试输出目录
install(DIRECTORY DESTINATION output)
install(DIRECTORY DESTINATION output/sdv)
install(DIRECTORY DESTINATION output/perf)
install(DIRECTORY DESTINATION output/fuzz)

# target_link_libraries(pqcp_provider PRIVATE hitls_bsl)
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-as-needed") 