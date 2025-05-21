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

project(openHiTLS)

set(HiTLS_SOURCE_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})

if(DEFINED BUILD_DIR)
    set(HiTLS_BUILD_DIR ${BUILD_DIR})
else()
    set(HiTLS_BUILD_DIR ${HiTLS_SOURCE_ROOT_DIR}/build)
endif()

execute_process(COMMAND python3 ${HiTLS_SOURCE_ROOT_DIR}/configure.py -m --build_dir ${HiTLS_BUILD_DIR})

include(${HiTLS_BUILD_DIR}/modules.cmake)

add_subdirectory(auth)

install(DIRECTORY ${HiTLS_SOURCE_ROOT_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include/hitls/
        FILES_MATCHING PATTERN "*.h")
