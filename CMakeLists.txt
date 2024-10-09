# ---------------------------------------------------------------------------------------------
#  This file is part of the openHiTLS project.
#  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
#  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
#  for license information.
# ---------------------------------------------------------------------------------------------
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
