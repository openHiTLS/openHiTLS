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

project(openHiTLS_PROVIDER_TEST)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -shared")

# Set output directory
set(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

# Define a function to recursively include directories
function(include_directories_recursive dir)
    include_directories(${dir})
    file(GLOB children RELATIVE ${dir} ${dir}/*)
    foreach(child ${children})
        if(IS_DIRECTORY ${dir}/${child})
            include_directories_recursive(${dir}/${child})
        endif()
    endforeach()
endfunction()

# Call the function to recursively include the specified directory
include_directories_recursive(${CMAKE_SOURCE_DIR}/../../../include)

# Define four file areas
set(SOURCE_FILES_PATH1_SO
    provider_load_test1.c
)

set(SOURCE_FILES_PATH1_LIBSO
    provider_get_cap_test1.c
    provider_load_test2.c
    provider_load_test_no_fullfunc.c
    provider_load_test_no_init.c
    provider_load_test1.c
    provider_load_test_providerNoInit.c
    provider_load_test_providerNoFree.c
)

set(SOURCE_FILES_PATH2_SO

)

set(SOURCE_FILES_PATH2_LIBSO
    provider_load_test1.c
)

# Create shared library targets for files with %s.so format in path1 directory
foreach(SOURCE_FILE ${SOURCE_FILES_PATH1_SO})
    get_filename_component(FILE_NAME ${SOURCE_FILE} NAME_WE)
    if(NOT TARGET ${FILE_NAME}_path1)
        add_library(${FILE_NAME}_path1 SHARED ${SOURCE_FILE})
        set_target_properties(${FILE_NAME}_path1 PROPERTIES
            PREFIX ""
            OUTPUT_NAME "${FILE_NAME}"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/path1"
        )
    endif()
endforeach()

# Create shared library targets for files with lib%s.so format in path1 directory
foreach(SOURCE_FILE ${SOURCE_FILES_PATH1_LIBSO})
    get_filename_component(FILE_NAME ${SOURCE_FILE} NAME_WE)
    if(NOT TARGET lib${FILE_NAME}_path1)
        add_library(lib${FILE_NAME}_path1 SHARED ${SOURCE_FILE})
        target_compile_options(lib${FILE_NAME}_path1 PRIVATE -g -O0)
        set_target_properties(lib${FILE_NAME}_path1 PROPERTIES
            PREFIX ""
            OUTPUT_NAME "lib${FILE_NAME}"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/path1"
        )
    endif()
endforeach()

# Create shared library targets for files with %s.so format in path2 directory
foreach(SOURCE_FILE ${SOURCE_FILES_PATH2_SO})
    get_filename_component(FILE_NAME ${SOURCE_FILE} NAME_WE)
    if(NOT TARGET ${FILE_NAME}_path2)
        add_library(${FILE_NAME}_path2 SHARED ${SOURCE_FILE})
        target_compile_options(lib${FILE_NAME}_path2 PRIVATE -g -O0)
        set_target_properties(${FILE_NAME}_path2 PROPERTIES
            PREFIX ""
            OUTPUT_NAME "${FILE_NAME}"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/path2"
        )
    endif()
endforeach()

# Create shared library targets for files with lib%s.so format in path2 directory
foreach(SOURCE_FILE ${SOURCE_FILES_PATH2_LIBSO})
    get_filename_component(FILE_NAME ${SOURCE_FILE} NAME_WE)
    if(NOT TARGET lib${FILE_NAME}_path2)
        add_library(lib${FILE_NAME}_path2 SHARED ${SOURCE_FILE})
        set_target_properties(lib${FILE_NAME}_path2 PROPERTIES
            PREFIX ""
            OUTPUT_NAME "lib${FILE_NAME}"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/path2"
        )
    endif()
endforeach()
