# ---------------------------------------------------------------------------------------------
#  This file is part of the openHiTLS project.
#  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
#  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
#  for license information.
# ---------------------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(openHiTLS_PROVIDER_TEST)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -shared")

# Set output directory
set(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

# Define source file list
set(SOURCE_FILES
    provider_load_test1.c
    provider_load_test2.c
    provider_load_test_no_init.c
    provider_load_test_no_fullfunc.c
)

# Create a shared library target for each source file
foreach(SOURCE_FILE ${SOURCE_FILES})
    # Get the file name (without extension)
    get_filename_component(FILE_NAME ${SOURCE_FILE} NAME_WE)
    
    # Create shared library target
    add_library(lib${FILE_NAME} SHARED ${SOURCE_FILE})
    
    # Set output name
    set_target_properties(lib${FILE_NAME} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "lib${FILE_NAME}"
    )
    
    # Link necessary libraries
    # target_link_libraries(lib${FILE_NAME}
    #     -lhitls_bsl
    #     -lboundscheck
    #     -lpthread
    #     -ldl
    # )
    
    # Set include directories
    target_include_directories(lib${FILE_NAME}
        PRIVATE
            ${CMAKE_SOURCE_DIR}/../../include
            ${CMAKE_SOURCE_DIR}/../../platform/Secure_C/include
    )
endforeach()
