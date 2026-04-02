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


set(_sal_sources "")

# Core SAL sources
list(APPEND _sal_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sal_ctrl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sal_atomic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sal_mem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sal_threadlock.c
)

# File
if(HITLS_BSL_SAL_FILE)
    list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/sal_file.c)
endif()

# Network
if(HITLS_BSL_SAL_NET)
    list(APPEND _sal_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/sal_net.c
    )
endif()

# Time
if(HITLS_BSL_SAL_TIME)
    list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/sal_time.c)
endif()

# String
if(HITLS_BSL_SAL_STR)
    list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/sal_string.c)
endif()

# Dynamic loading
if(HITLS_BSL_SAL_DL)
    list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/sal_dl.c)
endif()

# Ip Util
if(HITLS_BSL_SAL_IP)
    list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/sal_ip_util.c)
endif()

# Platform-specific implementations
if(HITLS_BSL_SAL_LINUX OR HITLS_BSL_SAL_DARWIN)
    # POSIX implementations for Unix/Linux/macOS
    list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/posix/posix_lock.c)
    if(HITLS_BSL_SAL_MEM)
        list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/posix/posix_mem.c)
    endif()
    if(HITLS_BSL_SAL_FILE)
        list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/posix/posix_file.c)
    endif()
    if(HITLS_BSL_SAL_NET)
        list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/posix/posix_net.c)
    endif()
    if(HITLS_BSL_SAL_TIME)
        list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/posix/posix_time.c)
    endif()
    if(HITLS_BSL_SAL_DL)
        list(APPEND _sal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/posix/posix_dl.c)
    endif()
endif()

# Create SAL target
add_library(_hitls_bsl_sal OBJECT ${_sal_sources})

target_link_libraries(_hitls_bsl_sal
    PUBLIC
        _hitls_bsl_common_include
)

target_include_directories(_hitls_bsl_sal
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)


hitls_register_objects(BSL _hitls_bsl_sal)
