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


set(_uio_sources "")

# UIO platform layer (base abstraction)
if(HITLS_BSL_UIO_PLT)
    list(APPEND _uio_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/uio_abstraction.c)
endif()

# Buffer UIO
if(HITLS_BSL_UIO_BUFFER)
    list(APPEND _uio_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/uio_buffer.c)
endif()

# SCTP UIO
if(HITLS_BSL_UIO_SCTP)
    list(APPEND _uio_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/uio_sctp.c)
endif()

# TCP UIO
if(HITLS_BSL_UIO_TCP)
    list(APPEND _uio_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/uio_tcp.c)
endif()

# UDP UIO
if(HITLS_BSL_UIO_UDP)
    list(APPEND _uio_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/uio_udp.c)
endif()

# File UIO
if(HITLS_BSL_UIO_FILE)
    list(APPEND _uio_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/uio_file.c)
endif()

# Memory UIO
if(HITLS_BSL_UIO_MEM)
    list(APPEND _uio_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/uio_mem.c)
endif()

if(NOT _uio_sources)
    message(WARNING "[BSL] No UIO sources enabled. The _hitls_bsl_uio target will not be created.")
    return()
endif()

add_library(_hitls_bsl_uio OBJECT ${_uio_sources})

target_link_libraries(_hitls_bsl_uio
    PUBLIC
        _hitls_bsl_common_include
)

target_include_directories(_hitls_bsl_uio
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/bsl/buffer/include
)

hitls_register_objects(BSL _hitls_bsl_uio)
