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


include_guard(GLOBAL)

include(CheckTypeSize)
include(TestBigEndian)


if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(HITLS_BSL_SAL_LINUX     ON CACHE BOOL "")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin") 
    set(HITLS_BSL_SAL_DARWIN    ON CACHE BOOL "")
    set(HITLS_CRYPTO_AUXVAL     OFF CACHE BOOL "")
endif()

# Endianness(little/big)
if(NOT HITLS_PLATFORM_ENDIAN)
    # Auto-detect endianness if HITLS_PLATFORM_ENDIAN is not explicitly set
    test_big_endian(_IS_BIG_ENDIAN)
    if(_IS_BIG_ENDIAN)
        set(HITLS_PLATFORM_ENDIAN "big" CACHE STRING "Endianness of the target platform (e.g., 'little', 'big')" FORCE)
    else()
        set(HITLS_PLATFORM_ENDIAN "little" CACHE STRING "Endianness of the target platform (e.g., 'little', 'big')" FORCE)
    endif()
endif()
if(HITLS_PLATFORM_ENDIAN STREQUAL "big")
    set(HITLS_BIG_ENDIAN ON)
elseif(HITLS_PLATFORM_ENDIAN STREQUAL "little")
    set(HITLS_BIG_ENDIAN OFF)
elseif(HITLS_PLATFORM_ENDIAN)
    message(FATAL_ERROR "Unsupported HITLS_PLATFORM_ENDIAN: ${HITLS_PLATFORM_ENDIAN}. "
            "Supported values are: 'little', 'big'.")
endif()

# Bits (32/64)
if(NOT HITLS_PLATFORM_BITS)
    # Auto-detect bits if HITLS_PLATFORM_BITS is not explicitly set
    check_type_size("void*" _SIZEOF_VOID_P)
    if(_SIZEOF_VOID_P EQUAL 8)
        set(HITLS_PLATFORM_BITS "64" CACHE STRING "Bitness of the target platform" FORCE)
    else()
        set(HITLS_PLATFORM_BITS "32" CACHE STRING "Bitness of the target platform" FORCE)
    endif()
endif()
if(HITLS_PLATFORM_BITS STREQUAL "64")
    set(HITLS_SIXTY_FOUR_BITS ON)
    set(HITLS_THIRTY_TWO_BITS OFF)
elseif(HITLS_PLATFORM_BITS STREQUAL "32")
    set(HITLS_SIXTY_FOUR_BITS OFF)
    set(HITLS_THIRTY_TWO_BITS ON)
else()
    message(FATAL_ERROR "Unsupported HITLS_PLATFORM_BITS: ${HITLS_PLATFORM_BITS}. "
            "Supported values are: '32', '64'.")
endif()

# ASM support
if(HITLS_ASM_X8664_AVX512)
    message(STATUS "HITLS_ASM_X8664 is auto enabled by HITLS_ASM_X8664_AVX512")
    set(HITLS_ASM_X8664 ON CACHE BOOL "Enable x86_64 assembly optimizations" FORCE)
endif()
if(HITLS_ASM)
    # Auto-detect architecture if no specific ASM arch flag is explicitly enabled
    if(NOT HITLS_ASM_X8664 AND NOT HITLS_ASM_ARMV8 AND NOT HITLS_ASM_ARMV7)
        string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _hitls_proc)
        if(_hitls_proc MATCHES "x86_64|amd64")
            set(HITLS_ASM_X8664 ON CACHE BOOL "Enable x86_64 assembly optimizations" FORCE)
            message(STATUS "ASM auto-detected architecture: x86_64")
        elseif(_hitls_proc MATCHES "aarch64|arm64")
            set(HITLS_ASM_ARMV8 ON CACHE BOOL "Enable ARMv8 assembly optimizations" FORCE)
            message(STATUS "ASM auto-detected architecture: ARMv8 (aarch64)")
        elseif(_hitls_proc MATCHES "armv7|armv7l|arm")
            set(HITLS_ASM_ARMV7 ON CACHE BOOL "Enable ARMv7 assembly optimizations" FORCE)
            message(STATUS "ASM auto-detected architecture: ARMv7")
        else()
            message(FATAL_ERROR 
                "HITLS_ASM is ON but no supported ASM architecture detected for processor: ${CMAKE_SYSTEM_PROCESSOR}. "
                "You can disable ASM with HITLS_ASM=OFF, or explicitly set the architecture with "
                "HITLS_ASM_X8664_AVX512/HITLS_ASM_X8664/HITLS_ASM_ARMV8/HITLS_ASM_ARMV7"
            )
        endif()
        unset(_hitls_proc)
    endif()
else()
    if(HITLS_ASM_X8664 OR HITLS_ASM_ARMV8 OR HITLS_ASM_ARMV7)
        set(HITLS_ASM ON CACHE BOOL "Enable assembly optimizations" FORCE)
    endif()
endif()

if(HITLS_ASM)
    # Check for conflicting ASM architecture settings
    set(_asm_arch_count 0)
    if(HITLS_ASM_X8664)
        math(EXPR _asm_arch_count "${_asm_arch_count} + 1")
    endif()
    if(HITLS_ASM_ARMV8)
        math(EXPR _asm_arch_count "${_asm_arch_count} + 1")
    endif()
    if(HITLS_ASM_ARMV7)
        math(EXPR _asm_arch_count "${_asm_arch_count} + 1")
    endif()

    if(_asm_arch_count GREATER 1)
        message(FATAL_ERROR "Cannot enable more than one ASM architecture at the same time. "
            "Please set only one of: HITLS_ASM_X8664/HITLS_ASM_X8664_AVX512, HITLS_ASM_ARMV8, HITLS_ASM_ARMV7")
    endif()
endif()

# Print platform configuration
message(STATUS "")
message(STATUS "========= Platform information =========")
message(STATUS "  Endianness:   ${HITLS_PLATFORM_ENDIAN}")
message(STATUS "  Bitness:      ${HITLS_PLATFORM_BITS}")
if(HITLS_ASM_X8664)
    message(STATUS "  ASM:          x86_64")  
elseif(HITLS_ASM_ARMV8)
    message(STATUS "  ASM:          armv8")
elseif(HITLS_ASM_ARMV7)
    message(STATUS "  ASM:          armv7")
else()
    message(STATUS "  ASM:          none")
endif()
message(STATUS "========================================")
message(STATUS "")
