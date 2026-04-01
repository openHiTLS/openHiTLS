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

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Default compile options for HiTLS.
set(_hitls_compile_options_list
    # CC_OVERALL_FLAGS
    -pipe
    # CC_WARN_FLAGS
    -Werror -Wextra -Wcast-qual -Wall -Wfloat-equal -Wshadow -Wformat=2
    # CC_LANGUAGE_FLAGS
    -fsigned-char
    # CC_CDG_FLAGS
    -fno-common
    # CC_OPT_FLAGS
    -fno-strict-aliasing -fno-omit-frame-pointer
    # CC_SEC_FLAGS
    -fstack-protector-strong
)
# Default link flags for HiTLS
set(_hitls_shared_link_flags_list "")
set(_hitls_exe_link_flags_list "")

if(CMAKE_BUILD_TYPE)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        # Add `-D_FORTIFY_SOURCE=2` if the build type is not Debug
        list(INSERT _hitls_compile_options_list 0 "-D_FORTIFY_SOURCE=2")
    endif()
else()
    # If `CMAKE_BUILD_TYPE` is unset, CMake does not apply any optimization flags by default,
    # so we add -O2 as a safe fallback. We also add -D_FORTIFY_SOURCE=2 as a safe default for non-Debug builds.
    list(INSERT _hitls_compile_options_list 0 "-D_FORTIFY_SOURCE=2;-O2")
endif()

# gcc specific options
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    list(APPEND _hitls_compile_options_list
        # CC_WARN_FLAGS
        -Wdate-time -Wno-stringop-overread
        # CC_SEC_FLAGS
        --param=ssp-buffer-size=4
    )
# clang/apple-clang specific options
elseif(CMAKE_C_COMPILER_ID MATCHES "^(Clang|AppleClang)$")
    list(APPEND _hitls_compile_options_list
        # CC_SEC_FLAGS
        -Wno-unused-command-line-argument
    )
endif()

# Linker flags based on detected linker
set(_hitls_public_link_flags_list "")

execute_process(
    COMMAND ${CMAKE_LINKER} --version
    OUTPUT_VARIABLE _hitls_linker_version
    ERROR_VARIABLE  _hitls_linker_version
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(_hitls_linker_version MATCHES "GNU gold|GNU ld|GNU Binutils")
    list(APPEND _hitls_public_link_flags_list
        -Wl,-z,noexecstack
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,--build-id=none
    )
    if(_hitls_linker_version MATCHES "GNU gold")
        list(APPEND _hitls_public_link_flags_list
            -Wl,--threads
            -Wl,--thread-count=4
        )
    endif()
elseif(_hitls_linker_version MATCHES "ld64" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND _hitls_public_link_flags_list -Wl,-dead_strip)
elseif(_hitls_linker_version MATCHES "LLD")
    list(APPEND _hitls_public_link_flags_list
        -Wl,-z,noexecstack
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,--build-id=none
        -Wl,--as-needed
    )
endif()

list(APPEND _hitls_shared_link_flags_list ${_hitls_public_link_flags_list})
list(APPEND _hitls_exe_link_flags_list ${_hitls_public_link_flags_list})

# User-overridable CACHE variables.
# Override via cmake -DHITLS_COMPILE_OPTIONS="flag1;flag2" (semicolons as CMake list separators).
# CMAKE_C_FLAGS / CMAKE_SHARED_LINKER_FLAGS / CMAKE_EXE_LINKER_FLAGS are NOT modified,
# so user-supplied values for those variables are fully preserved.
set(HITLS_COMPILE_OPTIONS "${_hitls_compile_options_list}" CACHE STRING
    "Compile options applied to all HiTLS targets (via add_compile_options).")
set(HITLS_SHARED_LINKER_FLAGS "${_hitls_shared_link_flags_list}" CACHE STRING
    "Linker flags applied only to HiTLS shared library targets via target_link_options.")
set(HITLS_EXE_LINKER_FLAGS "${_hitls_exe_link_flags_list}" CACHE STRING
    "Linker flags applied only to HiTLS executable targets via target_link_options.")

# Allow users to add or remove compile options via cache variables.
set(_HITLS_COMPILE_OPTIONS_DEL "" CACHE STRING "Compile options to remove from defaults (optional)")
if(_HITLS_COMPILE_OPTIONS_DEL)
    separate_arguments(_hitls_compile_options_del_list UNIX_COMMAND "${_HITLS_COMPILE_OPTIONS_DEL}")
    list(REMOVE_ITEM HITLS_COMPILE_OPTIONS ${_hitls_compile_options_del_list})
    set(HITLS_COMPILE_OPTIONS "${HITLS_COMPILE_OPTIONS}" CACHE STRING
        "Compile options applied to all HiTLS targets (via add_compile_options).")
endif()

# Apply global compile options
add_compile_options(${HITLS_COMPILE_OPTIONS})

message(STATUS "====== HiTLS Build Options ======")
message(STATUS "CMAKE_POSITION_INDEPENDENT_CODE : ${CMAKE_POSITION_INDEPENDENT_CODE}")
message(STATUS "HITLS_COMPILE_OPTIONS     : ${HITLS_COMPILE_OPTIONS}")
message(STATUS "HITLS_SHARED_LINKER_FLAGS : ${HITLS_SHARED_LINKER_FLAGS}")
message(STATUS "HITLS_EXE_LINKER_FLAGS    : ${HITLS_EXE_LINKER_FLAGS}")

message(STATUS "CMAKE_C_FLAGS             : ${CMAKE_C_FLAGS}")
message(STATUS "CMAKE_ASM_FLAGS           : ${CMAKE_ASM_FLAGS}")
message(STATUS "CMAKE_SHARED_LINKER_FLAGS : ${CMAKE_SHARED_LINKER_FLAGS}")
message(STATUS "CMAKE_EXE_LINKER_FLAGS    : ${CMAKE_EXE_LINKER_FLAGS}")

# Optimization level comes from CMAKE_C_FLAGS_<CONFIG>
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "CMAKE_C_FLAGS_DEBUG       : ${CMAKE_C_FLAGS_DEBUG}")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "CMAKE_C_FLAGS_RELEASE     : ${CMAKE_C_FLAGS_RELEASE}")
elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    message(STATUS "CMAKE_C_FLAGS_RELWITHDEBINFO : ${CMAKE_C_FLAGS_RELWITHDEBINFO}")
elseif(CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    message(STATUS "CMAKE_C_FLAGS_MINSIZEREL  : ${CMAKE_C_FLAGS_MINSIZEREL}")
endif()
message(STATUS "=================================")
