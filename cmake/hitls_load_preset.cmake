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

# Save user -D flags before preset loading (to restore after)
get_cmake_property(_all_cache_vars CACHE_VARIABLES)

# If HITLS_BUILD_PROFILE is not set, check if any HITLS_* options have been set by the user.
# If any HITLS_* option is set, we consider that a preset has been loaded 
#    (either via -C or external configuration), and we will not load the default profile.
if(NOT HITLS_BUILD_PROFILE)
    foreach(_var ${_all_cache_vars})
        if(_var MATCHES "^HITLS_(CRYPTO|BSL|TLS|PKI|AUTH)" AND NOT _var MATCHES "_OBJECTS$")
            if(DEFINED ${_var} AND ${_var})
                set(HITLS_BUILD_PROFILE "none" CACHE STRING "Build profile" FORCE)
                set(HITLS_PRESET_LOADED ON CACHE BOOL "" FORCE)
            endif()
        endif()
    endforeach()
endif()
 
# Check if a preset has already been loaded (e.g., via -C option)
# If HITLS_PRESET_LOADED is already set by a preset file (via -C), skip default profile loading
if(NOT HITLS_PRESET_LOADED)
    # No preset has been loaded yet, use the default build profile
    set(HITLS_BUILD_PROFILE "full" CACHE STRING "Build profile")
    set(HITLS_PRESET_LOADED ON CACHE BOOL "" FORCE)

    set(_user_overrides "")
    foreach(_var ${_all_cache_vars})
        if("${_var}" MATCHES "^HITLS_" AND NOT "${_var}" STREQUAL "HITLS_BUILD_PROFILE" AND NOT "${_var}" STREQUAL "HITLS_PRESET_LOADED")
            list(APPEND _user_overrides "${_var}")
            set(_user_${_var}_value "${${_var}}")
            set(_user_${_var}_type "")
            get_property(_user_${_var}_type CACHE ${_var} PROPERTY TYPE)
        endif()
    endforeach()

    set(_profile_file "${CMAKE_CURRENT_LIST_DIR}/presets/${HITLS_BUILD_PROFILE}.cmake")
    if(EXISTS "${_profile_file}")
        message(STATUS "Loading default build profile: ${HITLS_BUILD_PROFILE}")
        include("${_profile_file}")
    else()
        message(FATAL_ERROR "Unknown build profile: ${HITLS_BUILD_PROFILE}\n"
            "Available profiles: full, fips, minimal, standard, crypto-only, tls-only, embedded")
    endif()

    # Restore user -D flags (priority over preset)
    foreach(_var ${_user_overrides})
        if(DEFINED _user_${_var}_value)
            set(${_var} "${_user_${_var}_value}" CACHE ${_user_${_var}_type} "" FORCE)
        endif()
    endforeach()
else()
    message(STATUS "Preset already loaded via -C or external configuration, skipping default profile loading")
endif()

# Not allow building the hitls executable when all code is bundled into a single library,
# since it doesn't make sense to build an executable in that case
if(HITLS_BUNDLE_LIB AND HITLS_BUILD_EXE)
    message(FATAL_ERROR "HITLS_BUILD_EXE=ON is not supported when HITLS_BUNDLE_LIB=ON"
    "(building an executable doesn't make sense when all code is bundled into a single library)")
endif()

if(DEFINED HITLS_BUILD_STATIC AND DEFINED HITLS_BUILD_SHARED)
    if(NOT HITLS_BUILD_STATIC AND NOT HITLS_BUILD_SHARED)
        message(FATAL_ERROR "At least one of HITLS_BUILD_STATIC or HITLS_BUILD_SHARED must be enabled")
    endif()
endif()

set(_check_Whitelist "HITLS_PRESET_LOADED")
macro(hitls_check_undefined_options)
    file(READ "${CMAKE_CURRENT_LIST_DIR}/hitls_options.cmake" _opts_file)

    set(_known_opts ${_check_Whitelist})
    # Collect names declared with: option(HITLS_xxx ...)
    string(REGEX MATCHALL "option\\(HITLS_[A-Z0-9_]+" _matches "${_opts_file}")
    foreach(_m ${_matches})
        string(REGEX REPLACE "^option\\(" "" _name "${_m}")
        list(APPEND _known_opts "${_name}")
    endforeach()
    # Collect names declared with: set(HITLS_xxx ... CACHE ...)
    string(REGEX MATCHALL "set\\(HITLS_[A-Z0-9_]+" _matches "${_opts_file}")
    foreach(_m ${_matches})
        string(REGEX REPLACE "^set\\(" "" _name "${_m}")
        list(APPEND _known_opts "${_name}")
    endforeach()

    get_cmake_property(_all_vars CACHE_VARIABLES)
    set(_uninit_vars "")
    foreach(_var ${_all_vars})
        if(NOT _var MATCHES "^HITLS_")
            continue()
        endif()
        get_property(_type CACHE ${_var} PROPERTY TYPE)
        if(NOT "${_var}" IN_LIST _known_opts)
            list(APPEND _uninit_vars "${_var}")
        endif()
    endforeach()
    if(_uninit_vars)
        set(_hitls_err_lines
            " ================================================================================="
            " HiTLS Configuration Error(Unrecognized Options): "
            " ---------------------------------------------------------------------------------"
            " The following HITLS_* options are not recognized by HiTLS:"
        )
        foreach(_uvar ${_uninit_vars})
            list(APPEND _hitls_err_lines " * ${_uvar}")
        endforeach()
        list(APPEND _hitls_err_lines
            " ---------------------------------------------------------------------------------"
            " Please check the option name(s) and re-run cmake."
        )
        list(JOIN _hitls_err_lines "\n" _hitls_err_msg)
        message(FATAL_ERROR "${_hitls_err_msg}")
    endif()
endmacro()

# Check for any undefined options that were not expected.
hitls_check_undefined_options()