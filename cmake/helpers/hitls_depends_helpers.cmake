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


# hitls_define_dependency
# -------------------------
# Description:
#   Register dependency metadata for a build feature (option). This function records
#   three kinds of relationships that are later consumed by the dependency-resolution
#   macros at configure time:
#     DEPS       – other features that must be enabled when this feature is ON.
#     DEPS_CHECK – features whose presence is checked (warning only, not auto-enabled).
#     CHILDREN   – sub-features that are auto-enabled when this feature is ON.
#   All data is stored in CACHE INTERNAL variables and has no immediate side effect.
#
# Parameters:
#   option       (required) Feature name, e.g. HITLS_CRYPTO_SHA2.
#   DEPS         (optional) List of features that must be enabled together with <option>.
#   DEPS_CHECK   (optional) List of features to check; a warning is printed if missing.
#   CHILDREN     (optional) List of sub-features auto-enabled when <option> is ON.
#
# Example:
#   hitls_define_dependency(HITLS_CRYPTO_SHA2
#       DEPS HITLS_CRYPTO_MD
#       CHILDREN HITLS_CRYPTO_SHA256 HITLS_CRYPTO_SHA512
#   )
function(hitls_define_dependency option)
    cmake_parse_arguments(ARG "" "" "DEPS;DEPS_CHECK;CHILDREN" ${ARGN})

    # Store dependencies in a cache variable
    set(_G_HITLS_DEPS_${option} "${ARG_DEPS}" CACHE INTERNAL "Dependencies for ${option}")
    
    # Store dependencies check in a cache variable
    set(_G_HITLS_DEPS_CHECK_${option} "${ARG_DEPS_CHECK}" CACHE INTERNAL "Dependencies check for ${option}")

    # Store children in a cache variable
    set(_G_HITLS_CHILDREN_${option} "${ARG_CHILDREN}" CACHE INTERNAL "Children of ${option}")
endfunction()

# hitls_resolve_option_children
# -------------------------
# Description:
#   Recursively auto-enable all CHILDREN registered for <option>.
macro(hitls_resolve_option_children option)
    set(_children "${_G_HITLS_CHILDREN_${option}}")
    list(LENGTH _children _children_length)
    foreach(_child ${_children})
        # Check whether the user has explicitly set this child in the cache.
        # If it is already in the cache with value OFF, respect the user's choice
        # and do not auto-enable it.
        get_property(_child_is_cached CACHE ${_child} PROPERTY TYPE SET)
        if(_child_is_cached AND NOT ${_child})
            message(STATUS "  Skipping ${_child} (explicitly set to OFF by user, child of ${option})")
        elseif(NOT ${_child})
            # Not in cache – auto-enable as a default child feature.
            set(${_child} ON CACHE BOOL "")
            message(STATUS "  Auto-enabled ${_child} (child of ${option})")

            # Recursively resolve children of the child
            hitls_resolve_option_children(${_child})
        endif()
    endforeach()
    
    if(_children_length GREATER 0)
        unset(${option} CACHE)
    endif()
endmacro()

# hitls_feature_children_derive
# -------------------------
# Description:
#   Iterate over every currently enabled HITLS_CRYPTO/BSL/TLS/PKI/AUTH cache variable
#   and call hitls_resolve_option_children() for each one, driving the full
#   parent→child hierarchy in a single pass.
macro(hitls_feature_children_derive)
    message(STATUS "")
    message(STATUS "=== Propagating Features to Children ===")

    # Collect all currently enabled HITLS_* options
    set(_all_options "")

    get_cmake_property(_cache_vars CACHE_VARIABLES)
    foreach(_var ${_cache_vars})
        if(_var MATCHES "^HITLS_(CRYPTO|BSL|TLS|PKI|AUTH)")
            if(DEFINED ${_var} AND ${_var})
                list(APPEND _all_options ${_var})
            endif()
        endif()
    endforeach()

    # Drive children for each enabled option
    foreach(_opt ${_all_options})
        hitls_resolve_option_children(${_opt})
    endforeach()

    message(STATUS "=== Children Propagated ===")
    message(STATUS "")
endmacro()

# hitls_resolve_option_dependencies
# -------------------------
# Description:
#   Recursively enable all DEPS registered for <option> in the current variable
#   scope (not persisted to cache). Dependencies are re-derived on every cmake
#   run from the user-set options, so transient enablement is intentional.
macro(hitls_resolve_option_dependencies option)
    if(${option})
        # Get dependencies for this option
        set(_deps "${_G_HITLS_DEPS_${option}}")

        foreach(_dep ${_deps})
            if(NOT ${_dep})
                # Enable in current scope only (not persisted to cache).
                # Dependencies are re-derived from user-set options on every cmake run.
                set(${_dep} ON)
                message(STATUS "  Auto-enabled ${_dep} (required by ${option})")

                # Recursively resolve dependencies of the dependency
                hitls_resolve_option_dependencies(${_dep})
            endif()
        endforeach()
    endif()
endmacro()

# hitls_feature_dependencies_derive
# -------------------------
# Description:
#   Iterate over every currently enabled HITLS_CRYPTO/BSL/TLS/PKI/AUTH cache variable
#   and call hitls_resolve_option_dependencies() for each one, ensuring the full
#   DEPS chain is activated in the current scope.
macro(hitls_feature_dependencies_derive)
    message(STATUS "")
    message(STATUS "=== Resolving Feature Dependencies ===")

    # Collect all options that might need dependency resolution
    set(_all_options "")

    # Get all HITLS_* cache variables
    get_cmake_property(_cache_vars CACHE_VARIABLES)
    foreach(_var ${_cache_vars})
        if(_var MATCHES "^HITLS_(CRYPTO|BSL|TLS|PKI|AUTH)")
            if(DEFINED ${_var} AND ${_var})
                list(APPEND _all_options ${_var})
            endif()
        endif()
    endforeach()

    # Resolve dependencies for each enabled option
    foreach(_opt ${_all_options})
        hitls_resolve_option_dependencies(${_opt})
    endforeach()

    message(STATUS "=== Dependencies Resolved ===")
    message(STATUS "")
endmacro()

macro(hitls_feature_local_enable option)
    if(NOT DEFINED ${option} OR NOT ${option})
        set(${option} ON)
        hitls_resolve_option_dependencies(${option})
    endif()
endmacro()
