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


if(HITLS_BUILD_GEN_INFO)
    set(_macros_file "${CMAKE_BINARY_DIR}/macros.txt")
    set(_source_file "${CMAKE_BINARY_DIR}/sources.txt")
    set(_include_file "${CMAKE_BINARY_DIR}/include_dirs.txt")
    file(WRITE "${_macros_file}" "")
    file(WRITE "${_source_file}" "")
    file(WRITE "${_include_file}" "")

    # Generate macros file with all enabled macros formatted as compiler flags
    foreach(_macro ${_HITLS_ALL_FEATURE_MACROS})
        file(APPEND "${_macros_file}" "-D${_macro}\n")
    endforeach()
    message(STATUS "Generated macro definitions file: ${_macros_file}")

    # Generate sources lists for each module
    function(hitls_generate_sources_list _object_targets module_name)
        set(_sources "")
        foreach(_target ${_object_targets})
            get_target_property(_target_sources ${_target} SOURCES)
            list(APPEND _sources ${_target_sources})
        endforeach()
        # Remove duplicates and write to output file
        list(REMOVE_DUPLICATES _sources)

        file(APPEND "${_source_file}" "# ${module_name}\n")
        foreach(_src ${_sources})
            file(RELATIVE_PATH _rel_src "${PROJECT_SOURCE_DIR}" "${_src}")
            file(APPEND "${_source_file}" "${_rel_src}\n")
        endforeach()
    endfunction()

    function(hitls_generate_include_dirs_list _object_targets module_name)
        set(_include_dirs "")
        foreach(_target ${_object_targets})
            get_target_property(_target_includes ${_target} INCLUDE_DIRECTORIES)
            list(APPEND _include_dirs ${_target_includes})
        endforeach()
        # Remove duplicates
        list(REMOVE_DUPLICATES _include_dirs)

        # Process generator expressions (e.g., $<BUILD_INTERFACE:/path/to/include>)
        set(_processed_dirs "")
        foreach(_dir ${_include_dirs})
            string(REGEX REPLACE "\\$<BUILD_INTERFACE:([^>]+)>" "\\1" _processed_dir "${_dir}")
            list(APPEND _processed_dirs "${_processed_dir}")
        endforeach()
        list(REMOVE_DUPLICATES _processed_dirs)

        file(APPEND "${_include_file}" "# ${module_name}\n")
        foreach(_inc ${_processed_dirs})
            file(RELATIVE_PATH _rel_inc "${PROJECT_SOURCE_DIR}" "${_inc}")
            file(APPEND "${_include_file}" "${_rel_inc}\n")
        endforeach()
    endfunction()

    if(HITLS_BSL)
        hitls_generate_sources_list("${_G_HITLS_BSL_OBJECTS}" "bsl")
        hitls_generate_include_dirs_list("${_G_HITLS_BSL_OBJECTS}" "bsl")
    endif()
    if(HITLS_CRYPTO)
        hitls_generate_sources_list("${_G_HITLS_CRYPTO_OBJECTS}" "crypto")
        hitls_generate_include_dirs_list("${_G_HITLS_CRYPTO_OBJECTS}" "crypto")
    endif()
    if(HITLS_PKI)
        hitls_generate_sources_list("${_G_HITLS_PKI_OBJECTS}" "pki")
        hitls_generate_include_dirs_list("${_G_HITLS_PKI_OBJECTS}" "pki")
    endif()
    if(HITLS_TLS)
        hitls_generate_sources_list("${_G_HITLS_TLS_OBJECTS}" "tls")
        hitls_generate_include_dirs_list("${_G_HITLS_TLS_OBJECTS}" "tls")
    endif()
    if(HITLS_AUTH)
        hitls_generate_sources_list("${_G_HITLS_AUTH_OBJECTS}" "auth")
        hitls_generate_include_dirs_list("${_G_HITLS_AUTH_OBJECTS}" "auth")
    endif()
    if(HITLS_BUILD_EXE)
        hitls_generate_sources_list("${_G_HITLS_APPS_OBJECTS}" "apps")
        hitls_generate_include_dirs_list("${_G_HITLS_APPS_OBJECTS}" "apps")
    endif()
    message(STATUS "Generated sources list: ${_source_file}")
    message(STATUS "Generated include directories list: ${_include_file}")
endif()
