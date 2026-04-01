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


# Collect all defined macros to _HITLS_ALL_FEATURE_MACROS from the generated hitls_build_config.h
function(hitls_collect_all_macros_from_config_h)
    file(READ "${CONFIG_H_OUTPUT_PATH}" _build_config_content)

    # Match all #define HITLS_* patterns (with or without values)
    # This captures both boolean defines (#define HITLS_FOO) and value defines (#define HITLS_FOO value)
    string(REGEX MATCHALL "#define (HITLS_[A-Z0-9_]+)( [^\n]*)?" _macro_entries "${_build_config_content}")

    set(_collected_macros "")
    foreach(_entry ${_macro_entries})
        # Extract macro name and value separately
        # _entry format: "#define HITLS_XXX" or "#define HITLS_XXX value"
        string(REGEX MATCH "^#define (HITLS_[A-Z0-9_]+)(.*)$" _matched "${_entry}")

        if(CMAKE_MATCH_1)
            set(_macro_name "${CMAKE_MATCH_1}")
            set(_macro_value "${CMAKE_MATCH_2}")

            # Skip header guard macros (e.g., HITLS_XXX_H)
            if(_macro_name MATCHES "^HITLS_.*_H$")
                continue()
            endif()

            # Trim leading/trailing whitespace from value
            string(STRIP "${_macro_value}" _macro_value)

            # Store macro with its value if it has one
            if(_macro_value)
                list(APPEND _collected_macros "${_macro_name}=${_macro_value}")
            else()
                list(APPEND _collected_macros "${_macro_name}")
            endif()
        endif()
    endforeach()

    # Remove duplicates and store in cache
    set(_HITLS_ALL_FEATURE_MACROS "${_collected_macros}" CACHE STRING
        "List of all feature macros (boolean and value-based) extracted from config header file" FORCE
    )
endfunction()

hitls_collect_all_macros_from_config_h()
