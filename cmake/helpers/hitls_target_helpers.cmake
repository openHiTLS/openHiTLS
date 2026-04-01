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

# hitls_register_objects
# -------------------------
# Description:
#   Append an OBJECT library target to the per-module collection variable
#   _HITLS_<library_name>_OBJECTS (stored in the CMake cache as INTERNAL).
#
#   Additionally, sets the per-source-file compiler definition __FILENAME__
#   to the bare filename (e.g. "err.c") for every source in <object_target>,
#   so that runtime error messages show only the filename without any leading
#   directory path components.
function(hitls_register_objects library_name object_target)
    get_property(_current CACHE _G_HITLS_${library_name}_OBJECTS PROPERTY VALUE)
    list(APPEND _current "${object_target}")
    set(_G_HITLS_${library_name}_OBJECTS "${_current}" CACHE INTERNAL "${library_name} object libraries")

    # Set per-source-file __FILENAME__ to the bare filename (no path)
    get_target_property(_sources ${object_target} SOURCES)
    foreach(_src ${_sources})
        get_filename_component(_basename "${_src}" NAME)
        set_source_files_properties("${_src}" PROPERTIES
            COMPILE_DEFINITIONS "__FILENAME__=\"${_basename}\"")
    endforeach()
endfunction()
