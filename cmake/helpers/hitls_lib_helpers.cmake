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

# Helper function to collect OBJECT-library object files
function(objects_to_target_objects output_var _obj_targets)
    if(NOT _obj_targets)
        set(${output_var} "" PARENT_SCOPE)
        return()
    endif()

    # Collect all object files
    set(_target_objects "")
    foreach(_target ${_obj_targets})
        if(TARGET ${_target})
            list(APPEND _target_objects $<TARGET_OBJECTS:${_target}>)
        endif()
    endforeach()

    set(${output_var} "${_target_objects}" PARENT_SCOPE)
endfunction()


function(hitls_create_shared_library _target_objects shared_lib_name output_name)
    if(NOT _target_objects)
        message(STATUS "[HiTLS] No objects for ${shared_lib_name}, skipping shared library")
        return()
    endif()

    add_library(${shared_lib_name} SHARED ${_target_objects})
    target_link_options(${shared_lib_name} PRIVATE ${HITLS_SHARED_LINKER_FLAGS})
    set_target_properties(${shared_lib_name} PROPERTIES OUTPUT_NAME ${output_name})
    install(TARGETS ${shared_lib_name} DESTINATION ${CMAKE_INSTALL_LIBDIR})

    if(_G_HITLS_APPROVED_PROVIDER)
        install(CODE
            "execute_process(
                COMMAND openssl dgst -hmac \"${CMVP_INTEGRITYKEY}\"
                -${_G_HITLS_CMVP_HAMC_ALG} -out lib${output_name}.so.hmac
                lib${output_name}.so)"
            )
        install(CODE
            "execute_process(
                COMMAND cp lib${output_name}.so.hmac \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/lib${output_name}.so.hmac)"
            )
    endif()

    message(STATUS "[HiTLS] Created shared library ${shared_lib_name}")
endfunction()

function(hitls_create_static_library _target_objects static_lib_name output_name)
    if(NOT _target_objects)
        message(STATUS "[HiTLS] No objects for ${static_lib_name}, skipping static library")
        return()
    endif()

    add_library(${static_lib_name} STATIC ${_target_objects})
    set_target_properties(${static_lib_name} PROPERTIES OUTPUT_NAME ${output_name})
    install(TARGETS ${static_lib_name} DESTINATION ${CMAKE_INSTALL_LIBDIR})

    message(STATUS "[HiTLS] Created static library ${static_lib_name}")
endfunction()

function(hitls_create_executable _target_objects executable_name)
    if(NOT _target_objects)
        message(STATUS "[HiTLS] No objects for ${executable_name}, skipping executable")
        return()
    endif()

    add_executable(${executable_name} ${_target_objects})
    target_link_options(${executable_name} PRIVATE ${HITLS_EXE_LINKER_FLAGS})
    target_link_directories(${executable_name} PRIVATE ${CMAKE_BINARY_DIR})
    install(TARGETS ${executable_name} DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(CODE "execute_process(COMMAND openssl dgst -hmac \"${CMVP_INTEGRITYKEY}\" -sm3 -out hitls.hmac hitls)")
    install(CODE "execute_process(COMMAND cp hitls.hmac \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/hitls.hmac)")

    message(STATUS "[HiTLS] Created executable ${executable_name}")
endfunction()
