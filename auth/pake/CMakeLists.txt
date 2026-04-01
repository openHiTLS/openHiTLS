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


set(_pake_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/pake.c
)

# SPAKE2+
if(HITLS_AUTH_SPAKE2PLUS)
    list(APPEND _pake_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/spake2plus/src/spake2plus.c
    )
endif()

add_library(_hitls_auth_pake OBJECT ${_pake_sources})

target_link_libraries(_hitls_auth_pake
    PUBLIC
        _hitls_auth_common_include
)

target_include_directories(_hitls_auth_pake
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/spake2plus/include>
    PRIVATE
        ${PROJECT_SOURCE_DIR}/crypto/ecc/include
        ${PROJECT_SOURCE_DIR}/crypto/bn/include
)

hitls_register_objects(AUTH _hitls_auth_pake)
