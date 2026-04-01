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


file(GLOB _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_library(_hitls_crypto_util OBJECT ${_util_sources})

target_link_libraries(_hitls_crypto_util
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_util
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include/crypto>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/crypto/bn/include
        ${PROJECT_SOURCE_DIR}/crypto/ecc/include
        ${PROJECT_SOURCE_DIR}/crypto/eal/include
        ${PROJECT_SOURCE_DIR}/crypto/modes/include
        ${PROJECT_SOURCE_DIR}/crypto/drbg/include
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
)


hitls_register_objects(CRYPTO _hitls_crypto_util)
