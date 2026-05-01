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


file(GLOB _hbs_common_sources ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_library(_hitls_crypto_hbs_common OBJECT ${_hbs_common_sources})

target_link_libraries(_hitls_crypto_hbs_common
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_hbs_common
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/crypto/hbs/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
        ${PROJECT_SOURCE_DIR}/crypto/sha2/src
        ${PROJECT_SOURCE_DIR}/crypto/sha2/include
        ${PROJECT_SOURCE_DIR}/bsl/asn1/include
)

hitls_register_objects(CRYPTO _hitls_crypto_hbs_common)
