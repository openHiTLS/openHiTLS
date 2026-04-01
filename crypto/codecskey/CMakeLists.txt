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


set(_codecskey_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_codecskey.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_codecskey_local.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_codecskey_print.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_codecskey_utils.c
)
if(HITLS_CRYPTO_KEY_DECODE_CHAIN)
    list(APPEND _codecskey_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_decoder_der2key.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_decoder_ecc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_decoder_epki2pki.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_decoder_lowkey2pkey.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_decoder_pem2der.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_decoder_pqc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_decoder_rsa.c
    )
endif()

add_library(_hitls_crypto_codecskey OBJECT ${_codecskey_sources})

target_link_libraries(_hitls_crypto_codecskey
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_codecskey
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/crypto/provider/include
        ${PROJECT_SOURCE_DIR}/crypto/provider/src/mgr
        ${PROJECT_SOURCE_DIR}/crypto/eal/include
        ${PROJECT_SOURCE_DIR}/crypto/eal/src
        ${PROJECT_SOURCE_DIR}/crypto/ecc/include
        ${PROJECT_SOURCE_DIR}/crypto/rsa/include
        ${PROJECT_SOURCE_DIR}/crypto/ecdsa/include
        ${PROJECT_SOURCE_DIR}/crypto/sm2/include
        ${PROJECT_SOURCE_DIR}/crypto/curve25519/include
        ${PROJECT_SOURCE_DIR}/crypto/mldsa/include
        ${PROJECT_SOURCE_DIR}/crypto/mlkem/include
        ${PROJECT_SOURCE_DIR}/crypto/slh_dsa/include
        ${PROJECT_SOURCE_DIR}/crypto/xmss/include
        ${PROJECT_SOURCE_DIR}/crypto/bn/include
        ${PROJECT_SOURCE_DIR}/bsl/asn1/include
        ${PROJECT_SOURCE_DIR}/bsl/print/include
        ${PROJECT_SOURCE_DIR}/bsl/pem/include
        ${PROJECT_SOURCE_DIR}/bsl/obj/include
)

hitls_register_objects(CRYPTO _hitls_crypto_codecskey)
