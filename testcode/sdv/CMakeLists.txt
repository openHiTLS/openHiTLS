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
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

PROJECT(openHiTLS_TEST)

set(openHiTLS_SRC "${PROJECT_SOURCE_DIR}/../..")
set(TEST_SOURCE_SRC
    ${openHiTLS_SRC}/testcode/framework/gen_test/helper.c
    ${openHiTLS_SRC}/testcode/framework/gen_test/test.c
    ${openHiTLS_SRC}/testcode/framework/crypto/alg_check.c
    ${openHiTLS_SRC}/testcode/framework/crypto/crypto_test_util.c
    ${openHiTLS_SRC}/testcode/framework/stub/stub_replace.c
)

if(GEN_TEST_FILES)
    execute_process(COMMAND ./gen_testcase ${GEN_TEST_FILES}
        WORKING_DIRECTORY ${openHiTLS_SRC}/testcode/output
        RESULT_VARIABLE retval
    )
    if(${retval} EQUAL 0)
        message(STATUS "Generate ${GEN_TEST_FILES} success")
        set(TEST_FILES "${GEN_TEST_FILES}")
    else()
        message(WARNING "Generate ${GEN_TEST_FILES} failed")
    endif()
else()
    message(STATUS "No file needs to be generated")
endif()

message(STATUS "Enable bsl: ${ENABLE_BSL}")
message(STATUS "Enable fail repeat: ${ENABLE_FAIL_REPEAT}")
message(STATUS "Enable print: ${ENABLE_PRINT}")

set(EXECUTABLE_OUTPUT_PATH ${openHiTLS_SRC}/testcode/output)
get_filename_component(sdv_exe ${TEST_FILES} NAME)
add_executable(${sdv_exe} ${openHiTLS_SRC}/testcode/output/${sdv_exe}.c ${TEST_SOURCE_SRC})
target_compile_options(${sdv_exe} PUBLIC -D__FILENAME__="${sdv_exe}.c")
if(ENABLE_PRINT)
    target_compile_options(${sdv_exe} PUBLIC -DPRINT_TO_TERMINAL)
endif()
if(ENABLE_FAIL_REPEAT)
    target_compile_options(${sdv_exe} PUBLIC -DFAIL_REPEAT_RUN)
endif()
target_link_directories(${sdv_exe}
    PUBLIC
        ${openHiTLS_SRC}/build
        ${openHiTLS_SRC}/testcode/framework/tls/lib
        ${openHiTLS_SRC}/platform/Secure_C/lib
        )
if(ENABLE_PKI)
    target_link_libraries(${sdv_exe}
        -lhitls_pki
    )
endif()

if(ENABLE_TLS)
    target_link_libraries(${sdv_exe}
        -ltls_hlt
        -ltls_frame
        -lhitls_tls
        -lhitls_pki
        -lrec_wrapper
    )
endif()

if(ENABLE_CRYPTO OR ENABLE_TLS)
    target_link_libraries(${sdv_exe}
        -lhitls_crypto
    )
endif()

target_link_libraries(${sdv_exe}
    -lhitls_bsl
    -lboundscheck
    -lpthread
    -ldl
)
if(ENABLE_UIO_SCTP OR ENABLE_TLS)
    target_link_libraries(${sdv_exe} -lsctp)
endif()
target_include_directories(${sdv_exe}
    PRIVATE
        ${openHiTLS_SRC}/platform/Secure_C/include
        ${openHiTLS_SRC}/include
        ${openHiTLS_SRC}/testcode/framework/include
        ${openHiTLS_SRC}/testcode/framework/crypto
        ${openHiTLS_SRC}/testcode/framework/stub
        ${openHiTLS_SRC}/testcode/framework/tls/func_wrapper/include
        ${openHiTLS_SRC}/testcode/framework/tls/include
        ${openHiTLS_SRC}/testcode/framework/tls/callback/include
        ${openHiTLS_SRC}/testcode/framework/tls/base/include
        ${openHiTLS_SRC}/testcode/framework/tls/resource/include
        ${openHiTLS_SRC}/testcode/framework/tls/rpc/include
        ${openHiTLS_SRC}/testcode/framework/tls/process/include
        ${openHiTLS_SRC}/testcode/framework/tls/crypt/include
        ${openHiTLS_SRC}/testcode/framework/tls/transfer/include
        ${openHiTLS_SRC}/testcode/framework/tls/frame/src
        ${openHiTLS_SRC}/testcode/framework/tls/msg/include
        ${openHiTLS_SRC}/testcode/framework/tls/io/include
        ${openHiTLS_SRC}/testcode/framework/tls/io/src
        ${openHiTLS_SRC}/bsl/sal/include
        ${openHiTLS_SRC}/bsl/tlv/include
        ${openHiTLS_SRC}/include/bsl
        ${openHiTLS_SRC}/include/tls
        ${openHiTLS_SRC}/bsl/log/include
        ${openHiTLS_SRC}/bsl/hash/include
        ${openHiTLS_SRC}/bsl/base64/include
        ${openHiTLS_SRC}/bsl/pem/include
        ${openHiTLS_SRC}/bsl/list/include
        ${openHiTLS_SRC}/bsl/usrdata/include
        ${openHiTLS_SRC}/bsl/obj/include
        ${openHiTLS_SRC}/bsl/include
        ${openHiTLS_SRC}/bsl/sal/src
        ${openHiTLS_SRC}/include/crypto/
        ${openHiTLS_SRC}/crypto/bn/include/
        ${openHiTLS_SRC}/crypto/bn/src/
        ${openHiTLS_SRC}/crypto/entropy/include/
        ${openHiTLS_SRC}/crypto/sm3/include
        ${openHiTLS_SRC}/crypto/sha3/include
        ${openHiTLS_SRC}/crypto/sha2/include
        ${openHiTLS_SRC}/crypto/sha2/src
        ${openHiTLS_SRC}/crypto/sha1/include
        ${openHiTLS_SRC}/crypto/md5/include
        ${openHiTLS_SRC}/crypto/pbkdf2/include
        ${openHiTLS_SRC}/crypto/provider/include
        ${openHiTLS_SRC}/crypto/provider/src/mgr
        ${openHiTLS_SRC}/crypto/hkdf/include
        ${openHiTLS_SRC}/crypto/kdf/include
        ${openHiTLS_SRC}/crypto/scrypt/include
        ${openHiTLS_SRC}/crypto/hmac/include
        ${openHiTLS_SRC}/crypto/aes/include
        ${openHiTLS_SRC}/crypto/sm4/include
        ${openHiTLS_SRC}/crypto/drbg/include
        ${openHiTLS_SRC}/crypto/drbg/src
        ${openHiTLS_SRC}/crypto/include
        ${openHiTLS_SRC}/crypto/rsa/include
        ${openHiTLS_SRC}/crypto/rsa/src
        ${openHiTLS_SRC}/crypto/eal/src
        ${openHiTLS_SRC}/crypto/eal/include
        ${openHiTLS_SRC}/crypto/ealinit/include
        ${openHiTLS_SRC}/crypto/ealinit/src
        ${openHiTLS_SRC}/crypto/dsa/src
        ${openHiTLS_SRC}/crypto/curve25519/src
        ${openHiTLS_SRC}/crypto/curve25519/include
        ${openHiTLS_SRC}/crypto/chacha20/include
        ${openHiTLS_SRC}/crypto/dsa/include
        ${openHiTLS_SRC}/crypto/dsa/src
        ${openHiTLS_SRC}/crypto/dh/include
        ${openHiTLS_SRC}/crypto/dh/src
        ${openHiTLS_SRC}/crypto/ecc/include
        ${openHiTLS_SRC}/crypto/ecc/src
        ${openHiTLS_SRC}/crypto/ecdh/include
        ${openHiTLS_SRC}/crypto/ecdsa/include
        ${openHiTLS_SRC}/crypto/modes/include
        ${openHiTLS_SRC}/crypto/modes/src
        ${openHiTLS_SRC}/crypto/ecdh/include
        ${openHiTLS_SRC}/crypto/ecdsa/include
        ${openHiTLS_SRC}/crypto/sm2/include
        ${openHiTLS_SRC}/crypto/sm2/src
        ${openHiTLS_SRC}/crypto/paillier/include
        ${openHiTLS_SRC}/crypto/paillier/src
        ${openHiTLS_SRC}/crypto/encode/include
        ${openHiTLS_SRC}/bsl/err/include
        ${openHiTLS_SRC}/bsl/err/src
        ${openHiTLS_SRC}/include/tls
        ${openHiTLS_SRC}/tls/include
        ${openHiTLS_SRC}/tls/cert/include
        ${openHiTLS_SRC}/tls/cm/include
        ${openHiTLS_SRC}/tls/config/include
        ${openHiTLS_SRC}/tls/crypt/include
        ${openHiTLS_SRC}/tls/app/include
        ${openHiTLS_SRC}/tls/app/src
        ${openHiTLS_SRC}/tls/ccs/include
        ${openHiTLS_SRC}/tls/alert/include
        ${openHiTLS_SRC}/bsl/uio/include
        ${openHiTLS_SRC}/tls/record/include
        ${openHiTLS_SRC}/tls/record/src
        ${openHiTLS_SRC}/bsl/uio/src
        ${openHiTLS_SRC}/bsl/asn1/include
        ${openHiTLS_SRC}/include/pki
        ${openHiTLS_SRC}/pki/x509_cert/include
        ${openHiTLS_SRC}/pki/x509_csr/include
        ${openHiTLS_SRC}/pki/x509_common/include
        ${openHiTLS_SRC}/pki/x509_crl/include
        ${openHiTLS_SRC}/pki/pkcs12/include
        ${openHiTLS_SRC}/pki/cms/include
        ${openHiTLS_SRC}/pki/x509_verify/include
        ${openHiTLS_SRC}/config/macro_config
        ${openHiTLS_SRC}/tls/handshake/include
        ${openHiTLS_SRC}/tls/handshake/common/include
        ${openHiTLS_SRC}/tls/handshake/cookie/include
        ${openHiTLS_SRC}/tls/handshake/parse/include
        ${openHiTLS_SRC}/tls/handshake/pack/include
        ${openHiTLS_SRC}/tls/handshake/pack/src
        ${openHiTLS_SRC}/tls/handshake/send/src
        ${openHiTLS_SRC}/tls/handshake/recv/src
        ${openHiTLS_SRC}/tls/handshake/recv/include
        ${openHiTLS_SRC}/tls/feature/session/src
        ${openHiTLS_SRC}/tls/cert/include
        ${openHiTLS_SRC}/tls/cert/cert_adapt
        ${openHiTLS_SRC}/tls/cert/hitls_x509_adapt
        ${openHiTLS_SRC}/tls/crypt/crypt_self
        ${openHiTLS_SRC}/config/macro_config
        ${openHiTLS_SRC}/tls/handshake/parse/src
        ${openHiTLS_SRC}/config/macro_config)

