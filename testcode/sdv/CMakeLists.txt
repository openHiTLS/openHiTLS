# ---------------------------------------------------------------------------------------------
#  This file is part of the openHiTLS project.
#  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
#  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
#  for license information.
# ---------------------------------------------------------------------------------------------

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
        ${openHiTLS_SRC}/platform/Secure_C/lib
        )
if(ENABLE_X509)
    target_link_libraries(${sdv_exe}
        -lhitls_x509
    )
endif()
if(ENABLE_CRYPTO)
    target_link_libraries(${sdv_exe}
        -lhitls_crypto
    )
endif()

target_link_libraries(${sdv_exe}
    -lhitls_bsl
    -lboundscheck
    -lpthread
)

if(ENABLE_UIO_SCTP)
    target_link_libraries(${sdv_exe} -lsctp)
endif()
target_include_directories(${sdv_exe}
    PRIVATE
        ${openHiTLS_SRC}/platform/Secure_C/include
        ${openHiTLS_SRC}/include
        ${openHiTLS_SRC}/testcode/framework/include
        ${openHiTLS_SRC}/testcode/framework/crypto
        ${openHiTLS_SRC}/testcode/framework/stub
        ${openHiTLS_SRC}/bsl/sal/include
        ${openHiTLS_SRC}/bsl/tlv/include
        ${openHiTLS_SRC}/include/bsl
        ${openHiTLS_SRC}/include/tls
        ${openHiTLS_SRC}/bsl/log/include
        ${openHiTLS_SRC}/bsl/hash/include
        ${openHiTLS_SRC}/bsl/list/include
        ${openHiTLS_SRC}/bsl/usrdata/include
        ${openHiTLS_SRC}/bsl/obj/include
        ${openHiTLS_SRC}/bsl/include
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
        ${openHiTLS_SRC}/crypto/dsa/src
        ${openHiTLS_SRC}/crypto/curve25519/src
        ${openHiTLS_SRC}/crypto/curve25519/include
        ${openHiTLS_SRC}/crypto/curve448/src
        ${openHiTLS_SRC}/crypto/curve448/include
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
        ${openHiTLS_SRC}/crypto//encode/include
        ${openHiTLS_SRC}/bsl/err/include
        ${openHiTLS_SRC}/bsl/err/src
        ${openHiTLS_SRC}/bsl/uio/include
        ${openHiTLS_SRC}/bsl/uio/src
        ${openHiTLS_SRC}/bsl/asn1/include
        ${openHiTLS_SRC}/x509/include
        ${openHiTLS_SRC}/x509/x509_cert/include
        ${openHiTLS_SRC}/x509/x509_common/include
        ${openHiTLS_SRC}/x509/x509_crl/include
        ${openHiTLS_SRC}/x509/x509_verify/include
        ${openHiTLS_SRC}/config/macro_config)

