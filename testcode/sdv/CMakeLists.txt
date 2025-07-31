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

message(STATUS "Enable bsl: ${ENABLE_BSL}")
message(STATUS "Enable fail repeat: ${ENABLE_FAIL_REPEAT}")
message(STATUS "Enable print: ${ENABLE_PRINT}")

set(TEST_SOURCE
    ${openHiTLS_SRC}/testcode/framework/gen_test/helper.c
    ${openHiTLS_SRC}/testcode/framework/gen_test/test.c
    ${openHiTLS_SRC}/testcode/framework/crypto/alg_check.c
    ${openHiTLS_SRC}/testcode/framework/crypto/crypto_test_util.c
    ${openHiTLS_SRC}/testcode/framework/stub/stub_replace.c
)

add_library(TEST_INTF INTERFACE)
add_library(TEST_INTF_SHARED INTERFACE)

if(ENABLE_PRINT)
    target_compile_options(TEST_INTF INTERFACE -DPRINT_TO_TERMINAL)
    target_compile_options(TEST_INTF_SHARED INTERFACE -DPRINT_TO_TERMINAL)
endif()
if(ENABLE_FAIL_REPEAT)
    target_compile_options(TEST_INTF INTERFACE -DFAIL_REPEAT_RUN)
    target_compile_options(TEST_INTF_SHARED INTERFACE -DFAIL_REPEAT_RUN)
endif()
target_link_directories(TEST_INTF INTERFACE
    ${openHiTLS_SRC}/build
    ${openHiTLS_SRC}/testcode/output/lib
    ${openHiTLS_SRC}/platform/Secure_C/lib
)
target_link_directories(TEST_INTF_SHARED INTERFACE
    ${openHiTLS_SRC}/build
    ${openHiTLS_SRC}/testcode/output/lib
    ${openHiTLS_SRC}/platform/Secure_C/lib
)

# link libs
set(TEST_INTF_LIBS "")
set(TEST_INTF_SHARED_LIBS "")

if(APPS)
    list(APPEND TEST_INTF_LIBS hitls_apps)
endif()

if(ENABLE_TLS AND ${BUILD_TLS} GREATER -1)
    list(APPEND TEST_INTF_LIBS tls_hlt tls_frame libhitls_tls.a rec_wrapper)
    list(APPEND TEST_INTF_SHARED_LIBS tls_hlt tls_frame libhitls_tls.so rec_wrapper)
endif()

if(ENABLE_PKI AND ${BUILD_PKI} GREATER -1)
    list(APPEND TEST_INTF_LIBS libhitls_pki.a)
    list(APPEND TEST_INTF_SHARED_LIBS libhitls_pki.so)
endif()

if(ENABLE_AUTH AND ${BUILD_AUTH} GREATER -1)
    list(APPEND TEST_INTF_LIBS libhitls_auth.a)
    list(APPEND TEST_INTF_SHARED_LIBS libhitls_auth.so)
endif()

if(ENABLE_CRYPTO AND ${BUILD_CRYPTO} GREATER -1)
    list(APPEND TEST_INTF_LIBS libhitls_crypto.a)
    list(APPEND TEST_INTF_SHARED_LIBS libhitls_crypto.so)
endif()

list(APPEND TEST_INTF_LIBS libhitls_bsl.a boundscheck pthread dl)
list(APPEND TEST_INTF_SHARED_LIBS libhitls_bsl.so boundscheck pthread dl)

target_link_libraries(TEST_INTF INTERFACE ${TEST_INTF_LIBS})
target_link_libraries(TEST_INTF_SHARED INTERFACE ${TEST_INTF_SHARED_LIBS})

set(TEST_INTF_INCLUDE_DIRS 
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
    ${openHiTLS_SRC}/include/auth
    ${openHiTLS_SRC}/bsl/log/include
    ${openHiTLS_SRC}/bsl/hash/include
    ${openHiTLS_SRC}/bsl/base64/include
    ${openHiTLS_SRC}/bsl/pem/include
    ${openHiTLS_SRC}/bsl/list/include
    ${openHiTLS_SRC}/bsl/obj/include
    ${openHiTLS_SRC}/bsl/include
    ${openHiTLS_SRC}/bsl/sal/src
    ${openHiTLS_SRC}/bsl/conf/include
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
    ${openHiTLS_SRC}/crypto/siphash/include
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
    ${openHiTLS_SRC}/crypto/elgamal/include
    ${openHiTLS_SRC}/crypto/elgamal/src
    ${openHiTLS_SRC}/crypto/encode/include
    ${openHiTLS_SRC}/crypto/codecskey/include
    ${openHiTLS_SRC}/crypto/codecskey/src
    ${openHiTLS_SRC}/crypto/entropy/src
    ${openHiTLS_SRC}/crypto/provider/src/cmvp/cmvp_utils
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
    ${openHiTLS_SRC}/bsl/buffer/include
    ${openHiTLS_SRC}/include/pki
    ${openHiTLS_SRC}/pki/x509_cert/include
    ${openHiTLS_SRC}/pki/x509_csr/include
    ${openHiTLS_SRC}/pki/x509_common/include
    ${openHiTLS_SRC}/pki/x509_crl/include
    ${openHiTLS_SRC}/pki/pkcs12/include
    ${openHiTLS_SRC}/pki/cms/include
    ${openHiTLS_SRC}/pki/x509_verify/include
    ${openHiTLS_SRC}/pki/print/include
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
    ${openHiTLS_SRC}/tls/handshake/common/src
    ${openHiTLS_SRC}/tls/feature/session/src
    ${openHiTLS_SRC}/tls/cert/include
    ${openHiTLS_SRC}/tls/cert/cert_adapt
    ${openHiTLS_SRC}/tls/cert/hitls_x509_adapt
    ${openHiTLS_SRC}/tls/crypt/crypt_self
    ${openHiTLS_SRC}/config/macro_config
    ${openHiTLS_SRC}/tls/handshake/parse/src
    ${openHiTLS_SRC}/auth/privpass_token/include
    ${openHiTLS_SRC}/config/macro_config
    ${openHiTLS_SRC}/codecs/include
    ${openHiTLS_SRC}/tls/feature/custom_extensions/include
    ${openHiTLS_SRC}/crypto/mlkem/include
    ${openHiTLS_SRC}/crypto/mlkem/src
    ${openHiTLS_SRC}/crypto/mldsa/include
    ${openHiTLS_SRC}/crypto/mldsa/src
    ${openHiTLS_SRC}/apps/include
    ${openHiTLS_SRC}/apps/src
    ${openHiTLS_SRC}/bsl/ui/include
    ${openHiTLS_SRC}/bsl/print/include
)

target_include_directories(TEST_INTF
        INTERFACE
        ${TEST_INTF_INCLUDE_DIRS}
)
target_include_directories(TEST_INTF_SHARED
        INTERFACE
        ${TEST_INTF_INCLUDE_DIRS}
)

add_library(TESTCASE_PRE ${TEST_SOURCE})
add_library(TESTCASE_PRE_SHARED ${TEST_SOURCE})

target_link_libraries(TESTCASE_PRE PRIVATE TEST_INTF)
target_link_libraries(TESTCASE_PRE_SHARED PRIVATE TEST_INTF_SHARED)

if(GEN_TEST_FILES)
    # test1 test2 ...
    string(REPLACE " " ";" GEN_TEST_FILES ${GEN_TEST_FILES})
    foreach(gen_test_suite ${GEN_TEST_FILES})
        get_filename_component(suite ${gen_test_suite} NAME)
        execute_process(COMMAND touch ${openHiTLS_SRC}/testcode/output/${suite}.c
            WORKING_DIRECTORY ${openHiTLS_SRC}/testcode/output
        )
        add_custom_target(${suite}_phony
                          COMMAND ./gen_testcase ${gen_test_suite}
                          DEPENDS gen_testcase
                          WORKING_DIRECTORY ${openHiTLS_SRC}/testcode/output)
        message(STATUS "${suite}: ${gen_test_suite}")
        set(TEST_FILES "${TEST_FILES};${gen_test_suite}")
    endforeach()
else()
    message(STATUS "No file needs to be generated")
endif()

# Set library type for each test case
set(TEST_SHARED_LIBS
    test_suite_sdv_hlt_provider
    test_suite_sdv_frame_provider
    test_suite_sdv_hlt_base_connect
    test_suite_sdv_hlt_tlcp_ciphersuite
)

# Create test cases
foreach(test_suite ${TEST_FILES})
    get_filename_component(sdv_exe ${test_suite} NAME_WE)
    add_executable(${sdv_exe} ${openHiTLS_SRC}/testcode/output/${sdv_exe}.c)
    target_link_options(${sdv_exe} PRIVATE "LINKER:-z,noexecstack")
    add_dependencies(${sdv_exe} ${sdv_exe}_phony)
    set_target_properties(${sdv_exe} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${openHiTLS_SRC}/testcode/output"
    )
    # Choose between static and shared libraries based on test case
    if(${sdv_exe} IN_LIST TEST_SHARED_LIBS)
        target_link_libraries(${sdv_exe} PRIVATE TEST_INTF_SHARED TESTCASE_PRE_SHARED)
    else()
        target_link_libraries(${sdv_exe} PRIVATE TEST_INTF TESTCASE_PRE)
    endif()
endforeach()

if("${APPS}" STREQUAL "ON")
    SET(APPS_LIB "hitls_apps")
    aux_source_directory(${openHiTLS_SRC}/apps/src APPS_SRC)
    add_library(${APPS_LIB} STATIC ${APPS_SRC})
    target_link_libraries(${APPS_LIB} PRIVATE TEST_INTF)
    target_compile_options(${APPS_LIB} PRIVATE -O0 -g3 -gdwarf-2)
   
    set_target_properties(${APPS_LIB}
        PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${openHiTLS_SRC}/testcode/output/lib"
    )
endif()
