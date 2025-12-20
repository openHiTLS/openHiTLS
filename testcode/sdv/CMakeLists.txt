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

add_compile_definitions(OPENHITLSDIR="${CMAKE_INSTALL_PREFIX}/")
set(TEST_SOURCE
    ${openHiTLS_SRC}/testcode/framework/gen_test/helper.c
    ${openHiTLS_SRC}/testcode/framework/gen_test/test.c
    ${openHiTLS_SRC}/testcode/framework/crypto/alg_check.c
    ${openHiTLS_SRC}/testcode/framework/crypto/crypto_test_util.c
    ${openHiTLS_SRC}/testcode/framework/common/test_util.c
)

add_library(TEST_INTF INTERFACE)

if(ENABLE_PRINT)
    target_compile_options(TEST_INTF INTERFACE -DPRINT_TO_TERMINAL)
endif()
if(ENABLE_FAIL_REPEAT)
    target_compile_options(TEST_INTF INTERFACE -DFAIL_REPEAT_RUN)
endif()

target_link_directories(TEST_INTF INTERFACE
    ${openHiTLS_SRC}/build
    ${openHiTLS_SRC}/testcode/output/lib
    ${openHiTLS_SRC}/platform/Secure_C/lib
)

# Link libraries - cross-platform shared library configuration
# Use library names without extensions; CMake handles platform-specific suffixes
# macOS: .dylib, Linux: .so
set(TEST_INTF_LIBS "")


if(ENABLE_TLS AND ${BUILD_TLS} GREATER -1)
    list(APPEND TEST_INTF_LIBS tls_hlt tls_frame hitls_tls rec_wrapper)
endif()

if(ENABLE_PKI AND ${BUILD_PKI} GREATER -1)
    list(APPEND TEST_INTF_LIBS hitls_pki)
endif()

if(ENABLE_AUTH AND ${BUILD_AUTH} GREATER -1)
    list(APPEND TEST_INTF_LIBS hitls_auth)
endif()

if(ENABLE_CRYPTO AND ${BUILD_CRYPTO} GREATER -1)
    list(APPEND TEST_INTF_LIBS hitls_crypto)
endif()

# Use find_library to support cross-platform static library extensions (.a on Unix, .lib on Windows)
find_library(BOUNDSCHECK_STATIC_LIB
    NAMES libboundscheck.a boundscheck  # Try .a explicitly first, then let CMake find static version
    PATHS ${CMAKE_SOURCE_DIR}/../platform/Secure_C/lib
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
)
if(NOT BOUNDSCHECK_STATIC_LIB)
    message(FATAL_ERROR "Could not find static boundscheck library at ${CMAKE_SOURCE_DIR}/../platform/Secure_C/lib")
endif()
list(APPEND TEST_INTF_LIBS hitls_bsl ${BOUNDSCHECK_STATIC_LIB} pthread dl)
target_link_libraries(TEST_INTF INTERFACE ${TEST_INTF_LIBS})

# Shared variant inherits all configurations from TEST_INTF
add_library(TEST_INTF_SHARED INTERFACE)
target_link_libraries(TEST_INTF_SHARED INTERFACE TEST_INTF)

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
    ${openHiTLS_SRC}/crypto/sm9/include
    ${openHiTLS_SRC}/crypto/ecc/src/sm9/inc
    ${openHiTLS_SRC}/crypto/paillier/include
    ${openHiTLS_SRC}/crypto/paillier/src
    ${openHiTLS_SRC}/crypto/elgamal/include
    ${openHiTLS_SRC}/crypto/elgamal/src
    ${openHiTLS_SRC}/crypto/codecsdata/include
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
    ${openHiTLS_SRC}/auth/otp/include
    ${openHiTLS_SRC}/auth/pake/spake2plus/include
    ${openHiTLS_SRC}/config/macro_config
    ${openHiTLS_SRC}/codecs/include
    ${openHiTLS_SRC}/tls/feature/custom_extensions/include
    ${openHiTLS_SRC}/crypto/mlkem/include
    ${openHiTLS_SRC}/crypto/mlkem/src
    ${openHiTLS_SRC}/crypto/mldsa/include
    ${openHiTLS_SRC}/crypto/mldsa/src
    ${openHiTLS_SRC}/crypto/slh_dsa/include
    ${openHiTLS_SRC}/crypto/slh_dsa/src
    ${openHiTLS_SRC}/crypto/xmss/include
    ${openHiTLS_SRC}/crypto/xmss/src
    ${openHiTLS_SRC}/crypto/frodokem/include
    ${openHiTLS_SRC}/crypto/mceliece/include
    ${openHiTLS_SRC}/apps/include
    ${openHiTLS_SRC}/apps/src
    ${openHiTLS_SRC}/bsl/ui/include
    ${openHiTLS_SRC}/bsl/print/include
)

target_include_directories(TEST_INTF
        INTERFACE
        ${TEST_INTF_INCLUDE_DIRS}
)
# TEST_INTF_SHARED inherits include directories from TEST_INTF

# Test case precompiled library - currently using shared library configuration
# Future: Create separate TESTCASE_PRE if static library support is needed
add_library(TESTCASE_PRE ${TEST_SOURCE})
target_link_libraries(TESTCASE_PRE PRIVATE TEST_INTF_SHARED)

# Build apps library BEFORE test executables (must be defined before linking)
if("${APPS}" STREQUAL "ON")
    SET(APPS_LIB "hitls_apps")
    aux_source_directory(${openHiTLS_SRC}/apps/src APPS_SRC)
    # Exclude hitls.c which contains main() - conflicts with test executables
    list(REMOVE_ITEM APPS_SRC "${openHiTLS_SRC}/apps/src/hitls.c")
    # Build as SHARED library (dylib/so) for stub framework compatibility
    # Stub framework uses dlsym(RTLD_NEXT) which requires dynamic symbol visibility
    add_library(${APPS_LIB} SHARED ${APPS_SRC})

    if(WIN32)
        # Windows: .dll (not yet supported, placeholder for future implementation)
        set(HITLS_LIB_EXT "dll")
        message(WARNING "Windows build for apps library is not yet supported")
    elseif(APPLE)
        # macOS: .dylib
        set(HITLS_LIB_EXT "dylib")
    else()
        # Linux/Unix: .so
        set(HITLS_LIB_EXT "so")
    endif()

    target_link_libraries(${APPS_LIB} PRIVATE
        ${openHiTLS_SRC}/build/libhitls_crypto.${HITLS_LIB_EXT}
        ${openHiTLS_SRC}/build/libhitls_tls.${HITLS_LIB_EXT}
        ${openHiTLS_SRC}/build/libhitls_pki.${HITLS_LIB_EXT}
        ${openHiTLS_SRC}/build/libhitls_bsl.${HITLS_LIB_EXT}
    )

    # Platform-specific system libraries
    if(WIN32)
        # Windows system libraries (not yet supported)
        message(WARNING "Windows build for apps library is not yet supported")
    elseif(APPLE OR UNIX)
        # macOS and Linux: pthread and dl
        target_link_libraries(${APPS_LIB} PRIVATE pthread dl)
    endif()

    # Platform-specific compile options
    if(MSVC)
        # MSVC (Windows): Debug info + position-independent code equivalent
        # target_compile_options(${APPS_LIB} PRIVATE /Od /Zi /DEBUG)
        message(WARNING " Platform-specific options: Windows build for apps library is not yet supported")
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        # GCC/Clang (Linux/macOS): Debug info + position-independent code
        target_compile_options(${APPS_LIB} PRIVATE -O0 -g3 -gdwarf-2 -fPIC)
    endif()

    target_include_directories(${APPS_LIB} PRIVATE
        ${openHiTLS_SRC}/apps/include
        ${openHiTLS_SRC}/apps/src
        ${TEST_INTF_INCLUDE_DIRS}
    )

    # Output directory for shared library
    set_target_properties(${APPS_LIB}
        PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${openHiTLS_SRC}/testcode/output/lib"
        RUNTIME_OUTPUT_DIRECTORY "${openHiTLS_SRC}/testcode/output/lib"  # For Windows DLL
    )
endif()

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

# Create test cases with shared library linking for STUB framework compatibility
foreach(test_suite ${TEST_FILES})
    get_filename_component(sdv_exe ${test_suite} NAME_WE)
    add_executable(${sdv_exe} ${openHiTLS_SRC}/testcode/output/${sdv_exe}.c)
    # Apply GNU ld-specific link options only on Linux
    if(NOT APPLE)
        target_link_options(${sdv_exe} PRIVATE "LINKER:-z,noexecstack")
    endif()
    add_dependencies(${sdv_exe} ${sdv_exe}_phony)
    set_target_properties(${sdv_exe} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${openHiTLS_SRC}/testcode/output"
    )

    # Use shared libraries for STUB framework (dlsym RTLD_NEXT) compatibility
    target_link_libraries(${sdv_exe} PRIVATE TEST_INTF_SHARED TESTCASE_PRE)

    # Link apps test suites against hitls_apps shared library
    # Matches all 23 apps tests: 18 with "app" in name + dgst, enc, opt, print, rand
    if("${APPS}" STREQUAL "ON" AND ${sdv_exe} MATCHES "test_suite_ut_(app|dgst|enc|opt|print|rand)")
        target_link_libraries(${sdv_exe} PRIVATE hitls_apps)
    endif()
endforeach()
