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

project(demo)

message(status "HITLS_ROOT: ${HITLS_ROOT}")
set(HITLS_ROOT ../..)
set(HITLS_INCLUDE ${HITLS_ROOT}/include/bsl
                  ${HITLS_ROOT}/include/crypto
                  ${HITLS_ROOT}/include/tls
                  ${HITLS_ROOT}/include/pki
                  ${HITLS_ROOT}/include/auth
                  ${HITLS_ROOT}/config/macro_config
                  ${HITLS_ROOT}/platform/Secure_C/include)

if(CUSTOM_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CUSTOM_CFLAGS}")
endif()

if(ENABLE_GCOV)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage -lgcov")
endif()

if(ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-stack-protector -fno-omit-frame-pointer")
endif()

add_library(DEMO_INTF INTERFACE)
target_compile_options(DEMO_INTF INTERFACE -g)
target_link_directories(DEMO_INTF INTERFACE ${HITLS_ROOT}/build 
                                            ${HITLS_ROOT}/platform/Secure_C/lib/)

target_link_libraries(DEMO_INTF INTERFACE hitls_tls hitls_pki hitls_auth hitls_crypto hitls_bsl boundscheck pthread dl)
target_include_directories(DEMO_INTF INTERFACE ${HITLS_INCLUDE})

set(TESTS client.c server.c drbg.c ecdh.c pbkdf2.c sm2enc.c sm2sign.c sm4cbc.c hash.c privpass_token.c)
foreach(testcase ${TESTS})
    get_filename_component(testname ${testcase} NAME_WLE)
    add_executable(${testname} ${testcase})
    target_link_libraries(${testname} PRIVATE DEMO_INTF)
endforeach()

# --- TOTP Demo (Added for Subtask 5) ---
add_executable(totp_demo totp_demo.c)

# Include directories for the TOTP demo executable
# HITLS_ROOT is <repo_root>
target_include_directories(totp_demo PRIVATE
    ${HITLS_ROOT}/auth/totp/include          # For auth_totp.h
    ${HITLS_ROOT}/auth/privpass_token/include # For privpass_token.h (needed by auth_lib)
    ${HITLS_ROOT}/include                    # For general project headers (e.g. crypt_algid.h from crypto/crypt_algid.h if structure is include/crypto/crypt_algid.h)
    ${HITLS_ROOT}                            # To resolve includes like "crypto/crypt_algid.h", "bsl/bsl_types.h" 
                                             # when they are relative to repo root. auth_lib also propagates this.
)

# Link with auth_lib (defined in auth/CMakeLists.txt which includes TOTP sources)
# and the actual crypto and bsl libs (hitls_crypto, hitls_bsl from DEMO_INTF)
# and other common libraries from DEMO_INTF if needed.
target_link_libraries(totp_demo PRIVATE
    auth_lib       # Custom library from auth/CMakeLists.txt
    hitls_crypto   # Actual crypto lib name from DEMO_INTF
    hitls_bsl      # Actual bsl lib name from DEMO_INTF
    m              # For math functions like floor() used in auth_totp.c
    boundscheck    # From DEMO_INTF
    pthread        # From DEMO_INTF
    dl             # From DEMO_INTF
)

set_target_properties(totp_demo PROPERTIES C_STANDARD 99) # Consistent C standard
# --- End TOTP Demo ---
