# testcode/sdv/testcase/auth/CMakeLists.txt
cmake_minimum_required(VERSION 3.10) 
project(AuthTests C)

# Add executable for TOTP tests
add_executable(totp_tests totp/test_totp.c)

# Include directories for the test executable
target_include_directories(totp_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/auth/totp/include          # For auth_totp.h
    ${CMAKE_SOURCE_DIR}/auth/privpass_token/include # For privpass_token.h (needed by auth_lib)
    ${CMAKE_SOURCE_DIR}/include                    # For general project headers (e.g. crypt_algid.h if it's there)
                                                 # and other headers like crypto/crypt_algid.h, bsl/bsl_types.h etc.
    ${CMAKE_SOURCE_DIR}                            # To resolve includes like "crypto/..." and "bsl/..."
)

# Link with auth_lib and other dependencies
# auth_lib is the library created in auth/CMakeLists.txt
# Using actual library names hitls_crypto and hitls_bsl discovered from demo CMakeLists.txt
target_link_libraries(totp_tests PRIVATE
    auth_lib
    hitls_crypto 
    hitls_bsl    
    m             # For math functions like floor
)

# Set properties if needed, for example, C_STANDARD
set_target_properties(totp_tests PROPERTIES C_STANDARD 99)
