# auth/CMakeLists.txt

# Create a library for auth components
add_library(auth_lib STATIC
    totp/src/auth_totp.c
    privpass_token/src/privpass_token.c
    privpass_token/src/privpass_token_util.c
    privpass_token/src/privpass_token_wrapper.c
)

# Add include directories
# ${CMAKE_CURRENT_SOURCE_DIR} here is <repo_root>/auth
# ${CMAKE_SOURCE_DIR} is <repo_root>
target_include_directories(auth_lib PUBLIC
    # For auth_totp.h, privpass_token.h (specific to this module)
    ${CMAKE_CURRENT_SOURCE_DIR}/totp/include
    ${CMAKE_CURRENT_SOURCE_DIR}/privpass_token/include
    
    # For general project includes (e.g. "crypt_algid.h" might be here if moved from crypto dir)
    ${CMAKE_SOURCE_DIR}/include 

    # For BSL includes (e.g. "bsl/sal/include/sal_time.h", "bsl/bsl_types.h")
    # The C sources use paths like "bsl/sal/include/sal_time.h".
    # So, an include path to ${CMAKE_SOURCE_DIR} (repo root) itself would make "bsl/..." resolvable.
    # Or, more targeted: ${CMAKE_SOURCE_DIR}/bsl (if includes are "sal/include/sal_time.h")
    # Given "bsl/bsl_types.h", ${CMAKE_SOURCE_DIR} is better or ${CMAKE_SOURCE_DIR}/bsl (if bsl_types.h is in bsl/bsl_types.h)
    # The prompt specified ${CMAKE_SOURCE_DIR}/bsl/include. This implies headers are directly in bsl/include.
    # Let's check the includes in auth_totp.c:
    # "bsl/sal/include/sal_time.h" -> needs ${CMAKE_SOURCE_DIR} or ${CMAKE_SOURCE_DIR}/bsl to find "sal/..."
    # "bsl/bsl_types.h" -> needs ${CMAKE_SOURCE_DIR} or ${CMAKE_SOURCE_DIR}/bsl to find "bsl_types.h"
    # "bsl/bsl_errno.h" -> needs ${CMAKE_SOURCE_DIR} or ${CMAKE_SOURCE_DIR}/bsl to find "bsl_errno.h"
    # The most straightforward way to handle "bsl/foo/bar.h" is to add ${CMAKE_SOURCE_DIR}
    # However, if bsl_types.h is located at "bsl/include/bsl_types.h", then ${CMAKE_SOURCE_DIR}/bsl/include is correct for that one.
    # Let's stick to ${CMAKE_SOURCE_DIR} for bsl and crypto for simplicity as it covers the structure of includes used.
    # Reverting to the broader include path that was working in my head.
    # The prompt's suggestion of ${CMAKE_SOURCE_DIR}/bsl/include implies that auth_totp.h's include of "bsl/bsl_types.h"
    # would mean bsl_types.h is at <repo_root>/bsl/include/bsl/bsl_types.h, which is unlikely.
    # It's more likely bsl_types.h is at <repo_root>/bsl/bsl_types.h or <repo_root>/bsl/include/bsl_types.h
    # If "bsl/bsl_types.h" is the include string, and CMAKE_SOURCE_DIR is repo root, then adding ${CMAKE_SOURCE_DIR} works.
    # If bsl_types.h is at <repo_root>/bsl/include/bsl_types.h, then ${CMAKE_SOURCE_DIR}/bsl/include is NOT enough for "bsl/bsl_types.h".

    # For crypto includes (e.g. "crypto/crypt_eal_mac.h", "crypto/hmac/include/crypt_hmac.h")
    # Similar logic, ${CMAKE_SOURCE_DIR} makes "crypto/..." resolvable.
    ${CMAKE_SOURCE_DIR}
)

# Link with other libraries
# Using actual library names hitls_crypto and hitls_bsl discovered from demo CMakeLists.txt
target_link_libraries(auth_lib PRIVATE 
    hitls_crypto 
    hitls_bsl
    # Add 'm' for math library if floor() or other math functions are used and not linked by dependencies.
    # floor() is used in auth_totp.c.
    m 
)

# Set properties if needed, for example, C_STANDARD
set_target_properties(auth_lib PROPERTIES C_STANDARD 99)
