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


# ==============================================================================
# This file checks the dependencies(cryptography related) between features in the HiTLS library.
# ==============================================================================

include_guard(GLOBAL)

# Append a dependency warning message to the accumulated list.
# The caller is responsible for the condition check.
#
# Usage:
#   if(HITLS_FEATURE_A AND NOT HITLS_FEATURE_B)
#       hitls_add_dependency_warning(
#           "[HiTLS] HITLS_FEATURE_A requires HITLS_FEATURE_B to be enabled. "
#           "(HITLS_FEATURE_B)"
#       )
#   endif()
function(hitls_add_dependency_warning)
    set(_msg "")
    foreach(_part ${ARGN})
        string(APPEND _msg "${_part}")
    endforeach()
    if(_DEPENDENCY_CHECK_WARNINGS)
        set(_list "${_DEPENDENCY_CHECK_WARNINGS};${_msg}")
    else()
        set(_list "${_msg}")
    endif()
    set(_DEPENDENCY_CHECK_WARNINGS "${_list}" CACHE INTERNAL "Accumulated dependency warnings")
endfunction()

# Print all collected dependency warnings and terminate the configure step.
# Call this once after all hitls_add_dependency_warning() calls have been made.
# If no warnings were registered, this is a no-op.
macro(hitls_check_dependency_warnings)
    if(_DEPENDENCY_CHECK_WARNINGS)
        # Build a single formatted error string from all collected warnings.
        set(_hitls_err_lines
            " ============================================================================="
            " HiTLS Configuration Error(Missing Required Dependencies): "
            " -----------------------------------------------------------------------------"
        )
        foreach(_hitls_warn ${_DEPENDENCY_CHECK_WARNINGS})
            list(APPEND _hitls_err_lines " * ${_hitls_warn}")
        endforeach()
        list(APPEND _hitls_err_lines
            " -----------------------------------------------------------------------------"
            " Please enable the options listed above and re-run cmake."
        )
        if(NOT HITLS_SKIP_CONFIG_CHECK)
            list(APPEND _hitls_err_lines
                " Or if you understand the implications and want to proceed anyway,"
                " you can disable this check by setting -DHITLS_SKIP_CONFIG_CHECK=ON (not recommended)."
            )
        endif()
        list(APPEND _hitls_err_lines " =============================================================================")
        list(JOIN _hitls_err_lines "\n" _hitls_err_msg)

        # Clear the list so a subsequent reconfigure starts clean.
        set(_DEPENDENCY_CHECK_WARNINGS "" CACHE INTERNAL "Accumulated dependency warnings")
        message(FATAL_ERROR "${_hitls_err_msg}")
        unset(_hitls_err_lines)
        unset(_hitls_err_msg)
    endif()
endmacro()

# Check that ASM-specific crypto features have their corresponding ASM architecture enabled.
# This macro automatically detects and validates all HITLS_CRYPTO_*_X8664, HITLS_CRYPTO_*_ARMV8,
# and HITLS_CRYPTO_*_ARMV7 options without needing to manually list each one.
# Examples:
#   - Any HITLS_CRYPTO_*_ARMV8 requires HITLS_ASM_ARMV8
#   - Any HITLS_CRYPTO_*_ARMV7 requires HITLS_ASM_ARMV7
#   - Any HITLS_CRYPTO_*_X8664 requires HITLS_ASM_X8664
#   - Any HITLS_CRYPTO_*_X8664_AVX512 requires HITLS_ASM_X8664_AVX512
macro(hitls_check_asm_feature_auto)
    get_cmake_property(_all_vars CACHE_VARIABLES)
    foreach(_var ${_all_vars})
        if(NOT ${_var})
            continue()
        endif()

        # Check for X8664 Avx512 ASM features
        if(_var MATCHES "^HITLS_CRYPTO_.*_X8664_AVX512$")
            if(NOT HITLS_ASM_X8664_AVX512)
                hitls_add_dependency_warning(
                    "[HiTLS] The ${_var} requires HITLS_ASM_X8664_AVX512 to be enabled. (HITLS_ASM_X8664_AVX512)"
                )
            endif()
        endif()

        # Check for X8664 ASM features
        if(_var MATCHES "^HITLS_CRYPTO_.*_X8664$")
            if(NOT HITLS_ASM_X8664)
                hitls_add_dependency_warning(
                    "[HiTLS] The ${_var} requires HITLS_ASM_X8664 to be enabled. (HITLS_ASM_X8664)"
                )
            endif()
        endif()
        
        # Check for ARMV8 ASM features
        if(_var MATCHES "^HITLS_CRYPTO_.*_ARMV8$")
            if(NOT HITLS_ASM_ARMV8)
                hitls_add_dependency_warning(
                    "[HiTLS] The ${_var} requires HITLS_ASM_ARMV8 to be enabled. (HITLS_ASM_ARMV8)"
                )
            endif()
        endif()
        
        # Check for ARMV7 ASM features
        if(_var MATCHES "^HITLS_CRYPTO_.*_ARMV7$")
            if(NOT HITLS_ASM_ARMV7)
                hitls_add_dependency_warning(
                    "[HiTLS] The ${_var} requires HITLS_ASM_ARMV7 to be enabled. (HITLS_ASM_ARMV7)"
                )
            endif()
        endif()
    endforeach()
    unset(_all_vars)
    unset(_var)
endmacro()

if(NOT HITLS_SKIP_CONFIG_CHECK)
    # 1. Simple Case: define in options.cmake，link _G_HITLS_DEPS_CHECK_${option}
    # Get all HITLS_* cache variables
    get_cmake_property(_cache_vars CACHE_VARIABLES)
    foreach(_var ${_cache_vars})
        if(_var MATCHES "^_G_HITLS_DEPS_CHECK_" AND NOT _var MATCHES "_OBJECTS$")
            String(REPLACE "_G_HITLS_DEPS_CHECK_" "" _main_feature ${_var})
            if(${_main_feature})
                set(_deps_check "${${_var}}")
                foreach(_dep_check ${_deps_check})
                    if(NOT ${_dep_check})
                        hitls_add_dependency_warning(
                            "[HiTLS] The ${_main_feature} requires ${_dep_check} to be enabled. (${_dep_check})"
                        )
                    endif()
                endforeach()
            endif()
        endif()
    endforeach()

    # 2. Complex Case: manually check the dependencies in this file
    # --- BSL Check ---
    # Bn
    if(HITLS_CRYPTO_BN AND NOT HITLS_SIXTY_FOUR_BITS AND NOT HITLS_THIRTY_TWO_BITS)
        hitls_add_dependency_warning(
            "[HiTLS] To use bn, the number of system bits must be specified first. "
            "(HITLS_SIXTY_FOUR_BITS/HITLS_THIRTY_TWO_BITS)"
        )
    endif()


    # --- Crypto Check ---
    # DRBG
    if(HITLS_CRYPTO_DRBG)
        # DRBG-CTR
        if(HITLS_CRYPTO_DRBG_CTR AND NOT HITLS_CRYPTO_AES AND NOT HITLS_CRYPTO_SM4)
            hitls_add_dependency_warning(
                "[HiTLS] The DRBG-CTR must work with AES or SM4. (HITLS_CRYPTO_AES/HITLS_CRYPTO_SM4)"
            )
        endif()
        # DRBG-GM
        if(HITLS_CRYPTO_DRBG_GM AND NOT HITLS_CRYPTO_DRBG_CTR AND NOT HITLS_CRYPTO_DRBG_HASH)
            hitls_add_dependency_warning(
                "[HiTLS]DRBG-HASH or DRBG-CTR must be enabled for DRBG-GM. "
                "(HITLS_CRYPTO_DRBG_CTR/HITLS_CRYPTO_DRBG_HASH)"
            )
        endif()
    endif()

    # Entropy
    if(HITLS_CRYPTO_ENTROPY)
        if(NOT HITLS_CRYPTO_DRBG_HASH AND NOT HITLS_CRYPTO_DRBG_HMAC AND NOT HITLS_CRYPTO_DRBG_CTR)
            hitls_add_dependency_warning(
                "[HiTLS] The entropy must work with at least one DRBG. "
                "(HITLS_CRYPTO_DRBG_HASH/HITLS_CRYPTO_DRBG_HMAC/HITLS_CRYPTO_DRBG_CTR)"
            )
        endif()
        if(HITLS_CRYPTO_DRBG_CTR AND NOT HITLS_CRYPTO_DRBG_GM AND NOT HITLS_CRYPTO_CMAC_AES)
            hitls_add_dependency_warning(
                "[HiTLS] Configure the conditioning function. Currently, CRYPT_MAC_CMAC_AES is supported. "
                "others may be supported in the future. (HITLS_CRYPTO_CMAC_AES)"
            )
        endif()
    endif()

    # CodecsKey
    if(HITLS_CRYPTO_CODECSKEY)
        if(NOT HITLS_CRYPTO_ECDSA AND NOT HITLS_CRYPTO_SM2_SIGN AND NOT HITLS_CRYPTO_SM2_CRYPT AND
            NOT HITLS_CRYPTO_ED25519 AND NOT HITLS_CRYPTO_RSA_SIGN AND NOT HITLS_CRYPTO_RSA_VERIFY AND
            NOT HITLS_CRYPTO_MLDSA AND NOT HITLS_CRYPTO_XMSS AND NOT HITLS_CRYPTO_DH AND
            NOT HITLS_CRYPTO_DSA AND NOT HITLS_CRYPTO_MLKEM AND NOT HITLS_CRYPTO_SLH_DSA AND
            NOT HITLS_CRYPTO_X25519)
            hitls_add_dependency_warning(
                "[HiTLS] The codecs key must work with at least one algorithm. "
                "(HITLS_CRYPTO_ECDSA/HITLS_CRYPTO_SM2_SIGN/HITLS_CRYPTO_SM2_CRYPT/HITLS_CRYPTO_ED25519/"
                "HITLS_CRYPTO_RSA_SIGN/HITLS_CRYPTO_RSA_VERIFY/HITLS_CRYPTO_MLDSA/HITLS_CRYPTO_XMSS/"
                "HITLS_CRYPTO_DH/HITLS_CRYPTO_DSA/HITLS_CRYPTO_MLKEM/HITLS_CRYPTO_SLH_DSA/HITLS_CRYPTO_X25519)"
            )
        endif()
        if(HITLS_CRYPTO_KEY_EPKI)
            if(NOT HITLS_CRYPTO_KEY_ENCODE AND NOT HITLS_CRYPTO_KEY_DECODE)
                hitls_add_dependency_warning(
                    "[HiTLS] The codecs key with epki must work with key encode or decode. "
                    "(HITLS_CRYPTO_KEY_ENCODE/HITLS_CRYPTO_KEY_DECODE)"
                )
            endif()
        endif()
    endif()

    # RSA
    if(HITLS_CRYPTO_RSA)
        # sign/verify needs padding scheme
        if(HITLS_CRYPTO_RSA_SIGN OR HITLS_CRYPTO_RSA_VERIFY)
            if(NOT HITLS_CRYPTO_RSA_EMSA_PSS AND NOT HITLS_CRYPTO_RSA_EMSA_PKCSV15 AND NOT HITLS_CRYPTO_RSA_EMSA_ISO9796_2)
                hitls_add_dependency_warning(
                    "[HiTLS] The RSA signature and verification must work with at least one padding scheme. "
                    "(HITLS_CRYPTO_RSA_SIGN/HITLS_CRYPTO_RSA_VERIFY)"
                    "(HITLS_CRYPTO_RSA_EMSA_PSS/HITLS_CRYPTO_RSA_EMSA_PKCSV15/HITLS_CRYPTO_RSA_EMSA_ISO9796_2)"
                )
            endif()
        endif()
        # encryption/decryption needs padding scheme
        if(HITLS_CRYPTO_RSA_ENCRYPT OR HITLS_CRYPTO_RSA_DECRYPT)
            if(NOT HITLS_CRYPTO_RSA_NO_PAD AND NOT HITLS_CRYPTO_RSAES_OAEP AND NOT HITLS_CRYPTO_RSAES_PKCSV15 AND
                NOT HITLS_CRYPTO_RSAES_PKCSV15_TLS)
                hitls_add_dependency_warning(
                    "[HiTLS] The RSA encryption and decryption must work with at least one padding scheme. "
                    "(HITLS_CRYPTO_RSA_ENCRYPT/HITLS_CRYPTO_RSA_DECRYPT)"
                    "(HITLS_CRYPTO_RSA_NO_PAD/HITLS_CRYPTO_RSAES_OAEP/HITLS_CRYPTO_RSAES_PKCSV15/"
                    "HITLS_CRYPTO_RSAES_PKCSV15_TLS)"
                )
            endif()
        endif()
        # padding scheme needs encryption/decryption
        if(HITLS_CRYPTO_RSA_NO_PAD OR HITLS_CRYPTO_RSAES_OAEP OR HITLS_CRYPTO_RSAES_PKCSV15 OR HITLS_CRYPTO_RSAES_PKCSV15_TLS)
            if(NOT HITLS_CRYPTO_RSA_ENCRYPT AND NOT HITLS_CRYPTO_RSA_DECRYPT)
                hitls_add_dependency_warning(
                    "[HiTLS] The RSA padding scheme must work with at least one operation. "
                    "(HITLS_CRYPTO_RSA_NO_PAD/HITLS_CRYPTO_RSAES_OAEP/HITLS_CRYPTO_RSAES_PKCSV15/"
                    "HITLS_CRYPTO_RSAES_PKCSV15_TLS)"
                    "(HITLS_CRYPTO_RSA_ENCRYPT/HITLS_CRYPTO_RSA_DECRYPT)"
                )
            endif()
        endif()
        # padding scheme needs sign/verify
        if(HITLS_CRYPTO_RSA_EMSA_PSS OR HITLS_CRYPTO_RSA_EMSA_PKCSV15 OR HITLS_CRYPTO_RSA_EMSA_ISO9796_2)
            if(NOT HITLS_CRYPTO_RSA_SIGN AND NOT HITLS_CRYPTO_RSA_VERIFY)
                hitls_add_dependency_warning(
                    "[HiTLS] The RSA padding scheme must work with RSA signing or verification. "
                    "(HITLS_CRYPTO_RSA_EMSA_PSS/HITLS_CRYPTO_RSA_EMSA_PKCSV15/HITLS_CRYPTO_RSA_EMSA_ISO9796_2)"
                    "(HITLS_CRYPTO_RSA_SIGN/HITLS_CRYPTO_RSA_VERIFY)"
                )
            endif()
        endif()
        # blinding needs sign or verify
        if(HITLS_CRYPTO_RSA_BLINDING AND NOT HITLS_CRYPTO_RSA_DECRYPT AND NOT HITLS_CRYPTO_RSA_SIGN)
            hitls_add_dependency_warning(
                "[HiTLS] The RSA blinding must work with RSA decryption or signing. "
                "(HITLS_CRYPTO_RSA_DECRYPT/HITLS_CRYPTO_RSA_SIGN)"
            )
        endif()
        if(HITLS_CRYPTO_RSA_ENCRYPT AND
            (HITLS_CRYPTO_RSAES_OAEP OR HITLS_CRYPTO_RSAES_PKCSV15) AND NOT HITLS_CRYPTO_DRBG)
            hitls_add_dependency_warning(
                "[HiTLS] The RSA encryption with OAEP or PKCS#1 v1.5 must work with DRBG. (HITLS_CRYPTO_DRBG)"
            )
        endif()
        if(HITLS_CRYPTO_RSA_SIGN AND HITLS_CRYPTO_RSA_EMSA_PSS AND NOT HITLS_CRYPTO_DRBG)
            hitls_add_dependency_warning(
                "[HiTLS] The RSA signature with PSS must work with DRBG. (HITLS_CRYPTO_DRBG)"
            )
        endif()
    endif()

    # ECDH/ECDSA
    if(HITLS_CRYPTO_ECDH OR HITLS_CRYPTO_ECDSA)
        if(NOT HITLS_CRYPTO_CURVE_NISTP192 AND NOT HITLS_CRYPTO_CURVE_NISTP224 AND NOT HITLS_CRYPTO_CURVE_NISTP256 AND
            NOT HITLS_CRYPTO_CURVE_NISTP384 AND NOT HITLS_CRYPTO_CURVE_NISTP521 AND NOT HITLS_CRYPTO_CURVE_BP256R1 AND
            NOT HITLS_CRYPTO_CURVE_BP384R1 AND NOT HITLS_CRYPTO_CURVE_BP512R1)
            hitls_add_dependency_warning(
                "[HiTLS] The ECDH/ECDSA must work with at least one curve. "
                "(HITLS_CRYPTO_ECDH/HITLS_CRYPTO_ECDSA)"
                "(HITLS_CRYPTO_CURVE_NISTP192/HITLS_CRYPTO_CURVE_NISTP224/HITLS_CRYPTO_CURVE_NISTP256/"
                "HITLS_CRYPTO_CURVE_NISTP384/HITLS_CRYPTO_CURVE_NISTP521/HITLS_CRYPTO_CURVE_BP256R1/"
                "HITLS_CRYPTO_CURVE_BP384R1/HITLS_CRYPTO_CURVE_BP512R1)"
            )
        endif()
    endif()

    # Hybrid KEM
    if(HITLS_CRYPTO_HYBRIDKEM AND NOT HITLS_CRYPTO_ECDH AND NOT HITLS_CRYPTO_X25519)
        hitls_add_dependency_warning(
            "[HiTLS] The Hybrid KEM must work with ECDH or X25519. (HITLS_CRYPTO_ECDH/HITLS_CRYPTO_X25519)"
        )
    endif()

    # HPKE
    if(HITLS_CRYPTO_HPKE)
        if(NOT HITLS_CRYPTO_AES AND NOT HITLS_CRYPTO_CHACHA20POLY1305)
            hitls_add_dependency_warning(
                "[HiTLS] The hpke must work with aes or chacha20poly1305. "
                "(HITLS_CRYPTO_AES/HITLS_CRYPTO_CHACHA20POLY1305)"
            )
        endif()
        if(NOT HITLS_CRYPTO_CHACHA20POLY1305 AND HITLS_CRYPTO_AES AND NOT HITLS_CRYPTO_GCM)
            hitls_add_dependency_warning("[HiTLS] The hpke must work with aes-gcm. (HITLS_CRYPTO_GCM)")  
        endif()
        if(NOT HITLS_CRYPTO_CURVE_NISTP256 AND NOT HITLS_CRYPTO_CURVE_NISTP384 AND
            NOT HITLS_CRYPTO_CURVE_NISTP521 AND NOT HITLS_CRYPTO_X25519)
            hitls_add_dependency_warning("[HiTLS] The hpke must work with p256 or p384 or p521 or x25519. "
                "(HITLS_CRYPTO_CURVE_NISTP256/HITLS_CRYPTO_CURVE_NISTP384/HITLS_CRYPTO_CURVE_NISTP521/"
                "HITLS_CRYPTO_X25519)"
            )
        endif()
    endif()


    # --- PKI Check ---
    # x509
    ## x509_csr
    if(HITLS_PKI_X509_CSR_ATTR AND NOT HITLS_PKI_X509_CSR_GEN AND NOT HITLS_PKI_X509_CSR_PARSE)
        hitls_add_dependency_warning(
            "[HiTLS] The x509 csr attribute must work with csr generation or parsing. "
            "(HITLS_PKI_X509_CSR_GEN/HITLS_PKI_X509_CSR_PARSE)"
        )
    endif()
    if(HITLS_PKI_X509_CSR_GET AND NOT HITLS_PKI_X509_CSR_GEN AND NOT HITLS_PKI_X509_CSR_PARSE)
        hitls_add_dependency_warning(
            "[HiTLS] The x509 csr get must work with csr generation or parsing. "
            "(HITLS_PKI_X509_CSR_GEN/HITLS_PKI_X509_CSR_PARSE)"
        )
    endif()

    # info
    if(HITLS_PKI_INFO_CRT AND NOT HITLS_PKI_X509_CRT_GEN AND NOT HITLS_PKI_X509_CRT_PARSE)
        hitls_add_dependency_warning(
            "[HiTLS] The PKI info certificate must work with x509 certificate. "
            "(HITLS_PKI_X509_CRT_GEN/HITLS_PKI_X509_CRT_PARSE)"
        )
    endif()
    if(HITLS_PKI_INFO_CSR AND NOT HITLS_PKI_X509_CSR_GEN AND NOT HITLS_PKI_X509_CSR_PARSE)
        hitls_add_dependency_warning(
            "[HiTLS] The PKI info csr must work with x509 csr. "
            "(HITLS_PKI_X509_CSR_GEN/HITLS_PKI_X509_CSR_PARSE)"
        )
    endif()
    if(HITLS_PKI_INFO_CRL AND NOT HITLS_PKI_X509_CRL_GEN AND NOT HITLS_PKI_X509_CRL_PARSE)
        hitls_add_dependency_warning(
            "[HiTLS] The PKI info crl must work with x509 crl. "
            "(HITLS_PKI_X509_CRL_GEN/HITLS_PKI_X509_CRL_PARSE)"
        )
    endif()


    # --- TLS Check ---
    if(HITLS_TLS_CONFIG_CERT_VERIFY_LOCATION AND HITLS_TLS_CALLBACK_CERT AND NOT HITLS_PKI_X509_VFY_LOCATION)
        hitls_add_dependency_warning(
            "[HiTLS] The tls verify must work with pki vfy location. (HITLS_PKI_X509_VFY_LOCATION)"
        )
    endif()
    if(HITLS_TLS_PROTO_TLS_BASIC AND HITLS_TLS_FEATURE_SESSION_TICKET AND NOT HITLS_TLS_FEATURE_SESSION_ID)
        hitls_add_dependency_warning(
            "[HiTLS] session ticket must work with session id in tls12 and blow. (HITLS_TLS_FEATURE_SESSION_ID)"
        )
    endif()
    if(HITLS_TLS_SUITE_AES_128_GCM_SHA256 OR HITLS_TLS_SUITE_AES_256_GCM_SHA384 OR
        HITLS_TLS_SUITE_CHACHA20_POLY1305_SHA256 OR HITLS_TLS_SUITE_AES_128_CCM_SHA256 OR
        HITLS_TLS_SUITE_AES_128_CCM_8_SHA256)
        if(NOT HITLS_TLS_SUITE_AUTH_RSA AND NOT HITLS_TLS_SUITE_AUTH_ECDSA AND NOT HITLS_TLS_SUITE_AUTH_PSK)
            hitls_add_dependency_warning(
                "[HiTLS] tls13 ciphersuite must work with suite_auth_rsa or suite_auth_ecdsa or suite_auth_psk.
                (HITLS_TLS_SUITE_AUTH_RSA/HITLS_TLS_SUITE_AUTH_ECDSA/HITLS_TLS_SUITE_AUTH_PSK)"
            )
        endif()
    endif()

    if(HITLS_TLS_PROTO_DFX OR HITLS_TLS_PROTO_CLOSE_STATE)
        if(NOT HITLS_TLS_HOST)
            hitls_add_dependency_warning(
                "[HiTLS] The TLS protocol must work with the TLS host. (HITLS_TLS_HOST_CLIENT/HITLS_TLS_HOST_SERVER)"
            )
        endif()
        if(NOT HITLS_BSL_UIO_PLT AND NOT HITLS_BSL_UIO_SCTP AND NOT HITLS_BSL_UIO_TCP AND NOT HITLS_BSL_UIO_UDP)
            hitls_add_dependency_warning(
                "[HiTLS] The TLS protocol must work with at least one UIO. "
                "(HITLS_BSL_UIO_PLT/HITLS_BSL_UIO_SCTP/HITLS_BSL_UIO_TCP/HITLS_BSL_UIO_UDP)"
            )
        endif()
    endif()

    if(HITLS_TLS_FEATURE_PROVIDER OR HITLS_TLS_CALLBACK_CRYPT AND NOT HITLS_CRYPTO_EAL)
        hitls_add_dependency_warning(
            "[HiTLS] The TLS provider or the cryptographic callback must work with the crypto EAL. (HITLS_CRYPTO_EAL)"
        )
    endif()

    if(HITLS_TLS_CONFIG_CIPHER_SUITE AND HITLS_TLS_CAP_NO_STR)
        hitls_add_dependency_warning("[HiTLS] The cipher suite must work with string")
    endif()
endif() # HITLS_NO_CONFIG_CHECK

# Ensure that building the hitls executable only happens if all core libraries are enabled
# since the executable depends on BSL, CRYPTO, PKI, and TLS being available
if(HITLS_BUILD_EXE)
    if(NOT HITLS_BSL OR NOT HITLS_CRYPTO OR NOT HITLS_PKI OR NOT HITLS_TLS)
        hitls_add_dependency_warning(
            "[HiTLS] HITLS_BUILD_EXE=ON requires HITLS_BSL, HITLS_CRYPTO, HITLS_PKI, and HITLS_TLS to all be enabled"
        )
    endif()
endif()

# Automatically validate all ASM-specific crypto features
hitls_check_asm_feature_auto()

# print any warnings about unsatisfied dependencies to the user
hitls_check_dependency_warnings()
