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


# Configure the bundle library name and approved provider flags based on CMVP options
# This sets the internal variables that determine whether the build should produce an "approved provider"
#   library (for CMVP compliance), which hash algorithm to use for HMAC in CMVP builds, and what the final 
#   bundle library name should be based on the selected CMVP options.
set(_G_HITLS_APPROVED_PROVIDER OFF)
set(_G_HITLS_CMVP_HAMC_ALG "sha256")
set(_G_HITLS_BUNDLE_LIB_NAME "hitls")
if(HITLS_CRYPTO_CMVP_ISO19790)
    set(_G_HITLS_APPROVED_PROVIDER ON)
    set(_G_HITLS_BUNDLE_LIB_NAME "${_G_HITLS_BUNDLE_LIB_NAME}_iso")
elseif(HITLS_CRYPTO_CMVP_FIPS)
    set(_G_HITLS_BUNDLE_LIB_NAME "${_G_HITLS_BUNDLE_LIB_NAME}_fips")
elseif(HITLS_CRYPTO_CMVP_SM)
    set(_G_HITLS_APPROVED_PROVIDER ON)
    set(_G_HITLS_BUNDLE_LIB_NAME "${_G_HITLS_BUNDLE_LIB_NAME}_sm")
    set(_G_HITLS_CMVP_HAMC_ALG "sm3")
endif()

set(_G_HITLS_LIB_LINK_LIBS)

if(HITLS_BSL_SAL_DL AND (HITLS_BSL_SAL_LINUX OR HITLS_BSL_SAL_DARWIN))
    list(APPEND _G_HITLS_LIB_LINK_LIBS dl)
endif()
if(_G_HITLS_APPROVED_PROVIDER)
    list(APPEND _G_HITLS_LIB_LINK_LIBS m)
endif()

# Initialize object collection CACHE variables
set(_G_HITLS_BSL_OBJECTS "" CACHE INTERNAL "BSL object libraries")
set(_G_HITLS_CRYPTO_OBJECTS "" CACHE INTERNAL "Crypto object libraries")
set(_G_HITLS_TLS_OBJECTS "" CACHE INTERNAL "TLS object libraries")
set(_G_HITLS_PKI_OBJECTS "" CACHE INTERNAL "PKI object libraries")
set(_G_HITLS_AUTH_OBJECTS "" CACHE INTERNAL "Auth object libraries")
set(_G_HITLS_APPS_OBJECTS "" CACHE INTERNAL "Apps object libraries")

# Bundle all libs into a single library if enabled, otherwise build separate libraries for each module
if(HITLS_BUNDLE_LIB)
    project(hitls C ASM)
    set(CMAKE_ASM_NASM_OBJECT_FORMAT elf64)

    set(_all_obj_targets "")
    if(HITLS_BSL)
        add_subdirectory(bsl)
        objects_to_target_objects(_bsl_obj_targets "${_G_HITLS_BSL_OBJECTS}")
        list(APPEND _all_obj_targets ${_bsl_obj_targets})
    endif()
    if(HITLS_CRYPTO)
        add_subdirectory(crypto)
        if(HITLS_CRYPTO_CODECS)
            add_subdirectory(codecs)
        endif()
        objects_to_target_objects(_crypto_obj_targets "${_G_HITLS_CRYPTO_OBJECTS}")
        list(APPEND _all_obj_targets ${_crypto_obj_targets})
    endif()
    if(HITLS_PKI)
        add_subdirectory(pki)
        objects_to_target_objects(_pki_obj_targets "${_G_HITLS_PKI_OBJECTS}")
        list(APPEND _all_obj_targets ${_pki_obj_targets})
    endif()
    if(HITLS_TLS)
        add_subdirectory(tls)
        objects_to_target_objects(_tls_obj_targets "${_G_HITLS_TLS_OBJECTS}")
        list(APPEND _all_obj_targets ${_tls_obj_targets})
    endif()
    if(HITLS_AUTH)
        add_subdirectory(auth)
        objects_to_target_objects(_auth_obj_targets "${_G_HITLS_AUTH_OBJECTS}")
        list(APPEND _all_obj_targets ${_auth_obj_targets})
    endif()

    if(HITLS_BUILD_SHARED)
        hitls_create_shared_library("${_all_obj_targets}" ${_G_HITLS_BUNDLE_LIB_NAME}-shared ${_G_HITLS_BUNDLE_LIB_NAME})
        target_link_libraries(${_G_HITLS_BUNDLE_LIB_NAME}-shared PRIVATE ${_G_HITLS_LIB_LINK_LIBS})
    endif()
    if(HITLS_BUILD_STATIC)
        hitls_create_static_library("${_all_obj_targets}" ${_G_HITLS_BUNDLE_LIB_NAME}-static ${_G_HITLS_BUNDLE_LIB_NAME})
    endif()
else()
    # Add subdirectories for each module (BSL, Crypto, TLS, PKI, Auth)
    if(HITLS_BSL)
        project(hitls_bsl C)
        add_subdirectory(bsl)
        objects_to_target_objects(_bsl_obj_targets "${_G_HITLS_BSL_OBJECTS}")

        if(HITLS_BUILD_SHARED)
            hitls_create_shared_library("${_bsl_obj_targets}" hitls_bsl-shared hitls_bsl)
            target_link_libraries(hitls_bsl-shared PRIVATE ${_G_HITLS_LIB_LINK_LIBS})
        endif()
        if(HITLS_BUILD_STATIC)
            hitls_create_static_library("${_bsl_obj_targets}" hitls_bsl-static hitls_bsl)
        endif()
    endif()
    if(HITLS_CRYPTO)
        project(hitls_crypto C ASM)
        set(CMAKE_ASM_NASM_OBJECT_FORMAT elf64)

        add_subdirectory(crypto)
        if(HITLS_CRYPTO_CODECS)
            add_subdirectory(codecs)
        endif()
        objects_to_target_objects(_crypto_obj_targets "${_G_HITLS_CRYPTO_OBJECTS}")

        if(HITLS_BUILD_SHARED)
            hitls_create_shared_library("${_crypto_obj_targets}" hitls_crypto-shared hitls_crypto)
            target_link_libraries(hitls_crypto-shared PRIVATE hitls_bsl-shared ${_G_HITLS_LIB_LINK_LIBS})
        endif()
        if(HITLS_BUILD_STATIC)
            hitls_create_static_library("${_crypto_obj_targets}" hitls_crypto-static hitls_crypto)
        endif()
    endif()
    if(HITLS_PKI)
        add_subdirectory(pki)
        objects_to_target_objects(_pki_obj_targets "${_G_HITLS_PKI_OBJECTS}")
        project(hitls_pki C)
        if(HITLS_BUILD_SHARED)
            hitls_create_shared_library("${_pki_obj_targets}" hitls_pki-shared hitls_pki)
            target_link_libraries(hitls_pki-shared PRIVATE hitls_crypto-shared hitls_bsl-shared ${_G_HITLS_LIB_LINK_LIBS})
        endif()
        if(HITLS_BUILD_STATIC)
            hitls_create_static_library("${_pki_obj_targets}" hitls_pki-static hitls_pki)
        endif()
    endif()
    if(HITLS_TLS)
        project(hitls_tls C)
        add_subdirectory(tls)
        objects_to_target_objects(_tls_obj_targets "${_G_HITLS_TLS_OBJECTS}")
        set(_tgt_links "")
        if(HITLS_PKI)
            list(APPEND _tgt_links hitls_pki-shared)
        endif()
        list(APPEND _tgt_links hitls_crypto-shared hitls_bsl-shared)
        if(HITLS_BUILD_SHARED)
            hitls_create_shared_library("${_tls_obj_targets}" hitls_tls-shared hitls_tls)
            target_link_libraries(hitls_tls-shared PRIVATE ${_tgt_links} ${_G_HITLS_LIB_LINK_LIBS})
        endif()
        if(HITLS_BUILD_STATIC)
            hitls_create_static_library("${_tls_obj_targets}" hitls_tls-static hitls_tls)
        endif()
    endif()
    if(HITLS_AUTH)
        project(hitls_auth C)
        add_subdirectory(auth)
        objects_to_target_objects(_auth_obj_targets "${_G_HITLS_AUTH_OBJECTS}")
        if(HITLS_BUILD_SHARED)
            hitls_create_shared_library("${_auth_obj_targets}" hitls_auth-shared hitls_auth)
            target_link_libraries(hitls_auth-shared PRIVATE hitls_crypto-shared hitls_bsl-shared ${_G_HITLS_LIB_LINK_LIBS})
        endif()
        if(HITLS_BUILD_STATIC)
            hitls_create_static_library("${_auth_obj_targets}" hitls_auth-static hitls_auth)
        endif()
    endif()

    if(HITLS_BUILD_EXE)
        project(hitls_auth C)

        # Detect platform-specific shared library extension
        if(APPLE)
            set(SHARED_LIB_EXT ".dylib")
        else()
            set(SHARED_LIB_EXT ".so")
        endif()

        # Dynamically determine provider library name based on CMVP mode
        set(_hitls_provider_lib_name "libhitls${SHARED_LIB_EXT}")

        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHITLS_VERSION='\"${OPENHITLS_VERSION_S}\"'")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHITLS_PROVIDER_LIB_NAME='\"${_hitls_provider_lib_name}\"'")

        add_subdirectory(apps)
        objects_to_target_objects(_apps_obj_targets "${_G_HITLS_APPS_OBJECTS}")

        hitls_create_executable("${_apps_obj_targets}" hitls)
        if(HITLS_BUILD_SHARED)
            target_link_libraries(hitls PRIVATE
                hitls_tls-shared hitls_pki-shared hitls_crypto-shared hitls_bsl-shared
                dl pthread m
            )
        elseif(HITLS_BUILD_STATIC)
            target_link_libraries(hitls PRIVATE
                hitls_tls-static hitls_pki-static hitls_crypto-static hitls_bsl-static
                dl pthread m
            )
        endif()
    endif()
endif()
