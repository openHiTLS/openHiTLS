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

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "openhitls_async_benchmark requires Linux epoll")
    return()
endif()

set(_async_perf_req
    HITLS_BSL_UIO_TCP
    HITLS_CRYPTO_EALINIT
    HITLS_CRYPTO_PROVIDER
    HITLS_TLS_FEATURE_PROVIDER
    HITLS_TLS_FEATURE_PROVIDER_DYNAMIC
    HITLS_TLS_PROTO_TLS12
    HITLS_TLS_PROTO_TLS13)
foreach(_req ${_async_perf_req})
    if(NOT ${_req})
        message(STATUS
            "openhitls_async_benchmark not built: ${_req}=OFF (requires ${_async_perf_req} all ON)")
        return()
    endif()
endforeach()

set(_async_perf_libs "")
foreach(_c hitls_tls hitls_pki hitls_crypto hitls_bsl)
    # The benchmark MUST link the shared libraries: the simulation provider
    # .so depends on libhitls_crypto.so, so a static link would put two
    # crypto instances in one process (separate provider tables, DRBG state
    # and error stacks) and break the delegated calls.
    if(TARGET ${_c}-shared)
        list(APPEND _async_perf_libs ${_c}-shared)
    else()
        message(STATUS "openhitls_async_benchmark not built: ${_c}-shared required")
        return()
    endif()
endforeach()
if(HITLS_BSL_SAL_DL AND (HITLS_BSL_SAL_LINUX OR HITLS_BSL_SAL_DARWIN))
    list(APPEND _async_perf_libs dl)
endif()
if(UNIX AND NOT APPLE)
    list(APPEND _async_perf_libs pthread)
endif()

add_executable(openhitls_async_benchmark
    app/async_perf_main.c
    app/async_perf_opt.c
    app/sim_link.c
    app/bench_handshake.c
    app/affinity.c)

target_include_directories(openhitls_async_benchmark PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/tls
    ${PROJECT_SOURCE_DIR}/include/bsl
    ${PROJECT_SOURCE_DIR}/include/crypto
    ${PROJECT_SOURCE_DIR}/include/pki
    ${PROJECT_SOURCE_DIR}/config/macro_config
    ${PROJECT_SOURCE_DIR}/bsl/include
    ${PROJECT_SOURCE_DIR}/bsl/sal/include
    ${PROJECT_SOURCE_DIR}/tls/include
    ${PROJECT_SOURCE_DIR}/testcode/framework/async/include)

target_compile_definitions(openhitls_async_benchmark PRIVATE
    HITLS_ASYNC_SIM_PROVIDER_DIR="${PROJECT_SOURCE_DIR}/testcode/output/async_sim_provider"
    _GNU_SOURCE
    HITLS_ASYNC_PERF_CERT_DIR="${PROJECT_SOURCE_DIR}/testcode/testdata/tls/certificate/der")

target_link_libraries(openhitls_async_benchmark PRIVATE ${_async_perf_libs})

add_executable(openhitls_async_client app/client_demo.c)
target_include_directories(openhitls_async_client PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/tls
    ${PROJECT_SOURCE_DIR}/include/bsl
    ${PROJECT_SOURCE_DIR}/include/crypto
    ${PROJECT_SOURCE_DIR}/config/macro_config)
target_link_libraries(openhitls_async_client PRIVATE ${_async_perf_libs})
