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

# frame_async: test-framework side of the simulation provider. Consumed by the
# SDV build through TEST_INTF; the provider .so itself is built by the
# standalone project in provider/ via build_sdv.sh (D1).

set(FRAME_ASYNC_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/frame_async.c)

add_library(frame_async STATIC ${FRAME_ASYNC_SRC})
target_include_directories(frame_async PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(frame_async PRIVATE
    ${openHiTLS_SRC}/include
    ${openHiTLS_SRC}/include/bsl
    ${openHiTLS_SRC}/include/crypto
    ${openHiTLS_SRC}/include/tls
    ${openHiTLS_SRC}/config/macro_config
    # driving group: TLS_CONNECTED / HITLS_GetHandShakeState live in the
    # internal tls.h (the SDV test framework's established convention)
    ${openHiTLS_SRC}/tls/include
    ${openHiTLS_SRC}/tls/handshake/common/include
    ${openHiTLS_SRC}/tls/config/include
    ${openHiTLS_SRC}/tls/cert/include
    ${openHiTLS_SRC}/crypto/cipher/include
    ${openHiTLS_SRC}/bsl/sal/include
)
set_target_properties(frame_async PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${openHiTLS_SRC}/testcode/output/lib"
)

# Compile-time location of the built provider .so directory (D1); the
# environment variable HITLS_ASYNC_SIM_PROVIDER_PATH takes precedence at
# runtime.
target_compile_definitions(frame_async PUBLIC
    HITLS_ASYNC_SIM_PROVIDER_DIR="${openHiTLS_SRC}/testcode/output/async_sim_provider")
