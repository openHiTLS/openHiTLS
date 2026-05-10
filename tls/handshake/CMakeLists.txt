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


set(source_dir ${CMAKE_CURRENT_SOURCE_DIR})
# common
set(_handshake_sources_common
    ${source_dir}/common/src/hs_cert.c
    ${source_dir}/common/src/hs_comp.c
    ${source_dir}/common/src/hs_common.c
    ${source_dir}/common/src/hs_kx.c
    ${source_dir}/common/src/hs_verify.c
    ${source_dir}/common/src/transcript_hash.c
)
if(HITLS_TLS_PROTO_TLS13)
    list(APPEND _handshake_sources_common ${source_dir}/common/src/tls13key.c)
endif()
if(HITLS_TLS_PROTO_DTLS12 AND HITLS_BSL_UIO_UDP)
    list(APPEND _handshake_sources_common ${source_dir}/common/src/hs_dtls_timer.c)
endif()

# cookie
set(_handshake_sources_cookie)
if(HITLS_TLS_PROTO_DTLS12 AND HITLS_BSL_UIO_UDP)
    list(APPEND _handshake_sources_cookie ${source_dir}/cookie/src/hs_cookie.c)
endif()

# pack
set(_handshake_sources_pack
    ${source_dir}/pack/src/pack.c
    ${source_dir}/pack/src/pack_certificate.c
    ${source_dir}/pack/src/pack_common.c
    ${source_dir}/pack/src/pack_extensions.c
    ${source_dir}/pack/src/pack_finished.c
)
if(HITLS_TLS_PROTO_TLS13 AND HITLS_TLS_HOST_SERVER)
    list(APPEND _handshake_sources_pack ${source_dir}/pack/src/pack_encrypted_extensions.c)
endif()
if(HITLS_TLS_HOST_CLIENT)
    list(APPEND _handshake_sources_pack
        ${source_dir}/pack/src/pack_client_hello.c
        ${source_dir}/pack/src/pack_client_key_exchange.c
    )
endif()
if(HITLS_TLS_HOST_SERVER)
    list(APPEND _handshake_sources_pack
        ${source_dir}/pack/src/pack_server_hello.c
        ${source_dir}/pack/src/pack_server_key_exchange.c
    )
endif()
if(HITLS_TLS_HOST_CLIENT OR HITLS_TLS_PROTO_TLS13)
    list(APPEND _handshake_sources_pack ${source_dir}/pack/src/pack_certificate_verify.c)
endif()
if(HITLS_TLS_HOST_SERVER AND HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY)
    list(APPEND _handshake_sources_pack ${source_dir}/pack/src/pack_certificate_request.c)
endif()
if(HITLS_TLS_FEATURE_KEY_UPDATE)
    list(APPEND _handshake_sources_pack ${source_dir}/pack/src/pack_key_update.c)
endif()
if(HITLS_TLS_FEATURE_SESSION_TICKET AND HITLS_TLS_HOST_SERVER)
    list(APPEND _handshake_sources_pack ${source_dir}/pack/src/pack_new_session_ticket.c)
endif()
if(HITLS_TLS_PROTO_DTLS12 AND HITLS_BSL_UIO_UDP AND HITLS_TLS_HOST_SERVER)
    list(APPEND _handshake_sources_pack ${source_dir}/pack/src/pack_hello_verify_request.c)
endif()

# parse
set(_handshake_sources_parse
    ${source_dir}/parse/src/parse.c
    ${source_dir}/parse/src/parse_certificate.c
    ${source_dir}/parse/src/parse_common.c
    ${source_dir}/parse/src/parse_extensions.c
    ${source_dir}/parse/src/parse_finished.c
)
if(HITLS_TLS_PROTO_TLS13 AND HITLS_TLS_HOST_CLIENT)
    list(APPEND _handshake_sources_parse ${source_dir}/parse/src/parse_encrypted_extensions.c)
endif()
if(HITLS_TLS_HOST_CLIENT)
    list(APPEND _handshake_sources_parse
        ${source_dir}/parse/src/parse_certificate_request.c
        ${source_dir}/parse/src/parse_extensions_client.c
        ${source_dir}/parse/src/parse_server_hello.c
        ${source_dir}/parse/src/parse_server_key_exchange.c
    )
endif()
if(HITLS_TLS_HOST_SERVER)
    list(APPEND _handshake_sources_parse
        ${source_dir}/parse/src/parse_client_hello.c
        ${source_dir}/parse/src/parse_client_key_exchange.c
        ${source_dir}/parse/src/parse_extensions_server.c
    )
endif()
if((HITLS_TLS_HOST_SERVER AND HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY) OR HITLS_TLS_PROTO_TLS13)
    list(APPEND _handshake_sources_parse ${source_dir}/parse/src/parse_certificate_verify.c)
endif()
if(HITLS_TLS_FEATURE_KEY_UPDATE)
    list(APPEND _handshake_sources_parse ${source_dir}/parse/src/parse_key_update.c)
endif()
if(HITLS_TLS_FEATURE_SESSION_TICKET AND HITLS_TLS_HOST_CLIENT)
    list(APPEND _handshake_sources_parse ${source_dir}/parse/src/parse_new_session_ticket.c)
endif()
if(HITLS_TLS_PROTO_DTLS12 AND HITLS_TLS_HOST_CLIENT)
    list(APPEND _handshake_sources_parse ${source_dir}/parse/src/parse_hello_verify_request.c)
endif()

# reass
set(_handshake_sources_reass)
if(HITLS_TLS_PROTO_DTLS12)
    list(APPEND _handshake_sources_reass ${source_dir}/reass/src/hs_reass.c)
endif()

# recv
set(_handshake_sources_recv
    ${source_dir}/recv/src/hs_state_recv.c
    ${source_dir}/recv/src/recv_certificate.c
    ${source_dir}/recv/src/recv_finished.c
)
if(HITLS_TLS_PROTO_TLS13)
    list(APPEND _handshake_sources_recv ${source_dir}/recv/src/recv_encrypted_extensions.c)
endif()
if(HITLS_TLS_HOST_CLIENT)
    list(APPEND _handshake_sources_recv
        ${source_dir}/recv/src/recv_cert_request.c
        ${source_dir}/recv/src/recv_server_hello.c
        ${source_dir}/recv/src/recv_server_hello_done.c
        ${source_dir}/recv/src/recv_server_key_exchange.c
    )
endif()
if(HITLS_TLS_HOST_SERVER)
    list(APPEND _handshake_sources_recv
        ${source_dir}/recv/src/recv_client_hello.c
        ${source_dir}/recv/src/recv_client_key_exchange.c
    )
endif()
if((HITLS_TLS_HOST_SERVER AND HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY) OR HITLS_TLS_PROTO_TLS13)
    list(APPEND _handshake_sources_recv ${source_dir}/recv/src/recv_cert_verify.c)
endif()
if(HITLS_TLS_FEATURE_SESSION_TICKET)
    list(APPEND _handshake_sources_recv ${source_dir}/recv/src/recv_new_session_ticket.c)
endif()
if(HITLS_TLS_PROTO_DTLS12 AND HITLS_TLS_HOST_CLIENT)
    list(APPEND _handshake_sources_recv ${source_dir}/recv/src/recv_hello_verify_request.c)
endif()

# send
set(_handshake_sources_send
    ${source_dir}/send/src/hs_state_send.c
    ${source_dir}/send/src/send_certificate.c
    ${source_dir}/send/src/send_change_cipher_spec.c
    ${source_dir}/send/src/send_common.c
    ${source_dir}/send/src/send_finished.c
)
if(HITLS_TLS_PROTO_TLS13 AND HITLS_TLS_HOST_SERVER)
    list(APPEND _handshake_sources_send ${source_dir}/send/src/send_encrypted_extensions.c)
endif()
if(HITLS_TLS_HOST_CLIENT)
    list(APPEND _handshake_sources_send
        ${source_dir}/send/src/send_client_hello.c
        ${source_dir}/send/src/send_client_key_exchange.c
    )
endif()
if(HITLS_TLS_HOST_SERVER)
    list(APPEND _handshake_sources_send
        ${source_dir}/send/src/send_server_hello.c
        ${source_dir}/send/src/send_server_hello_done.c
        ${source_dir}/send/src/send_server_key_exchange.c
    )
endif()
if(HITLS_TLS_HOST_CLIENT OR HITLS_TLS_PROTO_TLS13)
    list(APPEND _handshake_sources_send ${source_dir}/send/src/send_cert_verify.c)
endif()
if(HITLS_TLS_HOST_SERVER AND HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY)
    list(APPEND _handshake_sources_send ${source_dir}/send/src/send_cert_request.c)
endif()
if(HITLS_TLS_FEATURE_SESSION_TICKET AND HITLS_TLS_HOST_SERVER)
    list(APPEND _handshake_sources_send ${source_dir}/send/src/send_new_session_ticket.c)
endif()
if(HITLS_TLS_FEATURE_RENEGOTIATION)
    list(APPEND _handshake_sources_send ${source_dir}/send/src/send_hello_request.c)
endif()
if(HITLS_TLS_PROTO_DTLS12 AND HITLS_BSL_UIO_UDP AND HITLS_TLS_HOST_SERVER)
    list(APPEND _handshake_sources_send ${source_dir}/send/src/send_hello_verify_request.c)
endif()

# sm
set(_handshake_sources_sm
    ${source_dir}/sm/src/hs_init.c
    ${source_dir}/sm/src/hs_sm.c
)


set(_handshake_sources
    ${_handshake_sources_common} ${_handshake_sources_cookie}
    ${_handshake_sources_pack} ${_handshake_sources_parse}
    ${_handshake_sources_reass} ${_handshake_sources_recv}
    ${_handshake_sources_send} ${_handshake_sources_sm}
)

add_library(_hitls_tls_handshake OBJECT ${_handshake_sources})

target_link_libraries(_hitls_tls_handshake
    PUBLIC
        _hitls_tls_common_include)

target_include_directories(_hitls_tls_handshake
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/common/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cookie/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/pack/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/parse/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/reass/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/recv/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/send/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sm/include>
    PRIVATE
        ${PROJECT_SOURCE_DIR}/tls/alert/include
        ${PROJECT_SOURCE_DIR}/tls/cert/include
        ${PROJECT_SOURCE_DIR}/tls/config/include
        ${PROJECT_SOURCE_DIR}/tls/crypt/include
        ${PROJECT_SOURCE_DIR}/tls/record/include
        ${PROJECT_SOURCE_DIR}/tls/record/src
        ${CMAKE_CURRENT_SOURCE_DIR}/parse/src
)

hitls_register_objects(TLS _hitls_tls_handshake)
