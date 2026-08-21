/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* BEGIN_HEADER */
/* INCLUDE_BASE test_suite_sdv_quic_tls */
#include "hs_ctx.h"
#include "quic_tls_internal.h"
#include "stub_utils.h"
#include "tls.h"
/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
STUB_DEFINE_RET2(void *, BSL_SAL_Calloc, uint32_t, uint32_t);
STUB_DEFINE_RET3(void *, BSL_SAL_Realloc, void *, uint32_t, uint32_t);

static void *QuicTlsTestMallocFail(uint32_t size)
{
    (void)size;
    return NULL;
}

static void *QuicTlsTestCallocFail(uint32_t count, uint32_t size)
{
    (void)count;
    (void)size;
    return NULL;
}

static void *QuicTlsTestReallocFail(void *address, uint32_t newSize, uint32_t oldSize)
{
    (void)address;
    (void)newSize;
    (void)oldSize;
    return NULL;
}

static const HITLS_QUIC_TLS_Callbacks g_quicTestIncompleteDispatch[] = {
    {HITLS_QUIC_TLS_FUNC_SET_READ_SECRET, (void *)QuicTlsTestSetReadSecret},
    HITLS_QUIC_TLS_CALLBACKS_END
};

static const HITLS_QUIC_TLS_Callbacks g_quicTestNullCallbackDispatch[] = {
    {HITLS_QUIC_TLS_FUNC_SET_READ_SECRET, NULL},
    {HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET, (void *)QuicTlsTestSetWriteSecret},
    {HITLS_QUIC_TLS_FUNC_ADD_HANDSHAKE_DATA, (void *)QuicTlsTestAddHandshakeData},
    {HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT, (void *)QuicTlsTestFlushFlight},
    {HITLS_QUIC_TLS_FUNC_SEND_ALERT, (void *)QuicTlsTestSendAlert},
    HITLS_QUIC_TLS_CALLBACKS_END
};

static const HITLS_QUIC_TLS_Callbacks g_quicTestUnknownIdDispatch[] = {
    {9999, (void *)QuicTlsTestFlushFlight},
    {HITLS_QUIC_TLS_FUNC_SET_READ_SECRET, (void *)QuicTlsTestSetReadSecret},
    {HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET, (void *)QuicTlsTestSetWriteSecret},
    {HITLS_QUIC_TLS_FUNC_ADD_HANDSHAKE_DATA, (void *)QuicTlsTestAddHandshakeData},
    {HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT, (void *)QuicTlsTestFlushFlight},
    {HITLS_QUIC_TLS_FUNC_SEND_ALERT, (void *)QuicTlsTestSendAlert},
    HITLS_QUIC_TLS_CALLBACKS_END
};

/**
 * @test SDV_TLS_QUIC_API_SET_METHOD_FUNC_TC001
 * @title Validate QUIC method installation, completeness, protocol and state constraints
 * @precon TLS feature QUIC is enabled
 * @brief Install complete, incomplete and invalid callback dispatch tables on stream TLS contexts.
 * @expect A complete dispatch succeeds on an idle stream TLS context; the handshake later enforces TLS 1.3.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_API_SET_METHOD_FUNC_TC001(void)
{
    HITLS_Config *tls13Config = NULL;
    HITLS_Config *tls12Config = NULL;
    HITLS_Ctx *tls13 = NULL;
    HITLS_Ctx *tls12 = NULL;
    QuicTlsTestEndpoint endpoint = {0};
    bool phaSupport = false;

    FRAME_Init();
    tls13Config = HITLS_CFG_NewTLS13Config();
    tls12Config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tls13Config != NULL);
    ASSERT_TRUE(tls12Config != NULL);
    ASSERT_EQ(HITLS_CFG_SetPostHandshakeAuthSupport(tls13Config, true), HITLS_SUCCESS);
    tls13 = HITLS_New(tls13Config);
    tls12 = HITLS_New(tls12Config);
    ASSERT_TRUE(tls13 != NULL);
    ASSERT_TRUE(tls12 != NULL);
    ASSERT_EQ(HITLS_GetPostHandshakeAuthSupport(tls13, &phaSupport), HITLS_SUCCESS);
    ASSERT_TRUE(phaSupport);

    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(NULL, g_quicTestDispatch, &endpoint), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(tls13, NULL, &endpoint), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(tls13, g_quicTestIncompleteDispatch, &endpoint),
        HITLS_UNREGISTERED_CALLBACK);
    ASSERT_EQ(HITLS_GetPostHandshakeAuthSupport(tls13, &phaSupport), HITLS_SUCCESS);
    ASSERT_TRUE(phaSupport);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(tls13, g_quicTestNullCallbackDispatch, &endpoint),
        HITLS_UNREGISTERED_CALLBACK);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(tls12, g_quicTestDispatch, &endpoint), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(tls13, g_quicTestUnknownIdDispatch, &endpoint), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetPostHandshakeAuthSupport(tls13, &phaSupport), HITLS_SUCCESS);
    ASSERT_TRUE(!phaSupport);
    ASSERT_EQ(HITLS_SetPostHandshakeAuthSupport(tls13, true), HITLS_CONFIG_UNSUPPORT);
    ASSERT_EQ(HITLS_SetPostHandshakeAuthSupport(tls13, false), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(tls13, g_quicTestDispatch, &endpoint), HITLS_SUCCESS);

EXIT:
    HITLS_Free(tls13);
    HITLS_Free(tls12);
    HITLS_CFG_FreeConfig(tls13Config);
    HITLS_CFG_FreeConfig(tls12Config);
    QuicTlsTestEndpointFree(&endpoint);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_API_PROVIDE_DATA_FUNC_TC001
 * @title Validate QUIC CRYPTO input arguments, encryption level and buffer limit
 * @precon An idle TLS 1.3 connection has a QUIC method installed
 * @brief Push empty, wrong-level, maximum-size and overflowing CRYPTO input.
 * @expect Valid current-level data is accepted; invalid input and overflow are rejected.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_API_PROVIDE_DATA_FUNC_TC001(void)
{
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_Ctx *plainCtx = NULL;
    QuicTlsTestEndpoint endpoint = {0};
    uint8_t *data = NULL;
    uint8_t one = 0u;
    size_t limit;

    FRAME_Init();
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    plainCtx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(plainCtx != NULL);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(ctx, g_quicTestDispatch, &endpoint), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(NULL, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL, NULL, 0u),
        HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL, NULL, 1u),
        HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(plainCtx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL, NULL, 0u),
        HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE, &one, 1u),
        HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, (HITLS_QUIC_TLS_EncryptionLevel)QUIC_TEST_LEVEL_COUNT, &one, 1u),
        HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL, NULL, 0u), HITLS_SUCCESS);

    limit = HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    ASSERT_TRUE(limit != 0u);
    data = (uint8_t *)calloc(1u, limit);
    ASSERT_TRUE(data != NULL);
    ASSERT_TRUE(limit > 8u * 1024u + 1u);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL, data, 1u), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL,
        data + 1u, 8u * 1024u), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL,
        data + 1u + 8u * 1024u, limit - 1u - 8u * 1024u), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL, &one, 1u),
        HITLS_REC_RECORD_OVERFLOW);

EXIT:
    free(data);
    HITLS_Free(ctx);
    HITLS_Free(plainCtx);
    HITLS_CFG_FreeConfig(config);
    QuicTlsTestEndpointFree(&endpoint);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_API_ALLOC_FAILURE_FUNC_TC001
 * @title Propagate allocation failures from QUIC context and owned input buffers
 * @precon An idle TLS 1.3 connection has no QUIC method installed
 * @brief Fail the context allocation, CRYPTO input growth and transport-parameter copy one at a time.
 * @expect Each public API returns HITLS_MEMALLOC_FAIL without retaining a partial allocation.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_API_ALLOC_FAILURE_FUNC_TC001(void)
{
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    QuicTlsTestEndpoint endpoint = {0};
    uint8_t value[] = {1u, 2u, 3u};

    FRAME_Init();
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    STUB_REPLACE(BSL_SAL_Calloc, QuicTlsTestCallocFail);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(ctx, g_quicTestDispatch, &endpoint), HITLS_MEMALLOC_FAIL);
    ASSERT_TRUE(((TLS_Ctx *)ctx)->quicTlsCtx == NULL);
    STUB_RESTORE(BSL_SAL_Calloc);

    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(ctx, g_quicTestDispatch, &endpoint), HITLS_SUCCESS);
    STUB_REPLACE(BSL_SAL_Realloc, QuicTlsTestReallocFail);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL,
        value, sizeof(value)), HITLS_MEMALLOC_FAIL);
    ASSERT_EQ(((TLS_Ctx *)ctx)->quicTlsCtx->input[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL].capacity, 0u);
    STUB_RESTORE(BSL_SAL_Realloc);

    STUB_REPLACE(BSL_SAL_Malloc, QuicTlsTestMallocFail);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(ctx, value, sizeof(value)), HITLS_MEMALLOC_FAIL);
    ASSERT_TRUE(((TLS_Ctx *)ctx)->quicTlsCtx->localTransportParams == NULL);

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    STUB_RESTORE(BSL_SAL_Calloc);
    STUB_RESTORE(BSL_SAL_Realloc);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    QuicTlsTestEndpointFree(&endpoint);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_API_BUFFER_REUSE_FUNC_TC001
 * @title Reuse consumed QUIC CRYPTO input space before and during buffer growth
 * @precon An idle TLS 1.3 connection has a QUIC method installed
 * @brief Append data after advancing the internal read cursor, first within the current allocation and then while
 *        growing it.
 * @expect Live bytes are compacted to the front in order, new bytes are appended intact, and oversized size_t input
 *         is rejected before the source pointer is read.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_API_BUFFER_REUSE_FUNC_TC001(void)
{
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    QuicTlsTestEndpoint endpoint = {0};
    QUIC_TLS_InputBuffer *buffer = NULL;
    uint8_t first[4096u];
    uint8_t second[2048u];
    uint8_t third[4096u];
    uint32_t i;

    FRAME_Init();
    for (i = 0u; i < sizeof(first); ++i) {
        first[i] = (uint8_t)i;
    }
    (void)memset(second, 0xa5, sizeof(second));
    (void)memset(third, 0x5a, sizeof(third));
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(ctx, g_quicTestDispatch, &endpoint), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL,
        first, sizeof(first)), HITLS_SUCCESS);
    buffer = &((TLS_Ctx *)ctx)->quicTlsCtx->input[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL];
    ASSERT_EQ(buffer->capacity, sizeof(first));
    buffer->offset = 3072u; /* Simulate TLS consuming the first three quarters of the CRYPTO stream. */
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL,
        second, sizeof(second)), HITLS_SUCCESS);
    ASSERT_EQ(buffer->offset, 0u);
    ASSERT_EQ(buffer->length, 1024u + sizeof(second));
    ASSERT_EQ(memcmp(buffer->data, first + 3072u, 1024u), 0);
    ASSERT_EQ(memcmp(buffer->data + 1024u, second, sizeof(second)), 0);

    buffer->offset = 1024u; /* The remaining 2048 bytes require compaction while the allocation grows. */
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL,
        third, sizeof(third)), HITLS_SUCCESS);
    ASSERT_TRUE(buffer->capacity > sizeof(first));
    ASSERT_EQ(buffer->offset, 0u);
    ASSERT_EQ(buffer->length, sizeof(second) + sizeof(third));
    ASSERT_EQ(memcmp(buffer->data, second, sizeof(second)), 0);
    ASSERT_EQ(memcmp(buffer->data + sizeof(second), third, sizeof(third)), 0);

    if (sizeof(size_t) > sizeof(uint32_t)) {
        ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(ctx, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL,
            third, (size_t)UINT32_MAX + 1u), HITLS_REC_RECORD_OVERFLOW);
    }

EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    QuicTlsTestEndpointFree(&endpoint);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_API_FLIGHT_SWITCH_FUNC_TC001
 * @title The flight-transmit switch cannot be enabled on a QUIC connection
 * @precon An idle TLS 1.3 connection with a QUIC method installed and a plain TLS connection
 * @brief Enable and disable the flight-transmit switch on both connections.
 * @expect Enabling on the QUIC connection is rejected with HITLS_CONFIG_UNSUPPORT and the
 *         switch stays off; disabling on the QUIC connection and both operations on the
 *         plain connection succeed.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_API_FLIGHT_SWITCH_FUNC_TC001(void)
{
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_Ctx *plainCtx = NULL;
    QuicTlsTestEndpoint endpoint = {0};
    bool isEnabled = true;

    FRAME_Init();
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    plainCtx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(plainCtx != NULL);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(ctx, g_quicTestDispatch, &endpoint), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(NULL, true), HITLS_NULL_INPUT);
    /* Enabling on a QUIC connection is rejected and leaves the switch off. */
    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(ctx, true), HITLS_CONFIG_UNSUPPORT);
    ASSERT_EQ(HITLS_GetFlightTransmitSwitch(ctx, &isEnabled), HITLS_SUCCESS);
    ASSERT_TRUE(isEnabled == false);
    /* Disabling on a QUIC connection is a harmless no-op that keeps the invariant. */
    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(ctx, false), HITLS_SUCCESS);
    /* A non-QUIC connection is unaffected by the guard. */
    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(plainCtx, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetFlightTransmitSwitch(plainCtx, &isEnabled), HITLS_SUCCESS);
    ASSERT_TRUE(isEnabled == true);
    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(plainCtx, false), HITLS_SUCCESS);

EXIT:
    HITLS_Free(ctx);
    HITLS_Free(plainCtx);
    HITLS_CFG_FreeConfig(config);
    QuicTlsTestEndpointFree(&endpoint);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_API_TRANSPORT_PARAMS_FUNC_TC001
 * @title Validate transport-parameter setter and peer getter contracts
 * @precon An idle TLS 1.3 connection is available
 * @brief Exercise null arguments, rejected empty parameters, replacement, size overflow and pre-handshake lookup.
 * @expect Each API returns its documented status without exposing unset peer parameters.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_API_TRANSPORT_PARAMS_FUNC_TC001(void)
{
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_Ctx *plainCtx = NULL;
    QuicTlsTestEndpoint endpoint = {0};
    const uint8_t *params = (const uint8_t *)(uintptr_t)1u;
    size_t paramsLen = 1u;
    uint8_t value[] = {1u, 2u, 3u};

    FRAME_Init();
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    plainCtx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(plainCtx != NULL);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(ctx, g_quicTestDispatch, &endpoint), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(NULL, value, sizeof(value)), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(ctx, NULL, 1u), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(plainCtx, value, sizeof(value)),
        HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(ctx, NULL, 0u), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(ctx, value, 0u), HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(ctx, value, sizeof(value)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(ctx, value, (size_t)UINT16_MAX + 1u),
        HITLS_INVALID_INPUT);

    ASSERT_EQ(HITLS_QUIC_TLS_GetPeerTransportParams(NULL, &params, &paramsLen), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_GetPeerTransportParams(ctx, NULL, &paramsLen), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_GetPeerTransportParams(ctx, &params, NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_GetPeerTransportParams(plainCtx, &params, &paramsLen),
        HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(HITLS_QUIC_TLS_GetPeerTransportParams(ctx, &params, &paramsLen), HITLS_SUCCESS);
    ASSERT_TRUE(params == NULL);
    ASSERT_EQ(paramsLen, 0u);

EXIT:
    HITLS_Free(ctx);
    HITLS_Free(plainCtx);
    HITLS_CFG_FreeConfig(config);
    QuicTlsTestEndpointFree(&endpoint);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_API_LEVEL_AND_LIMIT_FUNC_TC001
 * @title Query QUIC encryption levels and per-level handshake limits
 * @precon None
 * @brief Query all levels before the endpoint role is committed with maxCertList set to UINT32_MAX.
 * @expect The idle Handshake limit uses two bounded messages and is not enlarged by maxCertList.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_API_LEVEL_AND_LIMIT_FUNC_TC001(void)
{
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;

    FRAME_Init();
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetMaxCertList(config, UINT32_MAX), HITLS_SUCCESS);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(HITLS_QUIC_TLS_GetReadLevel(NULL), HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    ASSERT_EQ(HITLS_QUIC_TLS_GetWriteLevel(NULL), HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    ASSERT_EQ(HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(NULL,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE), 0u);
    ASSERT_EQ(HITLS_QUIC_TLS_GetReadLevel(ctx), HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    ASSERT_EQ(HITLS_QUIC_TLS_GetWriteLevel(ctx), HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    ASSERT_EQ(HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(ctx,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL), QUIC_TLS_DEFAULT_LEVEL_DATA_LIMIT);
    ASSERT_EQ(HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(ctx,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE), 2u * HITLS_HS_BUFFER_SIZE_LIMIT);
    ASSERT_EQ(HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(ctx,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION), QUIC_TLS_DEFAULT_LEVEL_DATA_LIMIT);
    ASSERT_EQ(HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(ctx,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_EARLY_DATA), 0u);
    ASSERT_EQ(HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(ctx,
        (HITLS_QUIC_TLS_EncryptionLevel)QUIC_TEST_LEVEL_COUNT), 0u);

EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_API_INTERNAL_GUARDS_FUNC_TC001
 * @title Validate QUIC context, cipher-suite and traffic-secret guards
 * @precon Idle QUIC and plain TLS 1.3 contexts exist
 * @brief Exercise context reset/query boundaries, the QUIC cipher whitelist, invalid secret mapping, callback
 *        failure, successful level switches and duplicate secret installation.
 * @expect Invalid state is rejected without changing levels; supported secrets advance exactly once and unsupported
 *         QUIC cipher suites are rejected without restricting plain TLS.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_API_INTERNAL_GUARDS_FUNC_TC001(void)
{
    static const uint16_t supportedSuites[] = {
        HITLS_AES_128_GCM_SHA256,
        HITLS_AES_256_GCM_SHA384,
        HITLS_CHACHA20_POLY1305_SHA256,
        HITLS_AES_128_CCM_SHA256
    };
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_Ctx *plainCtx = NULL;
    TLS_Ctx *tlsCtx = NULL;
    QUIC_TLS_Ctx *standalone = NULL;
    QuicTlsTestEndpoint endpoint = {0};
    uint8_t copiedSecret[32u] = {0};
    uint32_t i;

    FRAME_Init();
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    plainCtx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(plainCtx != NULL);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(ctx, g_quicTestDispatch, &endpoint), HITLS_SUCCESS);
    tlsCtx = (TLS_Ctx *)ctx;

    standalone = QUIC_TLS_CtxNew();
    ASSERT_TRUE(standalone != NULL);
    ASSERT_EQ(standalone->readLevel, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    ASSERT_EQ(standalone->writeLevel, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    ASSERT_TRUE(!QUIC_TLS_BufferHasData(NULL, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL));
    ASSERT_TRUE(!QUIC_TLS_BufferHasData(standalone,
        (HITLS_QUIC_TLS_EncryptionLevel)QUIC_TEST_LEVEL_COUNT));
    standalone->input[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL].length = 1u;
    ASSERT_TRUE(QUIC_TLS_BufferHasData(standalone, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL));
    standalone->input[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL].offset = 1u;
    ASSERT_TRUE(!QUIC_TLS_BufferHasData(standalone, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL));
    QUIC_TLS_CtxReset(standalone);
    ASSERT_EQ(standalone->input[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL].length, 0u);
    QUIC_TLS_CtxReset(NULL);
    QUIC_TLS_CtxFree(NULL);

    ASSERT_TRUE(QUIC_TLS_IsCipherSuiteSupported((TLS_Ctx *)plainCtx, HITLS_AES_128_CCM_8_SHA256));
    for (i = 0u; i < sizeof(supportedSuites) / sizeof(supportedSuites[0]); ++i) {
        ASSERT_TRUE(QUIC_TLS_IsCipherSuiteSupported(tlsCtx, supportedSuites[i]));
    }
    ASSERT_TRUE(!QUIC_TLS_IsCipherSuiteSupported(tlsCtx, HITLS_AES_128_CCM_8_SHA256));

    ASSERT_EQ(QUIC_TLS_SetTrafficSecret(NULL, copiedSecret, sizeof(copiedSecret), true),
        HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(QUIC_TLS_SetTrafficSecret((TLS_Ctx *)plainCtx, copiedSecret, sizeof(copiedSecret), true),
        HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(QUIC_TLS_SetTrafficSecret(tlsCtx, NULL, sizeof(copiedSecret), true),
        HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(QUIC_TLS_SetTrafficSecret(tlsCtx, copiedSecret, 0u, true),
        HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(QUIC_TLS_SetTrafficSecret(tlsCtx, copiedSecret, sizeof(copiedSecret), true),
        HITLS_CONFIG_UNSUPPORT);

    endpoint.failCallbackId = HITLS_QUIC_TLS_FUNC_SET_READ_SECRET;
    ASSERT_EQ(QUIC_TLS_SetTrafficSecret(tlsCtx, tlsCtx->serverAppTrafficSecret,
        sizeof(copiedSecret), false), HITLS_REC_CB_FAIL);
    ASSERT_EQ(tlsCtx->quicTlsCtx->readLevel, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    endpoint.failCallbackId = 0u;
    ASSERT_EQ(QUIC_TLS_SetTrafficSecret(tlsCtx, tlsCtx->clientAppTrafficSecret,
        sizeof(copiedSecret), true), HITLS_SUCCESS);
    ASSERT_EQ(tlsCtx->quicTlsCtx->writeLevel, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION);
    ASSERT_EQ(QUIC_TLS_SetTrafficSecret(tlsCtx, tlsCtx->clientAppTrafficSecret,
        sizeof(copiedSecret), true), HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(QUIC_TLS_SetTrafficSecret(tlsCtx, tlsCtx->serverAppTrafficSecret,
        sizeof(copiedSecret), false), HITLS_SUCCESS);
    ASSERT_EQ(tlsCtx->quicTlsCtx->readLevel, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION);
    ASSERT_EQ(QUIC_TLS_SetTrafficSecret(tlsCtx, tlsCtx->serverAppTrafficSecret,
        sizeof(copiedSecret), false), HITLS_MSG_HANDLE_STATE_ILLEGAL);

EXIT:
    QUIC_TLS_CtxFree(standalone);
    HITLS_Free(ctx);
    HITLS_Free(plainCtx);
    HITLS_CFG_FreeConfig(config);
    QuicTlsTestEndpointFree(&endpoint);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_API_PROCESS_POST_HANDSHAKE_STATE_FUNC_TC001
 * @title Validate post-handshake processing state checks
 * @precon Idle QUIC and non-QUIC TLS 1.3 contexts exist
 * @brief Invoke post-handshake processing before a handshake and with invalid contexts.
 * @expect Null, non-QUIC and idle QUIC calls are rejected with their documented errors.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_API_PROCESS_POST_HANDSHAKE_STATE_FUNC_TC001(void)
{
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_Ctx *plainCtx = NULL;
    QuicTlsTestEndpoint endpoint = {0};

    FRAME_Init();
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    plainCtx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(plainCtx != NULL);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(ctx, g_quicTestDispatch, &endpoint), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(plainCtx), HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(ctx), HITLS_MSG_HANDLE_STATE_ILLEGAL);

EXIT:
    HITLS_Free(ctx);
    HITLS_Free(plainCtx);
    HITLS_CFG_FreeConfig(config);
    QuicTlsTestEndpointFree(&endpoint);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_API_CLEAR_AND_STATE_FUNC_TC001
 * @title Verify Clear preserves the current QUIC method and SetMethod is forbidden after handshake start
 * @precon A configured QUIC client/server pair exists
 * @brief Override the configured method, start a handshake, retry SetMethod, then clear and reuse the client.
 * @expect SetMethod fails after start; Clear resets runtime state while preserving the connection-level override.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_API_CLEAR_AND_STATE_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    QuicTlsTestEndpoint overrideEndpoint = {0};
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(pair.clientLink->ssl, g_quicTestDispatch, &overrideEndpoint), HITLS_SUCCESS);
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_TRUE(overrideEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL].len != 0u);
    ASSERT_EQ(HITLS_QUIC_TLS_SetQuicTlsMethod(pair.clientLink->ssl, g_quicTestDispatch,
        &pair.clientEndpoint), HITLS_MSG_HANDLE_STATE_ILLEGAL);

    ASSERT_EQ(HITLS_Clear(pair.clientLink->ssl), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(pair.clientLink->ssl,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL, NULL, 0u), HITLS_SUCCESS);
    QuicTlsTestEndpointFree(&overrideEndpoint);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(pair.clientLink->ssl,
        g_quicTestClientParams, sizeof(g_quicTestClientParams)), HITLS_SUCCESS);
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_TRUE(overrideEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL].len != 0u);

EXIT:
    QuicTlsTestEndpointFree(&overrideEndpoint);
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */
