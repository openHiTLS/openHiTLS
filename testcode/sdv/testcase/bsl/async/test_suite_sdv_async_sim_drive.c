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

/* INCLUDE_BASE test_suite_sdv_async_sim */

/* BEGIN_HEADER */
#include "hitls.h"
#include "hitls_config.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"

#define ECHO_LEN 16u

/* TC004 bounded drive: pump rounds before the case gives up */
#define TC004_ROUNDS 600u

/* End-to-end driving-group cases: TLS 1.3 handshake over
 * a memory UIO pair, crypto points paused inside the simulation provider,
 * resumed by FRAME_ASYNC_Handshake on the owner thread. */

/* Post-handshake 16-byte echo with WANT retry: the memory UIO holds a single
 * pending blob per direction, so a WANT must drain the link and retry rather
 * than fail the case. */
static int32_t DriveEchoOnce(FRAME_LinkObj *from, FRAME_LinkObj *to, HITLS_Ctx *fromCtx, HITLS_Ctx *toCtx,
                             const uint8_t *out, uint8_t *in)
{
    uint32_t len = 0;
    int32_t rc = HITLS_Write(fromCtx, out, ECHO_LEN, &len);
    for (uint32_t guard = 0; rc == HITLS_REC_NORMAL_IO_BUSY && guard < 8; guard++) {
        (void)FRAME_TrasferMsgBetweenLink(from, to);
        len = 0;
        rc = HITLS_Write(fromCtx, out, ECHO_LEN, &len);
    }
    if (rc != HITLS_SUCCESS) {
        return rc;
    }
    (void)FRAME_TrasferMsgBetweenLink(from, to);
    len = 0;
    rc = HITLS_Read(toCtx, in, ECHO_LEN, &len);
    for (uint32_t guard = 0; rc == HITLS_REC_NORMAL_RECV_BUF_EMPTY && guard < 8; guard++) {
        (void)FRAME_TrasferMsgBetweenLink(from, to);
        len = 0;
        rc = HITLS_Read(toCtx, in, ECHO_LEN, &len);
    }
    if (rc != HITLS_SUCCESS || len != ECHO_LEN) {
        return rc != HITLS_SUCCESS ? rc : HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SUCCESS;
}
/* END_HEADER */

/**
 * @test   SDV_ASYNC_SIM_DRIVE_TC001
 * @title  End-to-end async handshake: PAUSE on SIGN, callback path
 * @precon MODE_ASYNC build; provider loaded; coroutine backend available
 * @brief
 *    1. Create a TLS 1.3 config through the frame (pinned group), enable
 *       HITLS_MODE_ASYNC, create a client/server link pair, attach both.
 *    2. Configure a PAUSE(1) scenario on SIGN (worker mode, P=2).
 *    3. Drive the handshake with FRAME_ASYNC_Handshake.
 *    4. Verify the handshake state, the stats deltas and the post-handshake
 *       16-byte echo round trip.
 * @expect
 *    1. Both sides reach TLS_CONNECTED.
 *    2. pauses >= 1, submits >= 1 (the async path was really taken).
 *    3. The echo round trip succeeds on both directions.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_DRIVE_TC001(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC) || \
    !defined(HITLS_TLS_FEATURE_MODE_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    HITLS_Config *config = NULL;
    FRAME_LinkObj *clientLink = NULL;
    FRAME_LinkObj *serverLink = NULL;
    FRAME_ASYNC_Link *client = NULL;
    FRAME_ASYNC_Link *server = NULL;
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    SIM_PROV_STATS base = {0};
    uint8_t out[16] = {0};
    uint8_t in[16] = {0};
    uint32_t state = 0;

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(8, 2), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    config = AsyncSimNewTls13Config(libCtx);
    ASSERT_TRUE(config != NULL);
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    ASSERT_EQ(HITLS_CFG_SetGroups(config, &group, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetModeSupport(config, HITLS_MODE_ASYNC), HITLS_SUCCESS);

    clientLink = FRAME_CreateLink(config, BSL_UIO_TCP);
    serverLink = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(clientLink != NULL && serverLink != NULL);
    ASSERT_EQ(FRAME_ASYNC_AttachLink(clientLink, &client), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_AttachLink(serverLink, &server), FRAME_ASYNC_SUCCESS);

    /* duplicate registration must be rejected */
    FRAME_ASYNC_Link *dup = NULL;
    ASSERT_EQ(FRAME_ASYNC_AttachLink(clientLink, &dup), FRAME_ASYNC_ERR_STATE);

    /* callback path: install the frame completion callback on both ends */
    ASSERT_EQ(HITLS_SetAsyncCallback(FRAME_GetTlsCtx(clientLink), FRAME_ASYNC_OnDone, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetAsyncCallback(FRAME_GetTlsCtx(serverLink), FRAME_ASYNC_OnDone, server), HITLS_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_SIGN;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_PAUSE;
    sc.resumeCount = 1;
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_WORKER, 2, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_Handshake(client, server, 10000), FRAME_ASYNC_SUCCESS);

    ASSERT_EQ(HITLS_GetHandShakeState(client->ctx, &state), HITLS_SUCCESS);
    ASSERT_EQ(state, (uint32_t)TLS_CONNECTED);
    ASSERT_EQ(HITLS_GetHandShakeState(server->ctx, &state), HITLS_SUCCESS);
    ASSERT_EQ(state, (uint32_t)TLS_CONNECTED);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    /* the async path was really taken (never degenerate) */
    ASSERT_TRUE(stats.pauses - base.pauses >= 1);
    ASSERT_TRUE(stats.submits - base.submits >= 1);
    ASSERT_TRUE(stats.resubmits - base.resubmits == 0);
    ASSERT_TRUE(stats.failures == base.failures);

    /* post-handshake echo: both directions */
    for (uint32_t i = 0; i < sizeof(out); i++) {
        out[i] = (uint8_t)(i + 1);
    }
    ASSERT_EQ(DriveEchoOnce(clientLink, serverLink, client->ctx, server->ctx, out, in), HITLS_SUCCESS);
    ASSERT_COMPARE("client to server echo differs", out, sizeof(out), in, sizeof(in));
    ASSERT_EQ(DriveEchoOnce(serverLink, clientLink, server->ctx, client->ctx, out, in), HITLS_SUCCESS);
    ASSERT_COMPARE("server to client echo differs", out, sizeof(out), in, sizeof(in));

EXIT:
    if (client != NULL) {
        (void)FRAME_ASYNC_DetachLink(client);
    }
    if (server != NULL) {
        (void)FRAME_ASYNC_DetachLink(server);
    }
    FRAME_FreeLink(clientLink);
    FRAME_FreeLink(serverLink);
    HITLS_CFG_FreeConfig(config);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_DRIVE_TC002
 * @title  Handle path: no application callback installed, pump waits on eventfd
 * @precon MODE_ASYNC build; provider loaded; coroutine backend available
 * @brief
 *    1. Same setup as TC001 but the frame installs no completion callback
 *       on the connections (the provider selects the notify-handle path).
 *    2. Configure PAUSE(2) on KEYEXCH (worker mode) so the shared secret
 *       computation pauses twice per side.
 *    3. Drive the handshake and verify the stats.
 * @expect
 *    1. Both sides reach TLS_CONNECTED.
 *    2. pauses >= 4 (two sides x two rounds), workerDone >= 2.
 *    3. The echo round trip succeeds.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_DRIVE_TC002(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC) || \
    !defined(HITLS_TLS_FEATURE_MODE_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    HITLS_Config *config = NULL;
    FRAME_LinkObj *clientLink = NULL;
    FRAME_LinkObj *serverLink = NULL;
    FRAME_ASYNC_Link *client = NULL;
    FRAME_ASYNC_Link *server = NULL;
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    SIM_PROV_STATS base = {0};
    uint8_t out[16] = {0};
    uint8_t in[16] = {0};
    uint32_t state = 0;

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(8, 2), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    config = AsyncSimNewTls13Config(libCtx);
    ASSERT_TRUE(config != NULL);
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    ASSERT_EQ(HITLS_CFG_SetGroups(config, &group, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetModeSupport(config, HITLS_MODE_ASYNC), HITLS_SUCCESS);

    clientLink = FRAME_CreateLink(config, BSL_UIO_TCP);
    serverLink = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(clientLink != NULL && serverLink != NULL);
    ASSERT_EQ(FRAME_ASYNC_AttachLink(clientLink, &client), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_AttachLink(serverLink, &server), FRAME_ASYNC_SUCCESS);

    /* no completion callback anywhere: the producer selects the notify-handle
     * path and the pump waits on the shared eventfd */
    sc.operaId = CRYPT_EAL_OPERAID_KEYEXCH;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_PAUSE;
    sc.resumeCount = 2;
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_WORKER, 2, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_Handshake(client, server, 10000), FRAME_ASYNC_SUCCESS);

    ASSERT_EQ(HITLS_GetHandShakeState(client->ctx, &state), HITLS_SUCCESS);
    ASSERT_EQ(state, (uint32_t)TLS_CONNECTED);
    ASSERT_EQ(HITLS_GetHandShakeState(server->ctx, &state), HITLS_SUCCESS);
    ASSERT_EQ(state, (uint32_t)TLS_CONNECTED);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(stats.pauses - base.pauses >= 4);
    ASSERT_TRUE(stats.workerDone - base.workerDone >= 2);
    ASSERT_TRUE(stats.resubmits - base.resubmits == 0);

    for (uint32_t i = 0; i < sizeof(out); i++) {
        out[i] = (uint8_t)(i + 3);
    }
    ASSERT_EQ(DriveEchoOnce(clientLink, serverLink, client->ctx, server->ctx, out, in), HITLS_SUCCESS);
    ASSERT_COMPARE("handle-path echo differs", out, sizeof(out), in, sizeof(in));

EXIT:
    if (client != NULL) {
        (void)FRAME_ASYNC_DetachLink(client);
    }
    if (server != NULL) {
        (void)FRAME_ASYNC_DetachLink(server);
    }
    FRAME_FreeLink(clientLink);
    FRAME_FreeLink(serverLink);
    HITLS_CFG_FreeConfig(config);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_DRIVE_TC003
 * @title  Injected FAIL surfaces as FRAME_ASYNC_ERR_PROTOCOL with lastRet
 * @precon MODE_ASYNC build; provider loaded; coroutine backend available
 * @brief
 *    1. Configure a FAIL scenario on SIGN with a non-zero errCode.
 *    2. Drive the handshake: the injected failure must surface as a fatal
 *       protocol error, not a timeout.
 *    3. Read back the raw return from the link's lastRet field.
 * @expect
 *    1. FRAME_ASYNC_Handshake returns FRAME_ASYNC_ERR_PROTOCOL.
 *    2. lastRet holds the last direct protocol API return.
 *    3. stats.failures increased by the injected failure.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_DRIVE_TC003(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC) || \
    !defined(HITLS_TLS_FEATURE_MODE_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    HITLS_Config *config = NULL;
    FRAME_LinkObj *clientLink = NULL;
    FRAME_LinkObj *serverLink = NULL;
    FRAME_ASYNC_Link *client = NULL;
    FRAME_ASYNC_Link *server = NULL;
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    SIM_PROV_STATS base = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(8, 2), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    config = AsyncSimNewTls13Config(libCtx);
    ASSERT_TRUE(config != NULL);
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    ASSERT_EQ(HITLS_CFG_SetGroups(config, &group, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetModeSupport(config, HITLS_MODE_ASYNC), HITLS_SUCCESS);

    clientLink = FRAME_CreateLink(config, BSL_UIO_TCP);
    serverLink = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(clientLink != NULL && serverLink != NULL);
    ASSERT_EQ(FRAME_ASYNC_AttachLink(clientLink, &client), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_AttachLink(serverLink, &server), FRAME_ASYNC_SUCCESS);

    /* callback path for determinism: the injected failure must surface
     * through the frame's fatal detection, not through a wait timeout */
    ASSERT_EQ(HITLS_SetAsyncCallback(FRAME_GetTlsCtx(clientLink), FRAME_ASYNC_OnDone, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetAsyncCallback(FRAME_GetTlsCtx(serverLink), FRAME_ASYNC_OnDone, server), HITLS_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_SIGN;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_FAIL;
    sc.resumeCount = 1;
    sc.errCode = CRYPT_EAL_ALG_NOT_SUPPORT;
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_WORKER, 2, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_Handshake(client, server, 10000), FRAME_ASYNC_ERR_PROTOCOL);

    /* the raw protocol return is retrievable without code folding */
    ASSERT_TRUE(client->lastRet != HITLS_SUCCESS || server->lastRet != HITLS_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(stats.failures - base.failures >= 1);

EXIT:
    if (client != NULL) {
        (void)FRAME_ASYNC_DetachLink(client);
    }
    if (server != NULL) {
        (void)FRAME_ASYNC_DetachLink(server);
    }
    FRAME_FreeLink(clientLink);
    FRAME_FreeLink(serverLink);
    HITLS_CFG_FreeConfig(config);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_DRIVE_TC004
 * @title  Registration capacity: many concurrent connections driven by Pump
 * @precon MODE_ASYNC build; provider loaded; coroutine backend available
 * @brief
 *    1. Create and attach `pairs` client/server pairs (2 x pairs connections,
 *       exercising the growable registration table beyond its initial size).
 *    2. Pair and start only the first `drivePairs` pairs the way
 *       FRAME_ASYNC_Handshake does (it drives one pair at a time, so the
 *       pairing is done here for concurrent driving); configure PAUSE(1) on
 *       every KEYEXCH hit in worker mode.
 *    3. Drive them with FRAME_ASYNC_Pump until every started side reaches
 *       TLS_CONNECTED, then detach the whole table; every detach must succeed,
 *       which is what shows the pump left no connection paused.
 * @param pairs [IN] Total client/server pairs to register
 * @param drivePairs [IN] Pairs that actually run a handshake (<= pairs)
 * @expect
 *    1. All 2 x pairs attaches succeed.
 *    2. Every driven side reaches TLS_CONNECTED; pauses delta >= 2 x
 *       drivePairs (one key exchange pause per driven connection); no
 *       failures; no outstanding request.
 *    3. All detaches succeed.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_DRIVE_TC004(int pairs, int drivePairs)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC) || \
    !defined(HITLS_TLS_FEATURE_MODE_ASYNC)
    (void)pairs;
    (void)drivePairs;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    HITLS_Config *config = NULL;
    FRAME_LinkObj **cliObj = NULL;
    FRAME_LinkObj **srvObj = NULL;
    FRAME_ASYNC_Link **cli = NULL;
    FRAME_ASYNC_Link **srv = NULL;
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    SIM_PROV_STATS base = {0};
    uint32_t state = 0;
    uint32_t rounds = 0;
    bool allConnected = false;

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_TRUE(pairs >= 1 && drivePairs >= 1 && drivePairs <= pairs);

    /* unlimited task pool: every driven connection may pause at the same time */
    ASSERT_EQ(AsyncSimSetup(0, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    config = AsyncSimNewTls13Config(libCtx);
    ASSERT_TRUE(config != NULL);
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    ASSERT_EQ(HITLS_CFG_SetGroups(config, &group, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetModeSupport(config, HITLS_MODE_ASYNC), HITLS_SUCCESS);

    cliObj = calloc((uint32_t)pairs, sizeof(*cliObj));
    srvObj = calloc((uint32_t)pairs, sizeof(*srvObj));
    cli = calloc((uint32_t)pairs, sizeof(*cli));
    srv = calloc((uint32_t)pairs, sizeof(*srv));
    ASSERT_TRUE(cliObj != NULL && srvObj != NULL && cli != NULL && srv != NULL);

    /* register every pair; the table grows past its initial capacity on demand */
    for (uint32_t i = 0; i < (uint32_t)pairs; i++) {
        cliObj[i] = FRAME_CreateLink(config, BSL_UIO_TCP);
        srvObj[i] = FRAME_CreateLink(config, BSL_UIO_TCP);
        ASSERT_TRUE(cliObj[i] != NULL && srvObj[i] != NULL);
        ASSERT_EQ(FRAME_ASYNC_AttachLink(cliObj[i], &cli[i]), FRAME_ASYNC_SUCCESS);
        ASSERT_EQ(FRAME_ASYNC_AttachLink(srvObj[i], &srv[i]), FRAME_ASYNC_SUCCESS);
    }

    /* pair only the driven ends so the pump's WANT_IO handling can find the
     * peer; idle registrations stay inert (the pump skips a NULL peer) */
    for (uint32_t i = 0; i < (uint32_t)drivePairs; i++) {
        cli[i]->peer = srv[i];
        srv[i]->peer = cli[i];
    }

    /* every driven connection pauses once inside its key exchange; no
     * callback is installed, so the pump takes the notify-handle (eventfd) path */
    sc.operaId = CRYPT_EAL_OPERAID_KEYEXCH;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_PAUSE;
    sc.resumeCount = 1;
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_WORKER, 4, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    /* start the driven pairs, then let the pump drive them together */
    for (uint32_t i = 0; i < (uint32_t)drivePairs; i++) {
        cli[i]->lastOp = FRAME_ASYNC_OP_CONNECT;
        cli[i]->lastRet = HITLS_Connect(cli[i]->ctx);
        srv[i]->lastOp = FRAME_ASYNC_OP_ACCEPT;
        srv[i]->lastRet = HITLS_Accept(srv[i]->ctx);
    }
    while (!allConnected) {
        allConnected = true;
        for (uint32_t i = 0; i < (uint32_t)drivePairs; i++) {
            if (HITLS_GetHandShakeState(cli[i]->ctx, &state) != HITLS_SUCCESS || state != (uint32_t)TLS_CONNECTED ||
                HITLS_GetHandShakeState(srv[i]->ctx, &state) != HITLS_SUCCESS || state != (uint32_t)TLS_CONNECTED) {
                allConnected = false;
                break;
            }
        }
        if (allConnected) {
            break;
        }
        ASSERT_TRUE(++rounds <= TC004_ROUNDS);
        int32_t ret = FRAME_ASYNC_Pump(100);
        ASSERT_TRUE(ret == FRAME_ASYNC_SUCCESS || ret == FRAME_ASYNC_ERR_TIMEOUT);
    }

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    /* one key-exchange pause per driven connection: drivePairs x 2 sides */
    ASSERT_TRUE(stats.pauses - base.pauses >= (uint64_t)drivePairs * 2);
    ASSERT_TRUE(stats.failures == base.failures);
    ASSERT_EQ(FRAME_ASYNC_GetOutstanding(), 0u);

    /* detach the whole table: DetachLink rejects a link whose task is still
     * paused, so these asserts are what shows the pump left nothing pending.
     * The handles are cleared so EXIT does not detach them a second time. */
    for (uint32_t i = 0; i < (uint32_t)pairs; i++) {
        ASSERT_EQ(FRAME_ASYNC_DetachLink(cli[i]), FRAME_ASYNC_SUCCESS);
        ASSERT_EQ(FRAME_ASYNC_DetachLink(srv[i]), FRAME_ASYNC_SUCCESS);
        cli[i] = NULL;
        srv[i] = NULL;
    }

EXIT:
    if (cliObj != NULL && srvObj != NULL) {
        for (uint32_t i = 0; i < (uint32_t)pairs; i++) {
            if (cli != NULL && cli[i] != NULL) {
                (void)FRAME_ASYNC_DetachLink(cli[i]);
            }
            if (srv != NULL && srv[i] != NULL) {
                (void)FRAME_ASYNC_DetachLink(srv[i]);
            }
            FRAME_FreeLink(cliObj[i]);
            FRAME_FreeLink(srvObj[i]);
        }
    }
    free(cliObj);
    free(srvObj);
    free(cli);
    free(srv);
    HITLS_CFG_FreeConfig(config);
    AsyncSimTeardown();
#endif
}
/* END_CASE */
