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
#include "crypt_eal_implprovider.h"
/* END_HEADER */

/**
 * @test SDV_ASYNC_SIM_FIX_TC002
 * @brief Drive an EAGAIN pause over a TLS pair in-process: the first
 *        submission is answered with EAGAIN, the single legal re-submission
 *        happens at the resume point and the handshake completes. Both
 *        notification paths (completion callback / notify handle) and both
 *        execution modes are covered by the data rows.
 * @expect The resume re-submits once, the handshake completes on both sides
 *         and the quiesced pair detaches and tears down cleanly.
 * @precon Async TLS and provider enabled.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_FIX_TC002(int callback, int mode)
{
#if !defined(HITLS_BSL_ASYNC) || !defined(HITLS_TLS_FEATURE_MODE_ASYNC) || !defined(HITLS_TLS_FEATURE_PROVIDER)
    (void)callback;
    (void)mode;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    HITLS_Config *cfg = NULL;
    FRAME_LinkObj *cl = NULL;
    FRAME_LinkObj *sl = NULL;
    FRAME_ASYNC_Link *client = NULL;
    FRAME_ASYNC_Link *server = NULL;
    SIM_PROV_STATS stats = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(8, 2), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    cfg = AsyncSimNewTls13Config(libCtx);
    ASSERT_TRUE(cfg != NULL);
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    ASSERT_EQ(HITLS_CFG_SetGroups(cfg, &group, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetModeSupport(cfg, HITLS_MODE_ASYNC), HITLS_SUCCESS);
    cl = FRAME_CreateLink(cfg, BSL_UIO_TCP);
    sl = FRAME_CreateLink(cfg, BSL_UIO_TCP);
    ASSERT_TRUE(cl != NULL && sl != NULL);
    ASSERT_EQ(FRAME_ASYNC_AttachLink(cl, &client), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_AttachLink(sl, &server), FRAME_ASYNC_SUCCESS);
    if (callback) {
        ASSERT_EQ(HITLS_SetAsyncCallback(client->ctx, FRAME_ASYNC_OnDone, client), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_SetAsyncCallback(server->ctx, FRAME_ASYNC_OnDone, server), HITLS_SUCCESS);
    }
    SIM_PROV_SCENARIO sc = {.operaId = CRYPT_EAL_OPERAID_KEYMGMT, .action = SIM_PROV_ACTION_EAGAIN};
    if (mode == SIM_PROV_EXEC_WORKER) {
        sc.operaId = CRYPT_EAL_OPERAID_SIGN;
        sc.waitNs = 10000000;
    }
    ASSERT_EQ(FRAME_ASYNC_SetDevice(mode, 2, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_Handshake(client, server, 1000), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_GetOutstanding(), 0u);
    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(stats.resubmits > 0 && stats.submits == stats.resubmits);
    ASSERT_TRUE(mode != SIM_PROV_EXEC_WORKER || stats.workerDone > 0);

    /* the EAGAIN flow must leave no residue: the quiesced pair detaches and
     * the full teardown succeeds on the owner thread. Order matters: every
     * object decoded through the provider (link certs/keys, config) must be
     * freed before the provider is unloaded. */
    ASSERT_EQ(FRAME_ASYNC_DetachLink(client), FRAME_ASYNC_SUCCESS);
    client = NULL;
    ASSERT_EQ(FRAME_ASYNC_DetachLink(server), FRAME_ASYNC_SUCCESS);
    server = NULL;
    FRAME_FreeLink(cl);
    cl = NULL;
    FRAME_FreeLink(sl);
    sl = NULL;
    HITLS_CFG_FreeConfig(cfg);
    cfg = NULL;
    ASSERT_EQ(FRAME_ASYNC_UnloadProvider(), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_CleanupThread(), FRAME_ASYNC_SUCCESS);

EXIT:
    if (client != NULL) {
        (void)FRAME_ASYNC_DetachLink(client);
    }
    if (server != NULL) {
        (void)FRAME_ASYNC_DetachLink(server);
    }
    FRAME_FreeLink(cl);
    FRAME_FreeLink(sl);
    HITLS_CFG_FreeConfig(cfg);
    AsyncSimTeardown();
#endif
}
/* END_CASE */
