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

#include "frame_tls.h"
#include "frame_link.h"
#include "session.h"
#include "hitls_config.h"
#include "hitls_crypt_init.h"
#include "crypt_provider_local.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "crypt_errno.h"
#include "cert_callback.h"
#include "test.h"
/* END_HEADER */


/* BEGIN_CASE */
void UT_TLS13_LOADPROVIDER_GROUP_TC001(char *path, char *get_cap_test1, int cmd)
{
#ifndef HITLS_TLS_FEATURE_PROVIDER
    (void)path;
    (void)get_cap_test1;
    (void)cmd;
    SKIP_TEST();
#else
    FRAME_Init();
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtx *providerMgr = NULL;
    HITLS_Config *config = NULL;
    int32_t ret = CRYPT_SUCCESS;
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, get_cap_test1, NULL, &providerMgr);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(providerMgr != NULL);

    config = HITLS_CFG_ProviderNewTLS13Config(libCtx, NULL);
    ASSERT_TRUE(config != NULL);
    uint16_t group = 477;
    HITLS_CFG_SetGroups(config, &group, 1);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS13_LOADPROVIDER_SIGNSCHEME_TC001(char *path, char *get_cap_test1, int cmd)
{
#ifndef HITLS_TLS_FEATURE_PROVIDER
    (void)path;
    (void)get_cap_test1;
    (void)cmd;
    SKIP_TEST();
#else
    FRAME_Init();
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtx *providerMgr = NULL;
    HITLS_Config *config = NULL;
    int32_t ret = CRYPT_SUCCESS;
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, get_cap_test1, NULL, &providerMgr);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(providerMgr != NULL);

    config = HITLS_CFG_ProviderNewTLS13Config(libCtx, NULL);
    ASSERT_TRUE(config != NULL);
    uint16_t signScheme = 23333;
    HITLS_CFG_SetSignature(config, &signScheme, 1);

    ret = HiTLS_X509_LoadCertAndKey(config, "new_signAlg/ca.der",
        "new_signAlg/inter.der",
        "new_signAlg/client.der",
        NULL,
        "new_signAlg/client.key.der",
        NULL);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLinkEx(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkEx(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
#endif
}
/* END_CASE */
