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
#include "crypt_eal_rand.h"
#include "bsl_obj_internal.h"
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
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
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
    // Random Unloading Test Case
    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(libCtx, GetAvailableRandAlgId(),
        "provider=provider_get_cap_test1", NULL, 0, NULL), CRYPT_SUCCESS);
  
    config = HITLS_CFG_ProviderNewTLS13Config(libCtx, NULL);
    ASSERT_TRUE(config != NULL);
    uint16_t group = 477;
    HITLS_CFG_SetGroups(config, &group, 1);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    BSL_OBJ_FreeHashTable();
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
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
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
    // Random Unloading Test Case
    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(libCtx, GetAvailableRandAlgId(),
        "provider=provider_get_cap_test1", NULL, 0, NULL), CRYPT_SUCCESS);
    config = HITLS_CFG_ProviderNewTLS13Config(libCtx, NULL);
    ASSERT_TRUE(config != NULL);
    uint16_t signScheme = 23333;
    HITLS_CFG_SetSignature(config, &signScheme, 1);

    FRAME_CertInfo certInfo = {
        "new_signAlg/ca.der",
        "new_signAlg/inter.der",
        "new_signAlg/client.der",
        NULL,
        "new_signAlg/client.key.der",
        NULL
    };
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    BSL_OBJ_FreeHashTable();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS13_LOADPROVIDER_NEWKEYTYPE_TC001(char *path, char *provider_new_alg_test, int cmd)
{
#ifndef HITLS_TLS_FEATURE_PROVIDER
    (void)path;
    (void)provider_new_alg_test;
    (void)cmd;
    SKIP_TEST();
#else
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtx *providerMgr = NULL;
    HITLS_Config *config = NULL;
    int32_t ret = CRYPT_SUCCESS;
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, provider_new_alg_test, NULL, &providerMgr);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(providerMgr != NULL);
    // Random Unloading Test Case
    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(libCtx, GetAvailableRandAlgId(),
        "provider=default", NULL, 0, NULL), CRYPT_SUCCESS);
    config = HITLS_CFG_ProviderNewTLS13Config(libCtx, NULL);
    ASSERT_TRUE(config != NULL);
    uint16_t signScheme = 24444;
    HITLS_CFG_SetSignature(config, &signScheme, 1);

    FRAME_CertInfo certInfo = {
        "new_keyAlg/ca.der",
        "new_keyAlg/inter.der",
        "new_keyAlg/client.der",
        NULL,
        "new_keyAlg/client.key.der",
        NULL
    };

    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

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
