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

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <stddef.h>
#include <sys/types.h>
#include <regex.h>
#include "securec.h"
#include "bsl_sal.h"
#include "sal_net.h"
#include "hitls.h"
#include "frame_tls.h"
#include "cert_callback.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "frame_io.h"
#include "uio_abstraction.h"
#include "tls.h"
#include "tls_config.h"
#include "logger.h"
#include "process.h"
#include "hs_ctx.h"
#include "hlt.h"
#include "stub_replace.h"
#include "hitls_type.h"
#include "frame_link.h"
#include "session_type.h"
#include "common_func.h"
#include "hitls_func.h"
#include "hitls_cert_type.h"
#include "cert_mgr_ctx.h"
#include "parser_frame_msg.h"
#include "recv_process.h"
#include "simulate_io.h"
#include "rec_wrapper.h"
#include "cipher_suite.h"
#include "alert.h"
#include "conn_init.h"
#include "pack.h"
#include "send_process.h"
#include "cert.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_type.h"
#include "hs.h"
#include "hs_state_recv.h"
#include "app.h"
#include "record.h"
#include "rec_conn.h"
#include "session.h"
#include "frame_msg.h"
#include "pack_frame_msg.h"
#include "cert_mgr.h"
#include "hs_extensions.h"
#include "hlt_type.h"
#include "sctp_channel.h"
#include "hitls_crypt_init.h"
#include "crypt_default.h"
#include "stub_crypt.h"
#include "hitls_crypt.h"
#include "security.h"
/* END_HEADER */

#define DEFAULT_DESCRIPTION_LEN 128
#define ERROR_HITLS_GROUP 1
#define ERROR_HITLS_SIGNATURE 0xffffu
typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession; /* Set the session to the client for session resume. */
} ResumeTestInfo;

static HITLS_Config *GetHitlsConfigViaVersion(int ver)
{
    switch (ver) {
        case TLS1_2:
        case HITLS_VERSION_TLS12:
            return HITLS_CFG_NewTLS12Config();
        case TLS1_3:
        case HITLS_VERSION_TLS13:
            return HITLS_CFG_NewTLS13Config();
        case DTLS1_2:
        case HITLS_VERSION_DTLS12:
            return HITLS_CFG_NewDTLS12Config();
        default:
            return NULL;
    }
}

static int32_t UT_ClientHelloCb(HITLS_Ctx *ctx, int32_t *alert, void *arg)
{
    (void)ctx;
    (void)alert;
    return *(int32_t *)arg;
}

static int32_t UT_CookieGenerateCb(HITLS_Ctx *ctx, uint8_t *cookie, uint32_t *cookie_len)
{
    (void)ctx;
    (void)cookie;
    (void)cookie_len;
    return 0;
}

static int32_t UT_CookieVerifyCb(HITLS_Ctx *ctx, const uint8_t *cookie, uint32_t cookie_len)
{
    (void)ctx;
    (void)cookie;
    (void)cookie_len;
    return 1;
}

/** @
* @test  UT_TLS_CFG_UPREF_FUNC_TC001
* @spec  -
* @title  Invoke the HITLS_CFG_UpRef interface to change the number of config reference times.
* @precon  nan
* @brief    1. Apply for and initialize config.
            2. Invoke the HITLS_CFG_UpRef interface and transfer the config parameter.
            3. Check the number of times the config file is referenced.
* @expect   1. The application is successful.
            2. The invoking is successful.
            3. The number of references is 2.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_UPREF_FUNC_TC001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_TRUE(HITLS_CFG_UpRef(config) == HITLS_SUCCESS);
    ASSERT_TRUE(config->references.count == 2);
    HITLS_CFG_FreeConfig(config);
    ASSERT_TRUE(config->references.count == 1);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */


/** @
* @test UT_TLS_CFG_SET_RESUMPTIONONRENEGOSUPPORT_API_TC001
* @Specifications-
* @title Test the HITLS_CFG_SetResumptionOnRenegoSupport interface for setting ResumptionOnRenegoSupport.
* @preppynan
* @brief HITLS_CFG_Setting negotiation support
* 1. Transfer empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and support invalid values. Expected result 2 is displayed.
* 3. The input configuration information is not empty and the value can be valid. Expected result 3 is obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned and isResumptionOnRenego is set to true.
* 3. HITLS_SUCCES is returned and isResumptionOnRenego is set to true or false.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_RESUMPTIONONRENEGOSUPPORT_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool support = -1;
    ASSERT_TRUE(HITLS_CFG_SetResumptionOnRenegoSupport(config, support) == HITLS_NULL_INPUT);

    switch (tlsVersion) {
        case HITLS_VERSION_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            break;
        default:
            config = NULL;
            break;
    }

    ASSERT_TRUE(HITLS_CFG_SetResumptionOnRenegoSupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(config->isResumptionOnRenego == true);

    support = false;
    ASSERT_TRUE(HITLS_CFG_SetResumptionOnRenegoSupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(config->isResumptionOnRenego == false);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_GET_NOCLIENTCERTSUPPORT_API_TC001
* @spec  -
* @title Test the HITLS_CFG_SetNoClientCertSupport and HITLS_CFG_GetNoClientVerifySupport interfaces.
* @precon nan
* @brief HITLS_CFG_SetNoClientCertSupport
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and set support to an invalid value. Expected result 2 is obtained.
* 3. Transfer non-empty configuration information and set support to a valid value. Expected result 3 is obtained.
*    HITLS_CFG_GetNoClientCertSupport
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer an empty isSupport pointer. Expected result 1 is obtained.
* 3. Transfer the non-null configuration information and the isSupport pointer is not null. Expected result 3 is
*    obtained.
* @expect 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned and config->isSupportNoClientCert is true.
* 3. Returns HITLS_SUCCES and config->isSupportNoClientCert is true or false.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_NOCLIENTCERTSUPPORT_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool support = -1;
    bool isSupport = -1;
    ASSERT_TRUE(HITLS_CFG_SetNoClientCertSupport(config, support) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetNoClientCertSupport(config, &isSupport) == HITLS_NULL_INPUT);

    switch (tlsVersion) {
        case HITLS_VERSION_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            break;
        default:
            config = NULL;
            break;
    }

    ASSERT_TRUE(HITLS_CFG_GetNoClientCertSupport(config, NULL) == HITLS_NULL_INPUT);

    support = true;
    ASSERT_TRUE(HITLS_CFG_SetNoClientCertSupport(config, support) == HITLS_SUCCESS);

    support = -1;
    ASSERT_TRUE(HITLS_CFG_SetNoClientCertSupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetNoClientCertSupport(config, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == true);

    support = false;
    ASSERT_TRUE(HITLS_CFG_SetNoClientCertSupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetNoClientCertSupport(config, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_GET_CLIENTVERIFYSUPPORT_API_TC001
* @spec -
* @title Test the HITLS_CFG_SetClientVerifySupport and HITLS_CFG_GetClientVerifySupport interfaces.
* @precon nan
* @brief HITLS_CFG_SetClientVerifySupport
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and set support to an invalid value. Expected result 2 is obtained.
* 3. Transfer non-empty configuration information and set support to a valid value. Expected result 3 is obtained.
*    HITLS_CFG_GetClientVerifySupport
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer an empty isSupport pointer. Expected result 1 is obtained.
* 3. Transfer the non-null configuration information and the isSupport pointer is not null. Expected result 3 is
*    obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned, and config->isSupportClientVerify is true and isSupportVerifyNone is false.
* 3. HITLS_SUCCES is returned, and config->isSupportClientVerify is true or false. isSupportVerifyNone and
isSupportVerifyNone are mutually exclusive, but can be false at the same time.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_CLIENTVERIFYSUPPORT_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool support = -1;
    bool isSupport = false;
    ASSERT_TRUE(HITLS_CFG_SetClientVerifySupport(config, support) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetClientVerifySupport(config, &isSupport) == HITLS_NULL_INPUT);

    switch (tlsVersion) {
        case HITLS_VERSION_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            break;
        default:
            config = NULL;
            break;
    }

    ASSERT_TRUE(HITLS_CFG_GetClientVerifySupport(config, NULL) == HITLS_NULL_INPUT);

    support = true;
    ASSERT_TRUE(HITLS_CFG_SetClientVerifySupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(config->isSupportVerifyNone == false);

    support = -1;
    ASSERT_TRUE(HITLS_CFG_SetClientVerifySupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetClientVerifySupport(config, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == true);

    support = false;
    ASSERT_TRUE(HITLS_CFG_SetClientVerifySupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetClientVerifySupport(config, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_TMPDH_API_TC001
* @spec  -
* @title Test the HITLS_CFG_SetTmpDh interface.
* @precon nan
* @brief HITLS_CFG_SetTmpDh
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and leave dhPkey empty. Expected result 1 is obtained.
* 3. Transfer non-empty configuration information and set dhPkey to a non-empty value. Expected result 2 is displayed.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. Returns HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_TMPDH_API_TC001(int tlsVersion, int securityBits, int securityLevel)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_CRYPT_Key *dhPkey = NULL;
    switch (tlsVersion) {
        case HITLS_VERSION_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            break;
        default:
            config = NULL;
            break;
    }
    dhPkey = HITLS_CRYPT_GenerateDhKeyBySecbits(LIBCTX_FROM_CONFIG(config), ATTRIBUTE_FROM_CONFIG(config), config,
                                                securityBits);
    ASSERT_TRUE(HITLS_CFG_SetTmpDh(NULL, dhPkey) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetSecurityLevel(config, securityLevel) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetTmpDh(config, NULL) == HITLS_NULL_INPUT);
    if (SECURITY_GetSecbits(securityLevel) <= securityBits) {
        ASSERT_TRUE(HITLS_CFG_SetTmpDh(config, dhPkey) == HITLS_SUCCESS);
    } else {
        ASSERT_TRUE(HITLS_CFG_SetTmpDh(config, dhPkey) == HITLS_CRYPT_ERR_DH);
    }

EXIT:
    if (SECURITY_GetSecbits(securityLevel) > securityBits) {
        SAL_CRYPT_FreeDhKey(dhPkey);
    }
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

int32_t g_securityBits = 0;

static HITLS_CRYPT_Key *UT_TmpDhCb(HITLS_Ctx *ctx, int32_t isExport, uint32_t keyLen)
{
    (void)isExport;
    (void)keyLen;
    HITLS_CRYPT_Key *dhPkey = NULL;
    HITLS_Config *config = &ctx->config.tlsConfig;
    dhPkey = HITLS_CRYPT_GenerateDhKeyBySecbits(LIBCTX_FROM_CONFIG(config), ATTRIBUTE_FROM_CONFIG(config), config,
                                                g_securityBits);
    return dhPkey;
}

/* @
* @test  UT_TLS_CFG_SET_TMPDHCB_API_TC001
* @title  Set tmpdhcallback. The link setup status varies according to the security level.
* @precon  nan
* @brief
* 1. Set the RSA certificate and algorithm suite.
* 2. Set dh callback and generate dhkey through dhcb.
* 3. Set security level to 2, set tmpdh key to 80 bits, and set up a link.
* 4. Set security level to 2, set tmpdh key to 112 bits, and set up a link.
* 5. Set security level to 1, set tmpdh key to 128 bits, and set up a link.
* 6. Set security level to 2, set tmpdh key to 128 bits, and set up a link.
* @expect
* 1. The setting is successful.
* 2. The setting is successful.
* 3. The link fails to be set up.
* 4. The link is set up successfully.
* 5. The link is set up successfully.
* 6. The link is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_TMPDHCB_API_TC001(int securityBits, int securityLevel)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint16_t pfsCipherSuites[] = {HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256};

    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(serverConfig != NULL);

    ASSERT_TRUE(HiTLS_X509_LoadCertAndKey(clientConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, NULL,
                                          RSA_SHA256_PRIV_PATH3, NULL) == HITLS_SUCCESS);
    ASSERT_TRUE(HiTLS_X509_LoadCertAndKey(serverConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, NULL,
                                          RSA_SHA256_PRIV_PATH3, NULL) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(clientConfig, pfsCipherSuites, sizeof(pfsCipherSuites) / sizeof(uint16_t)) ==
                HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(serverConfig, pfsCipherSuites, sizeof(pfsCipherSuites) / sizeof(uint16_t)) ==
                HITLS_SUCCESS);

    HITLS_CFG_SetDhAutoSupport(serverConfig, false);
    g_securityBits = securityBits;
    ASSERT_TRUE(HITLS_CFG_SetTmpDhCb(serverConfig, UT_TmpDhCb) == HITLS_SUCCESS);
    FRAME_CertInfo certInfo = {0, 0, 0, 0, 0, 0};
    client = FRAME_CreateLinkWithCert(clientConfig, BSL_UIO_TCP, &certInfo);
    server = FRAME_CreateLinkWithCert(serverConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(HITLS_SetSecurityLevel(server->ssl, securityLevel) == HITLS_SUCCESS);

    if (SECURITY_GetSecbits(securityLevel) > securityBits) {
        ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_KEY_EXCHANGE), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_ERR_GET_DH_KEY);
    } else {
        ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    }

EXIT:
    HITLS_CFG_FreeConfig(serverConfig);
    HITLS_CFG_FreeConfig(clientConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_CLIENTHELLOCB_API_TC001
* @title Test the HITLS_CFG_SetClientHelloCb interface.
* @precon nan
* @brief HITLS_CFG_SetClientHelloCb
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and leave callback empty. Expected result 1 is obtained.
* 3. Transfer non-empty configuration information and set callback to a non-empty value. Expected result 2 is obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. Returns HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_CLIENTHELLOCB_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    int32_t cbRetVal = 0;
    ASSERT_TRUE(HITLS_CFG_SetClientHelloCb(config, UT_ClientHelloCb, &cbRetVal) == HITLS_NULL_INPUT);

    switch (tlsVersion) {
        case HITLS_VERSION_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            break;
        default:
            config = NULL;
            break;
    }

    ASSERT_TRUE(HITLS_CFG_SetClientHelloCb(config, NULL, &cbRetVal) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_SetClientHelloCb(config, UT_ClientHelloCb, &cbRetVal) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_COOKIEGENERATECB_API_TC001
* @title Test the HITLS_CFG_SetCookieGenCb interface.
* @precon nan
* @brief HITLS_CFG_SetCookieGenCb
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and leave callback empty. Expected result 1 is obtained.
* 3. Transfer non-empty configuration information and set callback to a non-empty value. Expected result 2 is obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. Returns HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_COOKIEGENERATECB_API_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    ASSERT_TRUE(HITLS_CFG_SetCookieGenCb(config, UT_CookieGenerateCb) == HITLS_NULL_INPUT);

    config = HITLS_CFG_NewDTLS12Config();

    ASSERT_TRUE(HITLS_CFG_SetCookieGenCb(config, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_SetCookieGenCb(config, UT_CookieGenerateCb) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_COOKIEVERIFYCB_API_TC001
* @title Test the HITLS_CFG_SetCookieVerifyCb interface.
* @precon nan
* @brief HITLS_CFG_SetCookieVerifyCb
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and leave callback empty. Expected result 1 is obtained.
* 3. Transfer non-empty configuration information and set callback to a non-empty value. Expected result 2 is obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. Returns HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_COOKIEVERIFYCB_API_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    ASSERT_TRUE(HITLS_CFG_SetCookieVerifyCb(config, UT_CookieVerifyCb) == HITLS_NULL_INPUT);

    config = HITLS_CFG_NewDTLS12Config();

    ASSERT_TRUE(HITLS_CFG_SetCookieVerifyCb(config, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_SetCookieVerifyCb(config, UT_CookieVerifyCb) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_GET_VERSION_API_TC001
* @title  Test the HITLS_CFG_SetVersion, HITLS_CFG_GetMinVersion, and HITLS_CFG_GetMaxVersion interfaces.
* @precon  nan
* @brief HITLS_CFG_SetVersion
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information, set minVersion to 0, and set maxVersion to a value other than 0.
*    Expected result 2 is obtained.
* 3. Transfer non-empty configuration information, set minVersion to 0, and set maxVersion to 0. Expected result 3 is
*    obtained.
* 4. Transfer non-empty configuration information, set minVersion to 0, and set maxVersion to 0. Expected result 4 is
*    obtained.
* 5. Transfer non-empty configuration information, and set both minVersion and maxVersion to 0. Expected result 5 is
*    obtained.
* 5. Transfer non-empty configuration information, set minVersion to dtls, and set maxVersion to dtls. Expected result 5
*    is obtained.
* 6. Transfer non-empty configuration information, set minVersion to TLCP, and set maxVersion to TLCP. Expected result 5
*    is obtained.
* HITLS_CFG_GetMinVersion
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer an empty MinVersion pointer. Expected result 1 is obtained.
* 3. Transfer the non-null configuration information and the MinVersion pointer is not null. Expected result 5 is
*    obtained.
* HITLS_CFG_GetMaxVersion
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Pass an empty MaxVersion pointer. Expected result 1 is obtained.
* 3. Transfer non-null configuration information and ensure that the MaxVersion pointer is not null. Expected result 5
*    is obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. Returns HITLS_SUCCES and minVersion is HITLS_VERSION_SSL30.
* 3. Returns HITLS_SUCCES and maxVersion is HITLS_VERSION_TLS13.
* 4. The HITLS_SUCCES table is returned, and the version value is 0, which is cleared.
* 5. Returns HITLS_SUCCES with minVersion and maxVersion set to the configured values.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_VERSION_API_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Config *dtlsConfig = NULL;
    HITLS_Config *tlcpConfig = NULL;
    uint16_t minVersion = 0;
    uint16_t maxVersion = 0;

    ASSERT_TRUE(HITLS_CFG_SetVersion(config, minVersion, maxVersion) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetMinVersion(config, &minVersion) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetMaxVersion(config, &maxVersion) == HITLS_NULL_INPUT);

    config = HITLS_CFG_NewTLSConfig();
    dtlsConfig = HITLS_CFG_NewDTLSConfig();
    tlcpConfig = HITLS_CFG_NewTLCPConfig();

    ASSERT_TRUE(HITLS_CFG_GetMinVersion(config, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetMaxVersion(config, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_SetVersion(config, 0, 0) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == TLS_VERSION_MASK);

    ASSERT_TRUE(HITLS_CFG_SetVersion(config, HITLS_VERSION_TLS12, HITLS_VERSION_TLS13) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMinVersion(config, &minVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMaxVersion(config, &maxVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(minVersion == HITLS_VERSION_TLS12 && maxVersion == HITLS_VERSION_TLS13);

    ASSERT_TRUE(HITLS_CFG_SetVersion(config, 0, HITLS_VERSION_TLS13) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMinVersion(config, &minVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMaxVersion(config, &maxVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(minVersion == HITLS_VERSION_TLS12 && maxVersion == HITLS_VERSION_TLS13);
    ASSERT_TRUE(HITLS_CFG_SetVersion(config, HITLS_VERSION_TLS12, 0) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMinVersion(config, &minVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMaxVersion(config, &maxVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(minVersion == HITLS_VERSION_TLS12 && maxVersion == HITLS_VERSION_TLS13);

    ASSERT_TRUE(HITLS_CFG_SetVersion(dtlsConfig, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMinVersion(dtlsConfig, &minVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMaxVersion(dtlsConfig, &maxVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(minVersion == HITLS_VERSION_DTLS12 && maxVersion == HITLS_VERSION_DTLS12);

    ASSERT_TRUE(HITLS_CFG_SetVersion(tlcpConfig, HITLS_VERSION_TLCP_DTLCP11, HITLS_VERSION_TLCP_DTLCP11) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMinVersion(tlcpConfig, &minVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMaxVersion(tlcpConfig, &maxVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(minVersion == HITLS_VERSION_TLCP_DTLCP11 && maxVersion == HITLS_VERSION_TLCP_DTLCP11);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(dtlsConfig);
    HITLS_CFG_FreeConfig(tlcpConfig);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_GET_HASHID_API_TC001
* @title Test the HITLS_CFG_GetHashId interface.
* @precon nan
* @brief
*   1. Input an empty cipher suite. Expected result 1 is obtained.
*   2. Transfer an empty hashId. Expected result 1 is obtained.
*   3. Import the HITLS_RSA_WITH_AES_128_CBC_SHA cipher suite and set hashAlg to HITLS_HASH_BUTT. Expected result 2 is
*      obtained.
* @expect
*   1. Returns HITLS_NULL_INPUT
*   2. HITLS_SUCCESS is returned and HashId is HITLS_HASH_SHA1.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_GET_HASHID_API_TC001(void)
{
    const HITLS_Cipher *cipher = NULL;
    HITLS_HashAlgo hashId = HITLS_HASH_BUTT;
    ASSERT_TRUE(HITLS_CFG_GetHashId(cipher, &hashId) == HITLS_NULL_INPUT);

    const uint16_t cipherID = HITLS_RSA_WITH_AES_128_CBC_SHA;
    cipher = HITLS_CFG_GetCipherByID(cipherID);
    ASSERT_TRUE(HITLS_CFG_GetHashId(cipher, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_GetHashId(cipher, &hashId) == HITLS_SUCCESS);
    ASSERT_TRUE(hashId == HITLS_HASH_SHA1);
EXIT:
    return;
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_GET_MACID_API_TC001
* @title Test the HITLS_CFG_GetMacId interface.
* @precon nan
* @brief
*   1. Input an empty cipher suite. Expected result 1 is obtained.
*   2. Input an empty macAlg. Expected result 1
*   3. Input the HITLS_RSA_WITH_AES_128_CBC_SHA cipher suite and set macAlg to HITLS_MAC_BUTT. Expected result 2 is
*      obtained.
* @expect
*   1. Returns HITLS_NULL_INPUT
*   2. Returns HITLS_SUCCESS and macAlg is HITLS_MAC_1.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_GET_MACID_API_TC001(void)
{
    const HITLS_Cipher *cipher = NULL;
    HITLS_MacAlgo macAlg = HITLS_MAC_BUTT;
    ASSERT_TRUE(HITLS_CFG_GetMacId(cipher, &macAlg) == HITLS_NULL_INPUT);

    const uint16_t cipherID = HITLS_RSA_WITH_AES_128_CBC_SHA;
    cipher = HITLS_CFG_GetCipherByID(cipherID);
    ASSERT_TRUE(HITLS_CFG_GetMacId(cipher, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_GetMacId(cipher, &macAlg) == HITLS_SUCCESS);
    ASSERT_TRUE(macAlg == HITLS_MAC_1);
EXIT:
    return;
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_GET_KEYEXCHID_API_TC001
* @title Test the HITLS_CFG_GetKeyExchId interface.
* @precon nan
* @brief
* 1. Input an empty cipher suite. Expected result 1 is obtained.
* 2. Input null kxAlg. Expected result 1
* 3. Input the HITLS_RSA_WITH_AES_128_CBC_SHA cipher suite and set kxAlg to HITLS_KEY_EXCH_BUTT. Expected result 2 is
*    obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. Returns HITLS_SUCCESS and kxAlg is HITLS_KEY_EXCH_RSA.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_GET_KEYEXCHID_API_TC001(void)
{
    const HITLS_Cipher *cipher = NULL;
    HITLS_KeyExchAlgo kxAlg = HITLS_KEY_EXCH_BUTT;
    ASSERT_TRUE(HITLS_CFG_GetKeyExchId(cipher, &kxAlg) == HITLS_NULL_INPUT);

    const uint16_t cipherID = HITLS_RSA_WITH_AES_128_CBC_SHA;
    cipher = HITLS_CFG_GetCipherByID(cipherID);
    ASSERT_TRUE(HITLS_CFG_GetKeyExchId(cipher, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_GetKeyExchId(cipher, &kxAlg) == HITLS_SUCCESS);
    ASSERT_TRUE(kxAlg == HITLS_KEY_EXCH_RSA);
EXIT:
    return;
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_GET_CIPHERSUITESTDNAME_API_TC001
* @title Test the HITLS_CFG_GetCipherSuiteStdName interface.
* @precon nan
* @brief
*   1. Input an empty cipher suite. Expected result 1 is obtained.
*   2.Import the HITLS_RSA_WITH_AES_128_CBC_SHA cipher suite. Expected result 2 is obtained.
* @expect
*   1. Return "(NONE)"
*   2. Return "TLS_RSA_WITH_AES_128_CBC_SHA256"
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_GET_CIPHERSUITESTDNAME_API_TC001(void)
{
    const HITLS_Cipher *cipher = NULL;
    ASSERT_TRUE(strcmp((char *)HITLS_CFG_GetCipherSuiteStdName(cipher),"(NONE)") == 0);

    const uint16_t cipherID = HITLS_RSA_WITH_AES_128_CBC_SHA;
    cipher = HITLS_CFG_GetCipherByID(cipherID);
    ASSERT_TRUE(strcmp((char *)HITLS_CFG_GetCipherSuiteStdName(cipher),"TLS_RSA_WITH_AES_128_CBC_SHA") == 0);
EXIT:
    return;
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_GET_DESCRIPTION_API_TC001
* @title Test the HITLS_CFG_GetDescription interface.
* @precon nan
* @brief
* 1. Input an empty cipher suite. Expected result 1 is obtained.
* 2. Input an empty buff. Expected result 1 is obtained.
* 3. Transfer a buff whose length is less than the length of CIPHERSUITE_DESCRIPTION_MAXLEN. Expected result 1 is
*    obtained.
* 4. Transfer the abnormal algorithm name cipher suite. Expected result 2 is obtained.
* 5. Import the HITLS_RSA_WITH_AES_128_CBC_SHA cipher suite whose buff size is DEFAULT_DESCRIPTION_LEN. Expected result
*    3 is obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. Returns HITLS_CONFIG_INVALID_LENGTH.
* 3. Returns HITLS_SUCCESS, and buff is Description.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_GET_DESCRIPTION_API_TC001(void)
{
    const HITLS_Cipher *cipher = NULL;
    char buff[DEFAULT_DESCRIPTION_LEN] = {0};
    ASSERT_TRUE(HITLS_CFG_GetDescription(cipher, (uint8_t *)buff, sizeof(buff)) == HITLS_NULL_INPUT);

    const uint16_t cipherID = HITLS_RSA_WITH_AES_128_CBC_SHA;
    cipher = HITLS_CFG_GetCipherByID(cipherID);

    ASSERT_TRUE(HITLS_CFG_GetDescription(cipher, NULL, sizeof(buff)) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_GetDescription(cipher, (uint8_t *)buff, 0) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_GetDescription(cipher, (uint8_t *)buff, sizeof(buff)) == HITLS_SUCCESS);

    HITLS_Cipher *newCipher = (HITLS_Cipher *)malloc(sizeof(HITLS_Cipher));
    memcpy(newCipher, cipher, sizeof(HITLS_Cipher));
    newCipher->name =
        "************************************************************************************************************";

    ASSERT_TRUE(HITLS_CFG_GetDescription(newCipher, (uint8_t *)buff, sizeof(buff)) == HITLS_CONFIG_INVALID_LENGTH);
EXIT:
    free(newCipher);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_CIPHER_ISAEAD_API_TC001
* @title Test the HITLS_CIPHER_IsAead interface.
* @precon nan
* @brief
*   1. Input an empty cipher suite. Expected result 1 is obtained.
*   2. Import the HITLS_RSA_WITH_AES_128_GCM_SHA256 cipher suite. Expected result 2 is obtained.
* @expect
*   1. Returns HITLS_NULL_INPUT
*   2. Returns HITLS_SUCCESS and isAead is true.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_CIPHER_ISAEAD_API_TC001(void)
{
    const HITLS_Cipher *cipher = NULL;
    bool isAead = false;
    ASSERT_TRUE(HITLS_CIPHER_IsAead(cipher, &isAead) == HITLS_NULL_INPUT);

    const uint16_t cipherID = HITLS_RSA_WITH_AES_128_GCM_SHA256;
    cipher = HITLS_CFG_GetCipherByID(cipherID);
    ASSERT_TRUE(HITLS_CIPHER_IsAead(cipher, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CIPHER_IsAead(cipher, &isAead) == HITLS_SUCCESS);
    ASSERT_TRUE(isAead == true);
EXIT:
    return;
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_GET_VERSIONSUPPORT_API_TC001
* @spec  -
* @title Test the HITLS_CFG_SetVersionSupport and HITLS_CFG_GetVersionSupport interfaces.
* @precon nan
* @brief HITLS_CFG_SetVersionSupport
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and set version to an invalid value. Expected result 2 is obtained.
* 3. Transfer non-empty configuration information and set version to a valid value. Expected result 3 is obtained.
* HITLS_CFG_GetVersionSupport
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Pass the null version pointer. Expected result 1 is obtained.
* 3. Transfer non-null configuration information and ensure that the version pointer is not null. Expected result 4 is
*    obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned, and invalid values in config are filtered out.
* 3. HITLS_SUCCES is returned and config is the expected value.
* 4. The HITLS_SUCCES parameter is returned, and the version parameter is set to the value recorded in the config file.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_VERSIONSUPPORT_API_TC001()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    uint32_t version = 0;

    ASSERT_TRUE(HITLS_CFG_SetVersionSupport(config, version) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetVersionSupport(config, &version) == HITLS_NULL_INPUT);

    config = HITLS_CFG_NewTLSConfig();

    ASSERT_TRUE(HITLS_CFG_GetVersionSupport(config, NULL) == HITLS_NULL_INPUT);

    version = (TLS13_VERSION_BIT << 1) | TLS13_VERSION_BIT | TLS12_VERSION_BIT;
    ASSERT_TRUE(HITLS_CFG_SetVersionSupport(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS13);
    version = TLS13_VERSION_BIT | TLS12_VERSION_BIT;
    ASSERT_TRUE(HITLS_CFG_SetVersionSupport(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS13);
    uint32_t getversion = 0;
    ASSERT_TRUE(HITLS_CFG_GetVersionSupport(config, &getversion) == HITLS_SUCCESS);
    ASSERT_TRUE(getversion == config->version);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_GET_QUIETSHUTDOWN_API_TC001
* @title Test the HITLS_CFG_SetQuietShutdown and HITLS_CFG_GetQuietShutdown interfaces.
* @precon nan
* @brief HITLS_CFG_SetQuietShutdown
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and set mode to an invalid value. Expected result 2 is obtained.
* 3. Transfer non-empty configuration information and set mode to a valid value. Expected result 3 is obtained.
* HITLS_CFG_GetQuietShutdown
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer a null mode pointer. Expected result 1 is obtained.
* 3. Transfer non-null configuration information and ensure that the mode pointer is not null. Expected result 3 is
*    obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. Returns HITLS_CONFIG_INVALID_SET
* 3. Returns HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_QUIETSHUTDOWN_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    int32_t mode = 0;

    ASSERT_TRUE(HITLS_CFG_SetQuietShutdown(config, mode) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetQuietShutdown(config, &mode) == HITLS_NULL_INPUT);
    switch (tlsVersion) {
        case HITLS_VERSION_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            break;
        default:
            config = NULL;
            break;
    }

    ASSERT_TRUE(HITLS_CFG_GetQuietShutdown(config, NULL) == HITLS_NULL_INPUT);
    mode = 1;
    ASSERT_TRUE(HITLS_CFG_SetQuietShutdown(config, mode) == HITLS_SUCCESS);
    mode = 2;
    ASSERT_TRUE(HITLS_CFG_SetQuietShutdown(config, mode) == HITLS_CONFIG_INVALID_SET);

    int32_t getMode = -1;
    ASSERT_TRUE(HITLS_CFG_GetQuietShutdown(config, &getMode) == HITLS_SUCCESS);
    ASSERT_TRUE(getMode == config->isQuietShutdown);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_GET_CIPHERSERVERPREFERENCE_API_TC001
* @title Test the HITLS_CFG_SetCipherServerPreference and HITLS_CFG_GetCipherServerPreference interfaces.
* @precon nan
* @brief HITLS_CFG_SetCipherServerPreference
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and set isSupport to an invalid value. Expected result 2 is obtained.
* 3. Transfer a non-empty configuration information and set isSupport to a valid value. Expected result 3 is obtained.
* HITLS_CFG_GetCipherServerPreference
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer an empty isSupport pointer. Expected result 1 is obtained.
* 3. Transfer the non-null configuration information and the isSupport pointer is not null. Expected result 3 is
*    obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned and config->isSupportServerPreference is set to true.
* 3. Returns HITLS_SUCCES, and config->isSupportServerPreference is true or false.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_CIPHERSERVERPREFERENCE_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool isSupport = false;
    bool getIsSupport = false;
    ASSERT_TRUE(HITLS_CFG_SetCipherServerPreference(config, isSupport) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetCipherServerPreference(config, &getIsSupport) == HITLS_NULL_INPUT);

    switch (tlsVersion) {
        case HITLS_VERSION_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            break;
        default:
            config = NULL;
            break;
    }

    ASSERT_TRUE(HITLS_CFG_GetCipherServerPreference(config, NULL) == HITLS_NULL_INPUT);
    isSupport = true;
    ASSERT_TRUE(HITLS_CFG_SetCipherServerPreference(config, isSupport) == HITLS_SUCCESS);
    isSupport = 2;
    ASSERT_TRUE(HITLS_CFG_SetCipherServerPreference(config, isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(config->isSupportServerPreference = true);
    isSupport = false;
    ASSERT_TRUE(HITLS_CFG_SetCipherServerPreference(config, isSupport) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_GetCipherServerPreference(config, &getIsSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(getIsSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_GET_HELLO_VERIFY_REQ_API_TC001
* @title Test the HITLS_CFG_SetDtlsCookieExchangeSupport and HITLS_CFG_GetDtlsCookieExchangeSupport interfaces.
* @precon nan
* @brief HITLS_CFG_SetDtlsCookieExchangeSupport
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer non-empty configuration information and set isSupport to an invalid value. Expected result 2 is obtained.
* 3. Transfer a non-empty configuration information and set isSupport to a valid value. Expected result 3 is obtained.
* HITLS_CFG_GetDtlsCookieExchangeSupport
* 1. Import empty configuration information. Expected result 1 is obtained.
* 2. Transfer an empty isSupport pointer. Expected result 1 is obtained.
* 3. Transfer the non-null configuration information and the isSupport pointer is not null. Expected result 3 is
*    obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned and config->isSupportDtlsCookieExchange is set to true.
* 3. Returns HITLS_SUCCES, and config->isSupportDtlsCookieExchange is true or false.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_HELLO_VERIFY_REQ_API_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool isSupport = false;
    bool getIsSupport = false;
    ASSERT_TRUE(HITLS_CFG_SetDtlsCookieExchangeSupport(config, isSupport) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetDtlsCookieExchangeSupport(config, &getIsSupport) == HITLS_NULL_INPUT);

    config = HITLS_CFG_NewDTLS12Config();

    ASSERT_TRUE(HITLS_CFG_GetDtlsCookieExchangeSupport(config, NULL) == HITLS_NULL_INPUT);
    isSupport = true;
    ASSERT_TRUE(HITLS_CFG_SetDtlsCookieExchangeSupport(config, isSupport) == HITLS_SUCCESS);

    ASSERT_TRUE(config->isSupportDtlsCookieExchange = true);
    isSupport = false;
    ASSERT_TRUE(HITLS_CFG_SetDtlsCookieExchangeSupport(config, isSupport) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_GetDtlsCookieExchangeSupport(config, &getIsSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(getIsSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_RENEGOTIATIONSUPPORT_FUNC_TC001
* @title Test the function of supporting the renegotiation function by setting the HITLS_CFG_SetRenegotiationSupport and
*        obtaining the function of supporting the renegotiation function by the HITLS_CFG_GetRenegotiationSupport.
* @precon nan
* @brief    1. Call HITLS_CFG_SetRenegotiationSupport to disable renegotiation. Expected result 1 is obtained.
*            2. Invoke the HITLS_CFG_GetRenegotiationSupport interface to obtain the configured value. (Expected result
*                2)
*            3. Invoke the HITLS_SetRenegotiationSupport interface to support renegotiation. Expected result 3 is
*                obtained.
*            4. Invoke the HITLS_GetRenegotiationSupport interface to obtain the configured value. Expected result 4 is
*                obtained.
*            5. Establish a connection. and check whether the value of isSecureRenegotiation in the
*               negotiation information is true. Expected result 5 is obtained.
*            6. Perform renegotiation. Expected result 6 is obtained.
* @expect   1. Setting succeeded.
*            2. The interface returns false.
*            3. The setting is successful.
*            4. The interface returns true.
*            5. The value of isSecureRenegotiation is true.
*            6. The renegotiation succeeds.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_RENEGOTIATIONSUPPORT_FUNC_TC001()
{
    FRAME_Init();
    FRAME_LinkObj *clientRes;
    FRAME_LinkObj *serverRes;
    HITLS_Config *config = NULL;
    bool supportrenegotiation = false;
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    HITLS_CFG_SetRenegotiationSupport(config, false);
    HITLS_CFG_GetRenegotiationSupport(config, &supportrenegotiation);
    ASSERT_TRUE(supportrenegotiation == false);

    clientRes = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(clientRes != NULL);
    serverRes = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(serverRes != NULL);

    HITLS_SetRenegotiationSupport(clientRes->ssl, true);
    HITLS_SetRenegotiationSupport(serverRes->ssl, true);
    HITLS_GetRenegotiationSupport(clientRes->ssl, &supportrenegotiation);
    ASSERT_TRUE(supportrenegotiation == true);

    FRAME_CreateConnection(clientRes, serverRes, true, HS_STATE_BUTT);
    ASSERT_TRUE(clientRes->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverRes->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(HITLS_Renegotiate(serverRes->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(clientRes->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_CreateRenegotiationState(clientRes, serverRes, true, HS_STATE_BUTT) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(clientRes);
    FRAME_FreeLink(serverRes);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_ECPOINTFORMATS_FUNC_TC001
* @title Set the normal dot format value.
* @precon nan
* @brief    1. Set pointFormats to HITLS_POINT_FORMAT_UNCOMPRESSED and invoke the HITLS_CFG_SetEcPointFormats interface.
*            Expected result 1 is obtained.
*           2. Set pointFormats to HITLS_POINT_FORMAT_BUTT and invoke the HITLS_CFG_SetEcPointFormats interface.
*           (Expected result 2)
*           3. Use config to generate ctx, due to the result 3
*           4. Set pointFormats to HITLS_POINT_FORMAT_UNCOMPRESSED again and generate ctx again. Expected result 4 is
*            obtained. Set pointFormats to HITLS_POINT_FORMAT_UNCOMPRESSED and invoke the HITLS_SetEcPointFormats
*            interface. (Expected result 2)
*           5. Set pointFormats to HITLS_POINT_FORMAT_UNCOMPRESSED and invoke the HITLS_SetEcPointFormats interface.
*              Expected result 2 is obtained.
* @expect   1. Interface return value, HITLS_SUCCESS
*           2. Interface return value: HITLS_SUCCESS
*           3. Failed to generate the file.
*           4. The file is generated successfully.
*           5. The setting is successful.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_ECPOINTFORMATS_FUNC_TC001(int version)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *Config = NULL;
    HITLS_Ctx *ctx = NULL;
    Config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(Config != NULL);
    const uint8_t pointFormats[] = {HITLS_POINT_FORMAT_UNCOMPRESSED};
    uint32_t pointFormatsSize = sizeof(pointFormats) / sizeof(uint8_t);
    ASSERT_TRUE(HITLS_CFG_SetEcPointFormats(Config, pointFormats, pointFormatsSize) == HITLS_SUCCESS);
    const uint8_t pointFormats2[] = {HITLS_POINT_FORMAT_BUTT};
    uint32_t pointFormatsSize2 = sizeof(pointFormats2) / sizeof(uint8_t);
    ASSERT_TRUE(HITLS_CFG_SetEcPointFormats(Config, pointFormats2, pointFormatsSize2) == HITLS_SUCCESS);
    ctx = HITLS_New(Config);
    if(version == TLS1_2){
        ASSERT_TRUE(ctx == NULL);
    }

    HITLS_Free(ctx);

    ASSERT_TRUE(HITLS_CFG_SetEcPointFormats(Config, pointFormats, pointFormatsSize) == HITLS_SUCCESS);
    ctx = HITLS_New(Config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(HITLS_SetEcPointFormats(ctx, pointFormats, pointFormatsSize) == HITLS_SUCCESS);
    client = FRAME_CreateLink(Config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(Config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(Config);
    HITLS_Free(ctx);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    bool isSupportExtendMasterSecret;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isSupportRenegotiation;
    bool isSupportSessionTicket;
    bool needStopBeforeRecvCCS;
} HandshakeTestInfo;

/** @
* @test  UT_TLS_CFG_SET_GROUPS_FUNC_TC001
* @title Sets the elliptic curve that does not exist.
* @precon nan
* @brief    1. Set group to 0x0001 and invoke the HITLS_CFG_SetGroups interface. Expected result 1 is obtained.
*           2. Establish a connection. Check whether the group value in the client hello message sent by the client is
*              0x0001.Expected result 2 is obtained.
*           3. Establish a connection and check whether the connection is successfully established. (Expected result 3)
* @expect   1. Interface HITLS_SUCCESS
*           2. The value of group in the client hello message is 0x0001.
*           3. connection establishment fails.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_GROUPS_FUNC_TC001(int version)
{
    FRAME_Init();
    HandshakeTestInfo testInfo = {0};
    uint16_t group[] = {ERROR_HITLS_GROUP};
    uint32_t grouplength = sizeof(group) / sizeof(uint16_t);
    testInfo.isClient = false;
    testInfo.config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(testInfo.config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetGroups(testInfo.config, group, grouplength) == HITLS_SUCCESS);
    if (version == TLS1_2) {
        uint16_t cipherSuite[] = {HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};
        HITLS_CFG_SetCipherSuites(testInfo.config, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));
    }
    FRAME_CertInfo certInfo = {
        "rsa_sha/ca-3072.der:rsa_sha/inter-3072.der",
        "rsa_sha/inter-3072.der",
        "rsa_sha/end-sha256.der",
        NULL,
        "rsa_sha/end-sha256.key.der",
        NULL,
    };
    testInfo.client = FRAME_CreateLinkWithCert(testInfo.config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLinkWithCert(testInfo.config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, testInfo.isClient, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_SIGNATURE_FUNC_TC001
* @title Set a nonexistent signature algorithm.
* @precon nan
* @brief
*    1. Set Signature to 0xffff and call the HITLS_CFG_SetSignature interface. (Expected result 1)
* @expect
*    1. Interface return value: HITLS_CONFIG_INVALID_LENGTH
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_SIGNATURE_FUNC_TC001(int version)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {ERROR_HITLS_SIGNATURE};

    ASSERT_TRUE(HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t)) == HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client == NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server == NULL);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

void ExampleInfoCallback(const HITLS_Ctx *ctx, int32_t eventType, int32_t value)
{
    (void)ctx;
    (void)eventType;
    (void)value;
}

#define MSG_CB_PRINT_LEN 500

void msg_callback(int32_t writePoint, int32_t tlsVersion, int32_t contentType, const void *msg,
                    uint32_t msgLen, HITLS_Ctx *ctx, void *arg)
{
   (void)writePoint;
   (void)tlsVersion;
   (void)contentType;
   (void)msg;
   (void)msgLen;
   (void)ctx;
   (void)arg;
}

/* @
* @test  UT_TLS_CFG_InfoCb_API_TC001
* @title  InfoCb Interface Parameter Test
* @precon  nan
* @brief
1. Use the HITLS_CFG_GetInfoCb without HITLS_CFG_SetInfoCb. Expected result 1 is obtained.
2. Use the HITLS_CFG_SetInfoCb interface to set callback. Expected result 2
3. Use the HITLS_CFG_GetInfoCb . Expected result 3
4. Use the HITLS_CFG_GetInfoCb with the parameter is NULL . Expected result 4
* @expect
1. Return the NULL.
2. Return the HITLS_SUCCESS
3. Return value is not NULL.
4. Return the NULL.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_InfoCb_API_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_InfoCb infoCallBack = HITLS_CFG_GetInfoCb(config);
    ASSERT_TRUE(infoCallBack == NULL);
    int32_t ret = HITLS_CFG_SetInfoCb(config, ExampleInfoCallback);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    infoCallBack = HITLS_CFG_GetInfoCb(config);
    ASSERT_TRUE(infoCallBack != NULL);
    infoCallBack = HITLS_CFG_GetInfoCb(NULL);
    ASSERT_TRUE(infoCallBack == NULL);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_SetMsgCb_API_TC001
* @title  HITLS_CFG_SetMsgCb Interface Parameter Test
* @precon  nan
* @brief
1. Set config to NULL. Expected result 1 is obtained.
2. Invoke the HITLS_CFG_SetMsgCb interface to set callback. (Expected result 2)
* @expect
1. Return the HITLS_NULL_INPUT message.
2. Return the HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SetMsgCb_API_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetMsgCb(NULL, msg_callback), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_SetMsgCb(tlsConfig, msg_callback), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_SetMsgCbArg_API_TC001
* @title  HITLS_CFG_SetMsgCbArg Interface Parameter Test
* @precon  nan
* @brief  1. Set config to NULL. Expected result 1 is obtained.
2. Use the HITLS_CFG_SetMsgCbArg interface to set Arg. Expected result 2 is obtained.
* @expect 1. The HITLS_NULL_INPUT message is returned.
2. Return the HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SetMsgCbArg_API_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig;
    tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetMsgCbArg(NULL, msg_callback), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_SetMsgCbArg(tlsConfig, msg_callback), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_SETTMPDH_FUNC_TC001
* @title  Set tmpdhkey. The link setup status varies according to the security level.
* @precon  nan
* @brief
* 1. Set the RSA certificate and algorithm suite.
* 2. Set the dh key to not follow the certificate, and set the tmpdh key with 80 security bits.
* 3. Set the security level to 0 and set up a link.
* 4. Set the security level to 2 and set up a link.
* @expect
* 1. The setting is successful.
* 2. The setting is successful.
* 3. The link is set up successfully.
* 4. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SETTMPDH_FUNC_TC001(int level)
{
    (void)level;
    FRAME_Init();
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_CRYPT_Key *key = NULL;
    uint16_t pfsCipherSuites[] = {HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256};

    clientConfig = HITLS_CFG_NewTLS12Config();
    serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(serverConfig != NULL);

    ASSERT_TRUE(HiTLS_X509_LoadCertAndKey(clientConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH,
                RSA_SHA256_EE_PATH3, NULL, RSA_SHA256_PRIV_PATH3,NULL) == HITLS_SUCCESS);
    ASSERT_TRUE(HiTLS_X509_LoadCertAndKey(serverConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH,
                RSA_SHA256_EE_PATH3, NULL, RSA_SHA256_PRIV_PATH3,NULL) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(clientConfig, pfsCipherSuites, sizeof(pfsCipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(serverConfig, pfsCipherSuites, sizeof(pfsCipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    HITLS_CFG_SetSecurityLevel(serverConfig, level);
    HITLS_CFG_SetSecurityLevel(clientConfig, level);

    HITLS_CFG_SetDhAutoSupport(serverConfig, false);
    int32_t secBits = 80;
    key = HITLS_CRYPT_GenerateDhKeyBySecbits(LIBCTX_FROM_CONFIG(serverConfig), ATTRIBUTE_FROM_CONFIG(serverConfig),
        serverConfig, secBits);
    HITLS_CFG_SetTmpDh(serverConfig, key);

    FRAME_CertInfo certInfo = {0, 0, 0, 0, 0, 0};
    client = FRAME_CreateLinkWithCert(clientConfig, BSL_UIO_TCP, &certInfo);
    server = FRAME_CreateLinkWithCert(serverConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    if (level > 1) {
        ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_KEY_EXCHANGE), HITLS_SUCCESS);
        FRAME_TrasferMsgBetweenLink(server, client);
        HITLS_Connect(client->ssl);
        ASSERT_EQ(HITLS_Accept(server->ssl) , HITLS_MSG_HANDLE_ERR_GET_DH_KEY);
    } else {
        ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    }
EXIT:
    if (SECURITY_GetSecbits(level) > secBits) {
        SAL_CRYPT_FreeDhKey(key);
    }
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_SET_POSTHANDSHAKEAUTHSUPPORT_API_TC001
*
* @title Test the HITLS_SetPostHandshakeAuthSupport interface.
*
* @brief
* 1. The default value of the TLS connection handle isSupportPostHandshakeAuth is fasle. Expected result 1。
* 2. Run the HITLS_SetPostHandshakeAuthSupport command to set a handle. The value of isSupportPostHandshakeAuth is true.
* Expected result 2.
* @expect
* 1.  isSupportPostHandshakeAuth is false.
* 2.  isSupportPostHandshakeAuth is true.
@*/
/* BEGIN_CASE */
void UT_TLS_CFG_SET_POSTHANDSHAKEAUTHSUPPORT_API_TC001(int tlsVersion)
{
    HitlsInit();
    HITLS_Config *tlsConfig = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(tlsConfig != NULL);

    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(ctx->config.tlsConfig.isSupportPostHandshakeAuth == false);

    int ret = HITLS_SetPostHandshakeAuthSupport(ctx, true);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(ctx->config.tlsConfig.isSupportPostHandshakeAuth == true);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_GET_SECURE_RENEGOTIATIONSUPPORET_FUNC_TC001
* @title  HITLS_GetSecureRenegotationSupport The client does not support security renegotiation,
*         but the server supports security renegotiation. Obtains whether security renegotiation is supported.
* @precon  nan
* @brief HITLS_GetSecureRenegotationSupport
* 1. Transfer an empty TLS connection handle. Expected result 1.
* 2. Transfer the non-empty TLS connection handle information and leave isSecureRenegotiation blank. Expected result 1.
* 3. Transfer the non-empty TLS connection handle information. The isSecureRenegotiation parameter is not empty.
*    Expected result 2.
* @expect
*   1. Returns HITLS_NULL_INPUT
*   2. Returns HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_GET_SECURE_RENEGOTIATIONSUPPORET_API_TC001(void)
{
    HitlsInit();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool isSecureRenegotiation = false;
    ASSERT_TRUE(HITLS_GetSecureRenegotiationSupport(NULL, &isSecureRenegotiation) == HITLS_NULL_INPUT);

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetSecureRenegotiationSupport(ctx, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetSecureRenegotiationSupport(ctx, &isSecureRenegotiation) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_GET_DHAUTOSUPPORT_FUNC_TC001
* @title Test the HITLS_SetDhAutoSupport and HITLS_CFG_GetDhAutoSupport interfaces.
* @precon nan
* @brief
* 1. Invoke the HITLS_CFG_SetDhAutoSupport interface to set the parameter to false. Expected result 1 is obtained.
* 2. Establish a connection. Expected result 2 is obtained.
* @expect
* 1. The setting is successful.
* 2. connection establishment fails.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_DHAUTOSUPPORT_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint16_t pfsCipherSuites[] = {HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256};

    clientConfig = HITLS_CFG_NewTLS12Config();
    serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(serverConfig != NULL);

    ASSERT_TRUE(HiTLS_X509_LoadCertAndKey(clientConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH,
                RSA_SHA256_EE_PATH3, NULL, RSA_SHA256_PRIV_PATH3,NULL) == HITLS_SUCCESS);
    ASSERT_TRUE(HiTLS_X509_LoadCertAndKey(serverConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH,
                RSA_SHA256_EE_PATH3, NULL, RSA_SHA256_PRIV_PATH3,NULL) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(clientConfig, pfsCipherSuites, sizeof(pfsCipherSuites) / sizeof(uint16_t)) ==
        HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(serverConfig, pfsCipherSuites, sizeof(pfsCipherSuites) / sizeof(uint16_t)) ==
        HITLS_SUCCESS);

    HITLS_CFG_SetDhAutoSupport(serverConfig, false);

    FRAME_CertInfo certInfo = {0, 0, 0, 0, 0, 0};
    client = FRAME_CreateLinkWithCert(clientConfig, BSL_UIO_TCP, &certInfo);
    server = FRAME_CreateLinkWithCert(serverConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_KEY_EXCHANGE), HITLS_SUCCESS);
    FRAME_TrasferMsgBetweenLink(server, client);
    HITLS_Connect(client->ssl);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_ERR_GET_DH_KEY);
EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */