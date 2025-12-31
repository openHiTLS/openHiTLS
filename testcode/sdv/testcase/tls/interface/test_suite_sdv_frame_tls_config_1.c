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
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <stddef.h>
#include <sys/types.h>
#include <regex.h>
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
#include <stdlib.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_log.h"
#include "bsl_err.h"
#include "bsl_uio.h"
#include "hitls_crypt_reg.h"
#include "hitls_session.h"
#include "cert_method.h"
#include "bsl_list.h"
#include "session_mgr.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_verify.h"
#define DEFAULT_DESCRIPTION_LEN 128
#define MAX_PATH_LEN 4096
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

HITLS_CERT_X509 *HiTLS_X509_LoadCertFile(HITLS_Config *tlsCfg, const char *file);
void SAL_CERT_X509Free(HITLS_CERT_X509 *cert);

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

int32_t Stub_Write(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    (void)uio;
    (void)buf;
    (void)len;
    (void)writeLen;
    return HITLS_SUCCESS;
}

int32_t Stub_Read(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    (void)uio;
    (void)buf;
    (void)len;
    (void)readLen;
    return HITLS_SUCCESS;
}

int32_t Stub_Ctrl(BSL_UIO *uio, BSL_UIO_CtrlParameter cmd, void *param)
{
    (void)uio;
    (void)cmd;
    (void)param;
    return HITLS_SUCCESS;
}
/* END_HEADER */

/** @
* @test  UT_TLS_CFG_SET_VERSION_API_TC001
* @title Overwrite the input parameter of the HITLS_CFG_SetVersion interface.
* @precon nan
* @brief 1. Invoke the HITLS_CFG_SetVersion interface and leave config blank. Expected result 2 .
* 2. Invoke the HITLS_CFG_SetVersion interface. The config parameter is not empty. The minimum version number is
*   DTLS1.0, and the maximum version number is DTLS1.2. Expected result 2 .
* 3. Invoke the HITLS_CFG_SetVersion interface. The config parameter is not empty, the minimum version number is
*   DTLS1.2, and the maximum version number is DTLS1.2. Expected result 1 .
* 4. Invoke the HITLS_CFG_SetVersion interface, set config to a value, set the minimum version number to DTLS1.2, and
*   set the maximum version number to DTLS1.0. Expected result 2 .
* 5. Invoke the HITLS_CFG_SetVersion interface, set config to a value, set the minimum version number to DTLS1.2, and
*   set the maximum version number to TLS1.0. (Expected result 2)
* 6. Invoke the HITLS_CFG_SetVersion interface, set config to a value, set the minimum version number to DTLS1.2, and
*   set the maximum version number to TLS1.2. Expected result 2 .
* 7. Invoke the HITLS_CFG_SetVersion interface, set config to a value, set the minimum version number to TLS1.0, and set
*   the maximum version number to DTLS1.2. Expected result 2 .
* 8. Invoke the HITLS_CFG_SetVersion interface, set config to a value, set the minimum version number to TLS1.2, and set
*   the maximum version number to DTLS1.2. Expected result 2 .
* @expect 1. The interface returns a success response, HITLS_SUCCESS.
*         2. The interface returns an error code.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_VERSION_API_TC001(void)
{
    HitlsInit();

    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);

    int32_t ret;
    ret = HITLS_CFG_SetVersion(NULL, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12);
    ASSERT_TRUE(ret != HITLS_SUCCESS);

    ret = HITLS_CFG_SetVersion(tlsConfig, HITLS_VERSION_DTLS10, HITLS_VERSION_DTLS12);
    ASSERT_TRUE(ret != HITLS_SUCCESS);

    ret = HITLS_CFG_SetVersion(tlsConfig, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HITLS_CFG_SetVersion(tlsConfig, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS10);
    ASSERT_TRUE(ret != HITLS_SUCCESS);

    ret = HITLS_CFG_SetVersion(tlsConfig, HITLS_VERSION_DTLS12, HITLS_VERSION_TLS10);
    ASSERT_TRUE(ret != HITLS_SUCCESS);

    ret = HITLS_CFG_SetVersion(tlsConfig, HITLS_VERSION_DTLS12, HITLS_VERSION_TLS12);
    ASSERT_TRUE(ret != HITLS_SUCCESS);

    ret = HITLS_CFG_SetVersion(tlsConfig, HITLS_VERSION_TLS10, HITLS_VERSION_DTLS12);
    ASSERT_TRUE(ret != HITLS_SUCCESS);

    ret = HITLS_CFG_SetVersion(tlsConfig, HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12);
    ASSERT_TRUE(ret != HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_GET_VERSIONFORBID_API_TC001
* @title Test the HITLS_CFG_SetVersionForbid interface.
* @precon nan
* @brief HITLS_CFG_SetVersionForbid
* 1. Import empty configuration information. Expected result 1.
* 2. Transfer non-empty configuration information and set version to an invalid value. Expected result 2.
* 3. Transfer non-empty configuration information and set version to a valid value. Expected result 3.
* 4. Use HITLS_CFG_GetVersionSupport to view the result.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned, and invalid values in config are filtered out.
* 3. HITLS_SUCCES is returned and config is the expected value.
* 4. The HITLS_SUCCES parameter is returned, and the version parameter is set to the value recorded in the config file.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_VERSIONFORBID_API_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    uint32_t version = TLS12_VERSION_BIT;

    ASSERT_TRUE(HITLS_CFG_SetVersionSupport(config, version) == HITLS_NULL_INPUT);

    version = 0;
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == TLS12_VERSION_BIT);
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS12);
    HITLS_CFG_FreeConfig(config);

    config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == (TLS_VERSION_MASK | TLCP11_VERSION_BIT));
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS13);
    HITLS_CFG_FreeConfig(config);

    config = HITLS_CFG_NewTLS12Config();
    version = TLS12_VERSION_BIT;
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == 0);
    ASSERT_TRUE(config->minVersion == 0 && config->maxVersion == 0);
    HITLS_CFG_FreeConfig(config);
    config = HITLS_CFG_NewTLS12Config();
    version = DTLS12_VERSION_BIT;
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == TLS12_VERSION_BIT);
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS12);

    version = 0x10000000U;
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == TLS12_VERSION_BIT);
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS12);
    HITLS_CFG_FreeConfig(config);

    config = HITLS_CFG_NewTLSConfig();
    version = DTLS12_VERSION_BIT;
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == (TLS_VERSION_MASK | TLCP11_VERSION_BIT));
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS13);

    version = 0x10000000U;
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == (TLS_VERSION_MASK | TLCP11_VERSION_BIT));
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS13);
    HITLS_CFG_FreeConfig(config);

    config = HITLS_CFG_NewTLSConfig();
    version = TLS13_VERSION_BIT;
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == (TLS12_VERSION_BIT | TLCP11_VERSION_BIT));
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS12);

    HITLS_CFG_FreeConfig(config);
    config = HITLS_CFG_NewTLSConfig();
    version = STREAM_VERSION_BITS;
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == 0);
    ASSERT_TRUE(config->minVersion == 0 && config->maxVersion == 0);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_GET_VERSIONFORBID_API_TC002
* @title Test the HITLS_CFG_SetVersionForbid interface.
* @precon nan
* @brief HITLS_CFG_SetVersionForbid
* 1. Use HITLS_CFG_SetVersionForbid disable all version. Expected result 1.
* 2. Use HITLS_CFG_SetVersionSupport to set tls12 version. Expected result 2.
* 3. Use HITLS_CFG_GetVersionSupport to set tls13 version.
* @expect
* 1. config->version is 0, config->minVersion and config->maxVersion are 0.
* 2. config->version is TLS12_VERSION_BIT, config->minVersion and config->maxVersion are HITLS_VERSION_TLS12.
* 3. config->version is (TLS12_VERSION_BIT | TLS13_VERSION_BIT),
     config->minVersion is HITLS_VERSION_TLS12 and config->maxVersion is HITLS_VERSION_TLS13.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_VERSIONFORBID_API_TC002(void)
{
    FRAME_Init();
    uint32_t version = TLS_VERSION_MASK | TLCP11_VERSION_BIT;
    HITLS_Config *config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == 0);
    ASSERT_TRUE(config->minVersion == 0 && config->maxVersion == 0);

    version = TLS12_VERSION_BIT;
    ASSERT_TRUE(HITLS_CFG_SetVersionSupport(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == TLS12_VERSION_BIT);
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS12);

    version = TLS13_VERSION_BIT;
    ASSERT_TRUE(HITLS_CFG_SetVersionSupport(config, version) == HITLS_SUCCESS);
    ASSERT_TRUE(config->version == (TLS12_VERSION_BIT | TLS13_VERSION_BIT));
    ASSERT_TRUE(config->minVersion == HITLS_VERSION_TLS12 && config->maxVersion == HITLS_VERSION_TLS13);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_GET_EXTENEDMASTERSECRETSUPPORT_API_TC001
* @spec  -
* @title Test the HITLS_CFG_SetExtenedMasterSecretSupport and HITLS_CFG_GetExtenedMasterSecretSupport interfaces.
* @precon nan
* @brief HITLS_CFG_SetExtenedMasterSecretSupport
* 1. Import empty configuration information. Expected result 1.
* 2. Transfer non-empty configuration information and set support to an invalid value. Expected result 2.
* 3. Transfer non-empty configuration information and set support to a valid value. Expected result 3.
*    HITLS_CFG_GetExtenedMasterSecretSupport
* 1. Import empty configuration information. Expected result 1.
* 2. Transfer an empty isSupport pointer. Expected result 1.
* 3. Transfer the non-null configuration information and the isSupport pointer is not null. Expected result 3 is
*    obtained.
* @expect 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned and config->isSupportExtendMasterSecret is true.
* 3. Returns HITLS_SUCCES and config->isSupportExtendMasterSecret is true or false.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_EXTENEDMASTERSECRETSUPPORT_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool support = -1;
    bool isSupport = -1;
    ASSERT_TRUE(HITLS_CFG_SetExtenedMasterSecretSupport(config, support) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetExtenedMasterSecretSupport(config, &isSupport) == HITLS_NULL_INPUT);

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

    ASSERT_TRUE(HITLS_CFG_GetExtenedMasterSecretSupport(config, NULL) == HITLS_NULL_INPUT);

    support = true;
    ASSERT_TRUE(HITLS_CFG_SetExtenedMasterSecretSupport(config, support) == HITLS_SUCCESS);

    support = -1;
    ASSERT_TRUE(HITLS_CFG_SetExtenedMasterSecretSupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetExtenedMasterSecretSupport(config, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == true);

    support = false;
    ASSERT_TRUE(HITLS_CFG_SetExtenedMasterSecretSupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetExtenedMasterSecretSupport(config, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_GET_POSTHANDSHAKEAUTHSUPPORT_API_TC001
* @spec  -
* @titleTest the HITLS_CFG_SetPostHandshakeAuthSupport and HITLS_CFG_GetPostHandshakeAuthSupport interfaces.
* @precon nan
* @brief HITLS_CFG_SetPostHandshakeAuthSupport
* 1. Import empty configuration information. Expected result 1.
* 2. Transfer non-empty configuration information and set support to an invalid value. Expected result 2.
* 3. Transfer non-empty configuration information and set support to a valid value. Expected result 3.
*    HITLS_CFG_GetPostHandshakeAuthSupport
* 1. Import empty configuration information. Expected result 1.
* 2. Transfer an empty isSupport pointer. Expected result 1.
* 3. Transfer the non-null configuration information and the isSupport pointer is not null. Expected result 3 is
*    obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned and the value of config->isSupportPostHandshakeAuth is true.
* 3. HITLS_SUCCES is returned and config->isSupportPostHandshakeAuth is true or false.
@ */

/* BEGIN_CASE */
void  UT_TLS_CFG_SET_GET_POSTHANDSHAKEAUTHSUPPORT_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool support = -1;
    bool isSupport = -1;
    ASSERT_TRUE(HITLS_CFG_SetPostHandshakeAuthSupport(config, support) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetPostHandshakeAuthSupport(config, &isSupport) == HITLS_NULL_INPUT);

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

    ASSERT_TRUE(HITLS_CFG_GetPostHandshakeAuthSupport(config, NULL) == HITLS_NULL_INPUT);

    support = true;
    ASSERT_TRUE(HITLS_CFG_SetPostHandshakeAuthSupport(config, support) == HITLS_SUCCESS);

    support = -1;
    ASSERT_TRUE(HITLS_CFG_SetPostHandshakeAuthSupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetPostHandshakeAuthSupport(config, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == true);

    support = false;
    ASSERT_TRUE(HITLS_CFG_SetPostHandshakeAuthSupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetPostHandshakeAuthSupport(config, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_CIPHERSUITES_FUNC_TC001
* @title Test the HITLS_CFG_SetCipherSuites and HITLS_CFG_ClearTLS13CipherSuites interfaces.
* @precon nan
* @brief
* 1. The client invokes the HITLS_CFG_SetCipherSuites interface to set the tls1.3 cipher suite HITLS_AES_128_GCM_SHA256.
*    Expected result 1.
* 2. Call HITLS_CFG_ClearTLS13CipherSuites to clear the TLS1.3 algorithm suite. Expected result 2.
* 3. Check whether the value of config->tls13CipherSuites is NULL and whether the value of config->tls13cipherSuitesSize
*     is 0. (Expected result 3)
* 4. Establish a connection. Expected result 4.
* @expect
* 1. The setting is successful.
* 2. The interface returns a success message.
* 3. config->tls13CipherSuites, config->tls13cipherSuitesSize = 0
* 4. TLS1.3 initialization fails, and TLS1.2 connection are established.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_CIPHERSUITES_FUNC_TC001(int tlsVersion)
{
    FRAME_Init();

    HITLS_Config *config_c = NULL;
    HITLS_Config *config_s = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    uint16_t cipherSuites[1] = {
        HITLS_AES_128_GCM_SHA256
    };

    config_c = GetHitlsConfigViaVersion(tlsVersion);
    config_s = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(config_c, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t))
    == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_ClearTLS13CipherSuites(config_c) == HITLS_SUCCESS);
    ASSERT_TRUE(config_c->tls13CipherSuites == NULL);
    ASSERT_TRUE(config_c->tls13cipherSuitesSize == 0);

    FRAME_CertInfo certInfo = {
        "ecdsa/ca-nist521.der:ecdsa/inter-nist521.der:rsa_sha/ca-3072.der:rsa_sha/inter-3072.der",
        NULL, NULL, NULL, NULL, NULL,};

    client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfo);
    if (tlsVersion == TLS1_3) {
        ASSERT_TRUE(client == NULL);
        goto EXIT;
    }
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
* @
* @test  UT_TLS_CFG_SET_GET_KEYEXCHMODE_FUNC_TC001
* @title Setting the key exchange mode
* @precon nan
* @brief
* 1. Call HITLS_CFG_SetKeyExchMode to set the key exchange mode to TLS13_KE_MODE_PSK_ONLY. Expected result 1 is
*        obtained.
* 2. Invoke the HITLS_CFG_GetKeyExchMode interface. (Expected result 2)
* 3. Call HITLS_CFG_SetKeyExchMode to set the key exchange mode to TLS13_KE_MODE_PSK_WITH_DHE. Expected result 3 is
*    obtained.
* 4. Invoke the HITLS_CFG_GetKeyExchMode interface. (Expected result 4)
* @expect
* 1. The setting is successful.
* 2. The returned value is the same as that of TLS13_KE_MODE_PSK_ONLY.
* 3. The setting is successful.
* 4. The return value of the interface is the same as that of TLS13_KE_MODE_PSK_WITH_DHE.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_KEYEXCHMODE_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();

    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetKeyExchMode(testInfo.config), TLS13_KE_MODE_PSK_ONLY);
    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_WITH_DHE), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetKeyExchMode(testInfo.config), TLS13_KE_MODE_PSK_WITH_DHE);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
}
/* END_CASE */


/** @
* @test  UT_TLS_CFG_SET_GET_VERSIONSUPPORT_API_TC001
* @spec  -
* @title Test the HITLS_CFG_SetVersionSupport and HITLS_CFG_GetVersionSupport interfaces.
* @precon nan
* @brief HITLS_CFG_SetVersionSupport
* 1. Import empty configuration information. Expected result 1.
* 2. Transfer non-empty configuration information and set version to an invalid value. Expected result 2.
* 3. Transfer non-empty configuration information and set version to a valid value. Expected result 3.
* HITLS_CFG_GetVersionSupport
* 1. Import empty configuration information. Expected result 1.
* 2. Pass the null version pointer. Expected result 1.
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
* @test  UT_TLS_CFG_SET_GET_ENCRYPTTHENMAC_API_TC001
* @spec  -
* @title Test the HITLS_CFG_SetEncryptThenMac and HITLS_CFG_GetEncryptThenMac interfaces.
* @precon nan
* @brief HITLS_CFG_SetEncryptThenMac
* 1. Import empty configuration information. Expected result 1.
* 2. Transfer non-null configuration information and set encryptThenMacType to an invalid value. Expected result 2 is
*   obtained.
* 3. Transfer the non-empty configuration information and set encryptThenMacType to a valid value. Expected result 3 is
*   obtained.
* HITLS_CFG_GetEncryptThenMac
* 1. Import empty configuration information. Expected result 1.
* 2. Pass the null encryptThenMacType pointer. Expected result 1.
* 3. Transfer non-null configuration information and ensure that the encryptThenMacType pointer is not null. Expected
*   result 3.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned and config->isEncryptThenMac is true.
* 3. Returns HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_ENCRYPTTHENMAC_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool encryptThenMacType = false;

    ASSERT_TRUE(HITLS_CFG_SetEncryptThenMac(config, encryptThenMacType) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetEncryptThenMac(config, &encryptThenMacType) == HITLS_NULL_INPUT);
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

    ASSERT_TRUE(HITLS_CFG_GetEncryptThenMac(config, NULL) == HITLS_NULL_INPUT);
    encryptThenMacType = true;
    ASSERT_TRUE(HITLS_CFG_SetEncryptThenMac(config, encryptThenMacType) == HITLS_SUCCESS);
    encryptThenMacType = true;
    ASSERT_TRUE(HITLS_CFG_SetEncryptThenMac(config, encryptThenMacType) == HITLS_SUCCESS);
    ASSERT_TRUE(config->isEncryptThenMac == true);

    bool getencryptThenMacType = false;
    ASSERT_TRUE(HITLS_CFG_GetEncryptThenMac(config, &getencryptThenMacType) == HITLS_SUCCESS);
    ASSERT_TRUE(getencryptThenMacType == config->isEncryptThenMac);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_IS_DTLS_API_TC001
* @title Test the HITLS_CFG_IsDtls interface.
* @precon nan
* @brief
* 1. Transfer empty configuration information. Expected result 1.
* 2. Transfer the null pointer isDtls. Expected result 1.
* 3. Transfer the configuration information and ensure that the isDtls pointer is not null. Expected result 2 is
*     obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. The HITLS_SUCCESS and isDtls information is returned.
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_IS_DTLS_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool isDtls = false;

    ASSERT_TRUE(HITLS_CFG_IsDtls(config, &isDtls) == HITLS_NULL_INPUT);
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

    ASSERT_TRUE(HITLS_CFG_IsDtls(config, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_IsDtls(config, &isDtls) == HITLS_SUCCESS);
    ASSERT_TRUE(isDtls == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *s_config;
    HITLS_Config *c_config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession;
    HITLS_TicketKeyCb serverKeyCb;
} ResumeTestInfo1;

HITLS_CRYPT_Key *cert_key = NULL;
HITLS_CRYPT_Key* DH_CB(HITLS_Ctx *ctx, int32_t isExport, uint32_t keyLen)
{
    (void)ctx;
    (void)isExport;
    (void)keyLen;
    return cert_key;
}

uint64_t RECORDPADDING_CB(HITLS_Ctx *ctx, int32_t type, uint64_t length, void *arg)
{
    (void)ctx;
    (void)type;
    (void)length;
    (void)arg;
    return 100;
}
int32_t RecParseInnerPlaintext(TLS_Ctx *ctx, const uint8_t *text, uint32_t *textLen, uint8_t *recType);
int32_t STUB_RecParseInnerPlaintext(TLS_Ctx *ctx, const uint8_t *text, uint32_t *textLen, uint8_t *recType)
{
    (void)ctx;
    (void)text;
    (void)textLen;
    *recType = (uint8_t)REC_TYPE_APP;

    return HITLS_SUCCESS;
}

/** @
* @test  UT_TLS_CFG_GET_RECORDPADDING_API_TC001
* @title  HITLS_CFG_SetRecordPaddingCb Connection
* @precon  nan
* @brief    1. If config is empty, expected result 1.
            2. RecordPADDING_CB is empty. Expected result 2.
            3. RecordPADDING_CB is not empty. Expected result 3.
* @expect   1. The interface returns HITLS_NULL_INPUT.
            2. The interface returns HITLS_SUCCESS.
            3. The interface returns HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_GET_RECORDPADDING_API_TC001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Config is empty
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCb(NULL, RECORDPADDING_CB) ==  HITLS_NULL_INPUT);

    // RecordPADDING_CB is empty
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCb(config, NULL) ==  HITLS_SUCCESS);

    // RecordPADDING_CB is not empty
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCb(config, RECORDPADDING_CB) ==  HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetRecordPaddingCb(config) == RECORDPADDING_CB);
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCbArg(config, RECORDPADDING_CB) ==  HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCbArg(NULL, RECORDPADDING_CB) ==  HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCbArg(config, NULL) ==  HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_RECORDPADDINGARG_API_TC001
* @title  HITLS_CFG_SetRecordPaddingCbArg Connection
* @precon  nan
* @brief    1. If config is empty, expected result 1.
            2. RecordPADDING_CB is empty. Expected result 2.
            3. RecordPADDING_CB is not empty. Expected result 3.
* @expect   1. The interface returns HITLS_NULL_INPUT.
            2. The interface returns HITLS_SUCCESS.
            3. The interface returns HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_RECORDPADDINGARG_API_TC001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Config is empty
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCb(NULL, RECORDPADDING_CB) ==  HITLS_NULL_INPUT);

    // RecordPADDING_CB is empty
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCb(config, NULL) ==  HITLS_SUCCESS);

    // RecordPADDING_CB is not empty
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCb(config, RECORDPADDING_CB) ==  HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetRecordPaddingCb(config) == RECORDPADDING_CB);
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCbArg(config, RECORDPADDING_CB) ==  HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCbArg(NULL, RECORDPADDING_CB) ==  HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCbArg(config, NULL) ==  HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

int32_t EXAMPLE_TicketKeyCallback(
    uint8_t *keyName, uint32_t keyNameSize, HITLS_CipherParameters *cipher, uint8_t isEncrypt)
{
    (void)keyName;
    (void)keyNameSize;
    (void)cipher;
    (void)isEncrypt;
    return 100;
}

/** @
* @test  UT_TLS_CFG_SET_TICKET_CB_API_TC001
* @title  Test HITLS_CFG_SetTicketKeyCallback interface
* @brief    1. If config is empty, expected result 1.
            2. HITLS_CFG_SetTicketKeyCallback is empty. Expected result 2
            3. HITLS_CFG_SetTicketKeyCallback is not empty. Expected result 2
* @expect   1. Returns HITLS_NULL_INPUT.
            2. Returns HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_TICKET_CB_API_TC001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Config is empty
    ASSERT_TRUE(HITLS_CFG_SetTicketKeyCallback(NULL, EXAMPLE_TicketKeyCallback) ==  HITLS_NULL_INPUT);

    // HITLS_TicketKeyCb is empty
    ASSERT_TRUE(HITLS_CFG_SetTicketKeyCallback(config, NULL) ==  HITLS_SUCCESS);

    // HITLS_TicketKeyCb is not empty
    ASSERT_TRUE(HITLS_CFG_SetTicketKeyCallback(config, EXAMPLE_TicketKeyCallback) ==  HITLS_SUCCESS);

    SESSMGR_SetTicketKeyCb(config->sessMgr, EXAMPLE_TicketKeyCallback);
    ASSERT_EQ(SESSMGR_GetTicketKeyCb(config->sessMgr), EXAMPLE_TicketKeyCallback);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_NEW_DTLSCONFIG_API_TC001
* @title  Test HITLS_CFG_NewDTLSConfig interface
* @brief    1. Invoke the interface HITLS_CFG_NewTLS12Config, expected result 1.
* @expect   1. Returns not NULL.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_NEW_DTLSCONFIG_API_TC001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(config != NULL);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

#define DATA_MAX_LEN 1024
/** @
* @test UT_TLS_CFG_GET_SET_SESSION_TICKETKEY_API_TC001
* @title   Test HITLS_CFG_SetSessionTicketKey   interface
* @brief   1. Register the memory for config structure. Expected result 1.
*          2. If ticketKey is null, invoke HITLS_CFG_SetSessionTicketKey. Expected result 2.
*          3. Invoke HITLS_CFG_SetSessionTicketKey. Expected result 3.
*          4. If outSize is null, invoke HITLS_CFG_SetSessionTicketKey. Expected result 2.
*          5. Invoke HITLS_CFG_SetSessionTicketKey. Expected result 3.
* @expect  1. Memory register succeeded.
*          2. Return HITLS_NULL_INPUT.
*          3. Return HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_GET_SET_SESSION_TICKETKEY_API_TC001(int version)
{
    FRAME_Init();

    HITLS_Config *config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    uint8_t getKey[DATA_MAX_LEN] = {0};
    uint32_t getKeySize = DATA_MAX_LEN;
    uint32_t outSize = 0;

    char *ticketKey = "748ab9f3dc1a23748ab9f3dc1a23748ab9f3dc1a23748ab9f3dc1a23748ab9f3dc1a23748ab9f3d";
    uint32_t ticketKeyLen = HITLS_TICKET_KEY_NAME_SIZE + HITLS_TICKET_KEY_SIZE + HITLS_TICKET_KEY_SIZE;

    ASSERT_TRUE(HITLS_CFG_SetSessionTicketKey(config, NULL, ticketKeyLen) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetSessionTicketKey(config, (uint8_t *)ticketKey, ticketKeyLen) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_GetSessionTicketKey(config, getKey, getKeySize, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetSessionTicketKey(config, getKey, getKeySize, &outSize) == HITLS_SUCCESS);

    ASSERT_TRUE(outSize == ticketKeyLen);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_ADD_CAINDICATION_API_TC001
* @title:  Test Add different CA flag indication types.
* @brief
*   1. If data is NULL, Invoke the HITLS_CFG_AddCAIndication.Expected result 1.
*   2. Invoke the HITLS_CFG_AddCAIndication and set the transferred caType to HITLS_TRUSTED_CA_PRE_AGREED.Expected
*       result 2.
*   3. Invoke the HITLS_CFG_AddCAIndication and set the transferred caType to HITLS_TRUSTED_CA_KEY_SHA1.Expected
*       result 2.
*   4. Invoke the HITLS_CFG_AddCAIndication and set the transferred caType to HITLS_TRUSTED_CA_X509_NAME.Expected
*       result 2.
*   5. Invoke the HITLS_CFG_AddCAIndication and set the transferred caType to HITLS_TRUSTED_CA_CERT_SHA1.Expected
*       result 2.
*   6. Invoke the HITLS_CFG_AddCAIndication and set the transferred caType to HITLS_TRUSTED_CA_UNKNOWN.Expected
*       result 2.
* @expect
* 1. Return HITLS_NULL_INPUT.
* 2. Return HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_ADD_CAINDICATION_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    uint8_t data[] = {0};
    uint32_t len = sizeof(data);

    config = GetHitlsConfigViaVersion(tlsVersion);

    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_PRE_AGREED, NULL, len) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_PRE_AGREED, data, len) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_KEY_SHA1, data, len) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_X509_NAME, data, len) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_CERT_SHA1, data, len) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_UNKNOWN, data, len) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_GET_CALIST_API_TC001
* @title  Test HITLS_CFG_GetCAList interface
* @brief
*       1.Register the memory for config structure. Expected result 1.
*       1.Invoke the interface HITLS_CFG_GetCAList, expected result 2.
* @expect   1. Returns not NULL.
*           2. Returns NULL.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_GET_CALIST_API_TC001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_TRUE(HITLS_CFG_GetCAList(config) == NULL);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_GET_VERSION_API_TC001
* @title  Test HITLS_CFG_GetMinVersion/HITLS_CFG_GetMaxVersion/HITLS_SetVersion interface
* @brief
*       1.If minVersion is NULL, Invoke the HITLS_CFG_GetMinVersion.Expected result 1.
*       2.If maxVersion is NULL, Invoke the HITLS_CFG_GetMinVersion.Expected result 1.
*       3.Invoke HITLS_CFG_SetVersion.Expected result 2.
*       4.Invoke HITLS_CFG_GetMinVersion.Expected result 2.
*       5.Invoke HITLS_CFG_GetMaxVersion.Expected result 2.
*       6. Check minVersion is HITLS_VERSION_TLS12 and maxVersion is HITLS_VERSION_TLS13
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_SUCCES
*          3. Return HITLS_SUCCES，minVersion is HITLS_VERSION_TLS12 and maxVersion is HITLS_VERSION_TLS13
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_GET_VERSION_API_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLSConfig();
    uint16_t minVersion = 0;
    uint16_t maxVersion = 0;

    ASSERT_TRUE(HITLS_CFG_GetMinVersion(config, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetMaxVersion(config, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_SetVersion(config, HITLS_VERSION_TLS12, HITLS_VERSION_TLS13) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMinVersion(config, &minVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMaxVersion(config, &maxVersion) == HITLS_SUCCESS);
    ASSERT_TRUE(minVersion == HITLS_VERSION_TLS12 && maxVersion == HITLS_VERSION_TLS13);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */


/** @
* @test UT_TLS_CFG_GET_SESSION_CACHEMODE_API_TC001
* @title  Test ITLS_CFG_GetSessionCacheMoe interface
* @brief   1. Register the memory for config structure. Expected result 1.
*          2. Invoke HITLS_CFG_GetSessionCacheMode. Expected result 2.
* @expect  1. Memory register succeeded.
*          2. Return success and value is 0.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_GET_SESSION_CACHEMODE_API_TC001(void)
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    uint32_t getCacheMode = 0;
    ASSERT_EQ(HITLS_CFG_GetSessionCacheMode(config, &getCacheMode), 0);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test UT_TLS_CFG_SET_GET_SESSIONCACHESIZE_API_TC001
* @title   Test HITLS_CFG_SetSessionCacheSize/HITLS_CFG_GetSessionCacheSize interface
* @brief   1. Register the memory for config structure. Expected result 1.
*          2. Invoke HITLS_CFG_SetSessionCacheSize. Expected result 2.
*          3. Invoke HITLS_CFG_GetSessionCacheSize. Expected result 2.
*          4. Check getCacheSize and cacheSize is equal
* @expect  1. Memory register succeeded.
*          2. Return HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_SESSIONCACHESIZE_API_TC001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    uint32_t cacheSize = 10;
    uint32_t getCacheSize = 0;
    ASSERT_TRUE(HITLS_CFG_SetSessionCacheSize(config, cacheSize) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetSessionCacheSize(config, &getCacheSize) == HITLS_SUCCESS);
    ASSERT_TRUE(getCacheSize == cacheSize);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test UT_TLS_CFG_SET_GET_SESSION_TIMEOUT_API_TC001
* @title   Test HITLS_CFG_GetSessionTimeout interface
* @brief   1. Register the memory for config structure. Expected result 1.
*          2. Invoke HITLS_CFG_SetSessionTimeout. Expected result 2.
*          3. Invoke HITLS_CFG_GetSessionTimeout. Expected result 2.
*          4. Check timeOut and getTimeOut is equal
* @expect  1. Memory register succeeded.
*          2. Return HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_SESSION_TIMEOUT_API_TC001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    uint64_t timeOut = 10;
    uint64_t getTimeOut = 0;
    ASSERT_TRUE(HITLS_CFG_SetSessionTimeout(config, timeOut) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetSessionTimeout(config, &getTimeOut) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_VERSIONFORBID_API_TC001
* @title  Test HITLS_SetVersionForbid interface
* @brief   1. Register the memory for config structure. Expected result 1.
*          2. If context is NULL, invoke HITLS_SetVersionForbid. Expected result 3.
*          3. If context is NULL, invoke HITLS_SetVersionForbid. Expected result 2.
* @expect  1. Memory register succeeded.
*          2. Return HITLS_SUCCESS.
*          3. Return HITLS_NULL_INPUT
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_VERSIONFORBID_API_TC001(void)
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetVersionForbid(NULL, HITLS_VERSION_TLS12) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetVersionForbid(ctx, HITLS_VERSION_TLS12) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/** @
* @test UT_TLS_CFG_SET_GET_CONFIGUSEDATA_API_TC001
* @title  Test HITLS_CFG_SetConfigUserData/HITLS_CFG_GetConfigUserData interfaces
* @brief   1. Register the memory for config structure. Expected result 1.
*          2. If config is NULL, invoke HITLS_CFG_SetConfigUserData. Expected result 2.
*          3. Invoke HITLS_CFG_SetConfigUserData. Expected result 3.
*          3. Invoke HITLS_CFG_SetConfigUserData. Expected result 4.
* @expect  1. Memory register succeeded.
*          2. Return HITLS_NULL_INPUT.
*          3. Return HITLS_SUCCESS.
*          4. Return not NULL.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_CONFIGUSEDATA_API_TC001(int version)
{
    FRAME_Init();

    HITLS_Config *config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    char *userData = "123456";
    ASSERT_TRUE(HITLS_CFG_SetConfigUserData(NULL, userData) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetConfigUserData(config, userData) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetConfigUserData(config) != NULL);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */


void EXAMPLE_HITLS_ConfigUserDataFreeCb(
    void* data)
{
    (void)data;
    return;
}

/** @
* @test UT_TLS_CFG_SET_CONFIG_USERDATA_FREECB_API_TC001
* @title  Test HITLS_CFG_SetConfigUserDataFreeCb interfaces
* @brief   1. Register the memory for config structure. Expected result 1.
*          2. If config is NULL, invoke HITLS_CFG_SetConfigUserDataFreeCb. Expected result 2.
*          3. Invoke HITLS_CFG_SetConfigUserDataFreeCb. Expected result 3.
* @expect  1. Memory register succeeded.
*          2. Return HITLS_NULL_INPUT.
*          3. Return HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_CONFIG_USERDATA_FREECB_API_TC001(int version)
{
    FRAME_Init();

    HITLS_Config *config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetConfigUserDataFreeCb(NULL, EXAMPLE_HITLS_ConfigUserDataFreeCb) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetConfigUserDataFreeCb(config, EXAMPLE_HITLS_ConfigUserDataFreeCb) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_SET_GET_CERTIFICATE_API_TC001
* @title  Test HITLS_CFG_SetCertificate interface
* @brief 1. Invoke the HITLS_CFG_SetCertificate interface, set tlsConfig to null, and set cert for the device
*           certificate. (Expected result 1)
*       2. Invoke the HITLS_CFG_SetCertificate interface. Set tlsConfig and cert to an empty value for the device
*           certificate.(Expected result 1)
*       3. Invoke the HITLS_CFG_SetCertificate interface. Ensure that tlsConfig and cert are not empty. Perform deep
*           copy. (Expected result 3)
*       4. Invoke the HITLS_CFG_GetCertificate interface. The value of tlsConfig->certMgrCtx->currentCertKeyType is
*           greater than the value of TLS_CERT_KEY_TYPE_UNKNOWN, Expected result 4 is obtained.
*       5. Invoke the HITLS_CFG_GetCertificate interface and leave tlsConfig empty. Expected result 4 is obtained.
*       6. Invoke the HITLS_CFG_SetCertificate interface, set tlsConfig->certMgrCtx to null, and set cert to a non-empty
*           device certificate. (Expected result 2)
*       7. Invoke HITLS_CFG_GetCertificate
*       Run the tlsConfig command to set certMgrCtx to null. Expected result 4 is obtained.
* @expect
*       1. Returns HITLS_NULL_INPUT
*       2. Return HITLS_CERT_ERR_X509_DUP
*       3. HITLS_SUCCESS is returned.
*       4. NULL is returned.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_CERTIFICATE_API_TC001(int version, char *certFile)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_CERT_X509 *cert = HiTLS_X509_LoadCertFile(tlsConfig, certFile);
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ASSERT_TRUE(HITLS_CFG_SetCertificate(NULL, cert, false) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetCertificate(tlsConfig, NULL, true) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_SetCertificate(tlsConfig, cert, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_GetCertificate(tlsConfig) != NULL);
    tlsConfig->certMgrCtx->currentCertKeyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    ASSERT_TRUE(HITLS_CFG_GetCertificate(tlsConfig) == NULL);
    ASSERT_TRUE(HITLS_CFG_GetCertificate(NULL) == NULL);
    SAL_CERT_MgrCtxFree(tlsConfig->certMgrCtx);
    tlsConfig->certMgrCtx = NULL;
    ASSERT_EQ(HITLS_CFG_SetCertificate(tlsConfig, cert, true), HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetCertificate(tlsConfig) == NULL);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    SAL_CERT_X509Free(cert);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_CHECK_PRIVATEKEY_API_TC001
* @title Test HITLS_CFG_CheckPrivateKey interface
* @brief 1. Invoke the HITLS_CFG_CheckPrivateKey interface and leave tlsConfig blank. Expected result 1
*        2. Invoke the HITLS_CFG_CheckPrivateKey interface. The tlsConfig parameter is not empty,
*           The value of tlsConfig->certMgrCtx->currentCertKeyType is greater than or equal to the maximum value
*           TLS_CERT_KEY_TYPE_UNKNOWN. Expected result 2
*       3. Invoke the HITLS_CFG_CheckPrivateKey interface and leave tlsConfig->certMgrCtx empty. Expected result 3
* @expect   1. Returns HITLS_NULL_INPUT
*           2. HITLS_CONFIG_NO_CERT is returned.
*           3. The HITLS_UNREGISTERED_CALLBACK message is returned.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_CHECK_PRIVATEKEY_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ASSERT_TRUE(HITLS_CFG_CheckPrivateKey(NULL) == HITLS_NULL_INPUT);
    tlsConfig->certMgrCtx->currentCertKeyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    ASSERT_TRUE(HITLS_CFG_CheckPrivateKey(tlsConfig) == HITLS_CONFIG_NO_CERT);
    SAL_CERT_MgrCtxFree(tlsConfig->certMgrCtx);
    tlsConfig->certMgrCtx = NULL;
    ASSERT_TRUE(HITLS_CFG_CheckPrivateKey(tlsConfig) == HITLS_UNREGISTERED_CALLBACK);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/** @
* @test  UT_TLS_CFG_ADD_CHAINCERT_API_TC001
* @title  Test HITLS_CFG_GetChainCerts interface
* @brief 1. Invoke the HITLS_CFG_AddChainCert interface, set tlsConfig to null, and set addCert to a certificate to be
*           added. Perform shallow copy. Expected result 1 .
*        2. Invoke the HITLS_CFG_AddChainCert interface. The tlsConfig parameter is not empty and the addCert parameter
*           is empty.Perform deep copy. Expected result 1 .
*        3. Invoke the HITLS_CFG_AddChainCert interface. Ensure that tlsConfig is not empty and addCert is not empty.
*           Perform shallow copy. Expected result 2 .
*       4. Invoke the HITLS_CFG_AddChainCert interface. The value of tlsConfig is not empty and the value of
*           tlsConfig->certMgrCtx->currentCertKeyType is greater than or equal to the maximum value TLS_CERT_KEY_TYPE_UNKNOWN.
*          Expected result 4 .
*       5. Invoke the HITLS_CFG_GetChainCerts interface. Set tlsConfig to a value greater than or equal to the maximum
*           value TLS_CERT_KEY_TYPE_UNKNOWN. (Expected result 3)
*       6. Invoke the HITLS_CFG_GetChainCerts interface and leave tlsConfig blank. Expected result 3 .
*       7. Invoke the HITLS_CFG_LoadKeyBuffer interface. Set tlsConfig->certMgrCtx to null and addCert to the
*           certificate to be added. Perform deep copy. Expected result 5 .
*       8. Invoke the HITLS_CFG_GetChainCerts interface and leave tlsConfig->certMgrCtx empty. Expected result 3.
* @expect
*   1. Returns HITLS_NULL_INPUT
*   2. HITLS_SUCCESS is returned.
*   3. NULL is returned.
*   4. Return ITLS_CERT_ERR_ADD_CHAIN_CERT
*   5. Return HITLS_CERT_ERR_X509_DUP
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_ADD_CHAINCERT_API_TC001(int version, char *certFile, char *addCertFile)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_CERT_X509 *cert = HITLS_CFG_ParseCert(tlsConfig, (const uint8_t *)certFile, strlen(certFile) + 1, TLS_PARSE_TYPE_FILE,
        TLS_PARSE_FORMAT_ASN1);
    cert = HiTLS_X509_LoadCertFile(tlsConfig, certFile);
    HITLS_CERT_X509 *addCert = HiTLS_X509_LoadCertFile(tlsConfig, addCertFile);

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ASSERT_TRUE(HITLS_CFG_SetCertificate(tlsConfig, cert, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_AddChainCert(NULL, addCert, false) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_AddChainCert(tlsConfig, NULL, true) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_AddChainCert(tlsConfig, addCert, false), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_GetChainCerts(tlsConfig) != NULL);
    tlsConfig->certMgrCtx->currentCertKeyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    ASSERT_EQ(HITLS_CFG_AddChainCert(tlsConfig, cert, true), HITLS_CERT_ERR_ADD_CHAIN_CERT);
    ASSERT_TRUE(HITLS_CFG_GetChainCerts(tlsConfig) == NULL);
    ASSERT_TRUE(HITLS_CFG_GetChainCerts(NULL) == NULL);
    SAL_CERT_MgrCtxFree(tlsConfig->certMgrCtx);
    tlsConfig->certMgrCtx = NULL;
    ASSERT_EQ(HITLS_CFG_AddChainCert(tlsConfig, cert, true), HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetChainCerts(tlsConfig) == NULL);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */


/** @
* @test  UT_HITLS_CFG_REMOVE_CERTANDKEY_API_TC001
* @title  Test HITLS_CFG_RemoveCertAndKey interface
* @brief
*       1. Register the memory for config structure. Expected result 1.
*       2. Invoke HITLS_CFG_RemoveCertAndKey interface, expected result 3.
*       3. Invoke HITLS_CFG_SetCertificate interface, expected result 3.
*       4. Invoke HITLS_CFG_LoadKeyFile interface, expected result 3.
*       5. Invoke HITLS_CFG_GetCertificate interface, expected result 2.
*       6. Invoke HITLS_CFG_GetPrivateKey interface, expected result 2.
*       7. Invoke HITLS_CFG_CheckPrivateKey interface, expected result 3.
*       8. Invoke HITLS_CFG_RemoveCertAndKey interface, expected result 3.
*       9. Invoke HITLS_CFG_GetCertificate interface, expected result 4.
*       10. Invoke HITLS_CFG_GetPrivateKey interface, expected result 4.
* @expect  1. Create successful.
*        2. Return not NULL
*        3. Return  HITLS_SUCCESS
*        4.Return NULL
@ */
/* BEGIN_CASE */
void UT_HITLS_CFG_REMOVE_CERTANDKEY_API_TC001(int version, char *certFile, char *keyFile)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_CERT_X509 *cert = HiTLS_X509_LoadCertFile(tlsConfig, certFile);

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ASSERT_EQ(HITLS_CFG_RemoveCertAndKey(tlsConfig), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_CFG_SetCertificate(tlsConfig, cert, true), HITLS_SUCCESS);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ASSERT_EQ(HITLS_CFG_ProviderLoadKeyFile(tlsConfig, keyFile, "ASN1", NULL), HITLS_SUCCESS);
#else
    ASSERT_EQ(HITLS_CFG_LoadKeyFile(tlsConfig, keyFile, TLS_PARSE_FORMAT_ASN1), HITLS_SUCCESS);
#endif
    ASSERT_TRUE(HITLS_CFG_GetCertificate(tlsConfig) != NULL);
    ASSERT_TRUE(HITLS_CFG_GetPrivateKey(tlsConfig) != NULL);
    ASSERT_EQ(HITLS_CFG_CheckPrivateKey(tlsConfig), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_RemoveCertAndKey(tlsConfig), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_GetCertificate(tlsConfig) == NULL);
    ASSERT_TRUE(HITLS_CFG_GetPrivateKey(tlsConfig) == NULL);

EXIT:
    HITLS_CFG_FreeCert(tlsConfig, cert);
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

void StubListDataDestroy(void *data)
{
    BSL_SAL_FREE(data);
    return;
}

/** @
* @test  UT_HITLS_CFG_ADD_EXTRA_CHAINCERT_API_TC001
* @title  Test HITLS_CFG_AddExtraChainCert interface
* @brief
*   1. Create a config object. Expected result 1 .
*   2. If the input value of config is null, invoke HITLS_CFG_GetExtraChainCerts to obtain the configured additional
*       certificate chain. Expected result 2 .
*   3. Call the interface to add a certificate to the additional certificate chain and call HITLS_CFG_GetExtraChainCerts
*       to obtain the configured additional certificate chain. Expected result 3 .
*   4. Call the API again to add certificate 2 to the additional certificate chain and call HITLS_CFG_GetExtraChainCerts
*       to obtain the configured additional certificate chain. Expected result 4 .
5. Invoke HITLS_CFG_ClearChainCerts to clear the attached certificate chain. Expected result 5 .
* @expect
*   1. The config object is created successfully.
*   2. Failed to set the additional certificate chain. The obtained additional certificate chain is empty.
*   3. The additional certificate chain is successfully set and obtained.
*   4. The additional certificate chain is successfully set and obtained.
*   5. The STORE for obtaining the attached certificate chain does not change.
@ */
/* BEGIN_CASE */
void UT_HITLS_CFG_ADD_EXTRA_CHAINCERT_API_TC001(int version, char *certFile1, char *certFile2)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_CERT_X509 *cert1 = HiTLS_X509_LoadCertFile(tlsConfig, certFile1);
    HITLS_CERT_X509 *cert2 = HiTLS_X509_LoadCertFile(tlsConfig, certFile2);
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ASSERT_TRUE(HITLS_CFG_AddExtraChainCert(NULL, cert1) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_AddExtraChainCert(tlsConfig, cert1) == HITLS_SUCCESS);
    HITLS_CERT_Chain *extraChainCert = HITLS_CFG_GetExtraChainCerts(tlsConfig);
    ASSERT_TRUE(extraChainCert->count == 1);
    ASSERT_TRUE(HITLS_CFG_GetExtraChainCerts(tlsConfig) != NULL);

    ASSERT_TRUE(HITLS_CFG_AddExtraChainCert(tlsConfig, cert2) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetExtraChainCerts(tlsConfig) != NULL);
    ASSERT_TRUE(HITLS_CFG_ClearChainCerts(tlsConfig) == HITLS_SUCCESS);
    HITLS_CERT_Chain *extraChainCert1 = HITLS_CFG_GetExtraChainCerts(tlsConfig);
    ASSERT_TRUE(extraChainCert1->count == 2);
    ASSERT_TRUE(HITLS_CFG_GetExtraChainCerts(tlsConfig) != NULL);
    ASSERT_TRUE(HITLS_CFG_ClearExtraChainCerts(NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_ClearExtraChainCerts(tlsConfig) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetExtraChainCerts(tlsConfig) == NULL);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_SET_DTLS_MTU_API_TC001
* @title  Test HITLS_SetMtu interface
* @brief 1. Create the TLS configuration object config.Expect result 1.
*       2. Use config to create the client and server.Expect result 2.
*       3. Invoke HITLS_SetMtu, Expect result 3.
* @expect 1. The config object is successfully created.
*       2. The client and server are successfully created.
*       3. Return HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_DTLS_MTU_API_TC001(void)
{
    FRAME_Init();
    uint32_t mtu = 1500;

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(HITLS_SetMtu(client->ssl, mtu) == HITLS_SUCCESS);

    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(HITLS_SetMtu(server->ssl, mtu) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

void Test_HITLS_KeyLogCb(HITLS_Ctx *ctx, const char *line)
{
    (void)ctx;
    (void)line;
    printf("there is Test_HITLS_KeyLogCb\n");
}

/* @
* @test  UT_TLS_CFG_LogSecret_TC001
* @spec  -
* @title  Test the HITLS_LogSecret interface.
* @precon  nan
* @brief
*           1. Transfer an empty context. The label and secret are not empty, and the secret length is not 0.
*              Expected result 1 is obtained.
*           2. Transfer a non-empty context. The label is empty, the secret is not empty,
*              and the secret length is not 0. Expected result 1 is obtained.
*           3. Transfer a non-empty context. The label is not empty, the secret is empty,
*              and the secret length is not 0. Expected result 1 is obtained.
*           4. Transfer a non-empty context. The label and secret are not empty, and the secret length is 0.
*              Expected result 1 is obtained.
*           5. Transfer a non-empty context. The label and secret are not empty, and the secret length is not 0.
*              Expected result 2 is obtained.
* @expect  1. return HITLS_NULL_INPUT
*          2. return HITLS_SUCCES
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_LogSecret_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = NULL;
    HITLS_CFG_SetKeyLogCb(config, Test_HITLS_KeyLogCb);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    const char label[] = "hello";
    const char secret[] = "hello123";

    ASSERT_EQ(HITLS_LogSecret(NULL, label, (const uint8_t *)secret, strlen(secret)),  HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_LogSecret(ctx, NULL, (const uint8_t *)secret, strlen(secret)),  HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_LogSecret(ctx, label, NULL, strlen(secret)),  HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_LogSecret(ctx, label, (const uint8_t *)secret, 0), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_LogSecret(ctx, label, (const uint8_t *)secret, strlen(secret)), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_SetTmpDhCb_TC001
* @spec  -
* @title  HITLS_CFG_SetTmpDhCb interface test. The config field is empty.
* @precon  nan
* @brief    1. If config is empty, expected result 1 is obtained.
* @expect   1. HITLS_NULL_INPUT is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SetTmpDhCb_TC001()
{
    // config is empty
    ASSERT_TRUE(HITLS_CFG_SetTmpDhCb(NULL, DH_CB) == HITLS_NULL_INPUT);
EXIT:
    ;
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_GET_CIPHERSUITESBYSTDNAME_TC001
* @spec  -
* @title  HITLS_CFG_GetCipherSuiteByStdName connection
* @precon  nan
* @brief    1. Transfer a null pointer. Expected result 1 is obtained.
*           2. Transfer the "TLS_RSA_WITH_AES_128_CBC_SHA" character string. Expected result 2 is obtained.
*           3. Input the character string x. Expected result 3 is obtained.
* @expect  1. return NULL
*          2. return HITLS_RSA_WITH_AES_128_CBC_SHA
*          3. return NULL
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_GET_CIPHERSUITESBYSTDNAME_TC001(void)
{
    const char *StdName = NULL;
    ASSERT_TRUE(HITLS_CFG_GetCipherSuiteByStdName((const uint8_t *)StdName) == NULL);

    const char StdName2[] = "TLS_RSA_WITH_AES_128_CBC_SHA";
    const HITLS_Cipher* Cipher2 = HITLS_CFG_GetCipherSuiteByStdName((const uint8_t *)StdName2);
    ASSERT_TRUE(Cipher2->cipherSuite == HITLS_RSA_WITH_AES_128_CBC_SHA);

    const char StdName3[] = "x";
    ASSERT_TRUE(HITLS_CFG_GetCipherSuiteByStdName((const uint8_t *)StdName3) == NULL);
EXIT:
    return;
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_CLEAR_CALIST_TC001
* @title  HITLS_CFG_ClearCAList interface test
* @precon  nan
* @brief  1. pass NULL parameter, expect result 1
*         2. pass config with NULL caList, expect result 1
*         3. pass normal config, expect result 1
* @expect 1. void function has no return value
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void  UT_TLS_CFG_CLEAR_CALIST_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Config *config2 = {0};

    HITLS_CFG_ClearCAList(NULL);
    HITLS_CFG_ClearCAList(config2);
    HITLS_CFG_ClearCAList(config);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_SET_GET_DHAUTOSUPPORT_TC001
* @spec  -
* @title  HITLS_CFG_SetDhAutoSupport and HITLS_CFG_GetDhAutoSupport contact
* @precon  nan
* @brief   HITLS_CFG_SetDhAutoSupport
*          1. Import empty configuration information. Expected result 1 is obtained.
*          2. Transfer non-empty configuration information and set support to an invalid value. Expected result 2 is obtained.
*          3. Transfer non-empty configuration information and set support to a valid value. Expected result 3 is obtained.
*          HITLS_CFG_GetDhAutoSupport
*          1. Import empty configuration information. Expected result 1 is obtained.
*          2. Transfer an empty isSupport pointer. Expected result 1 is obtained.
*          3. Transfer the non-null configuration information and the isSupport pointer is not null. Expected result 3 is obtained.
* @expect  1. return HITLS_NULL_INPUT
*          2. return HITLS_SUCCES，and config->isSupportDhAuto is True
*          3. return HITLS_SUCCES，and config->isSupportDhAuto is False or True
@ */

/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_DHAUTOSUPPORT_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool support = -1;
    bool isSupport = -1;
    ASSERT_TRUE(HITLS_CFG_SetDhAutoSupport(config, support) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetDhAutoSupport(config, &isSupport) == HITLS_NULL_INPUT);

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

    ASSERT_TRUE(HITLS_CFG_GetDhAutoSupport(config, NULL) == HITLS_NULL_INPUT);

    support = true;
    ASSERT_TRUE(HITLS_CFG_SetDhAutoSupport(config, support) == HITLS_SUCCESS);

    support = -1;
    ASSERT_TRUE(HITLS_CFG_SetDhAutoSupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetDhAutoSupport(config, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == true);

    support = false;
    ASSERT_TRUE(HITLS_CFG_SetDhAutoSupport(config, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetDhAutoSupport(config, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_GET_READ_AHEAD_TC001
* @title  HITLS_CFG_GetReadAhead interface test
* @precon  nan
* @brief  1. pass NULL config, expect result 1
*         2. pass NULL onOff, expect result 1
*         3. pass normal parameters, expect result 2
* @expect 1. return HITLS_NULL_INPUT
*         2. return HITLS_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_GET_READ_AHEAD_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    int32_t onOff = 0;
    ASSERT_TRUE(HITLS_CFG_GetReadAhead(NULL, &onOff) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetReadAhead(config, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetReadAhead(config, &onOff) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_CONFIG_SET_KeyLogCb_TC001
* @spec  -
* @title  Test the HITLS_CFG_SetKeyLogCb and HITLS_CFG_GetKeyLogCb interfaces.
* @precon  nan
* @brief   HITLS_CFG_SetKeyLogCb and HITLS_CFG_GetKeyLogCb
*          1. Import empty configuration information. Expected result 1 is obtained.
*          2. Transfer non-empty configuration information and set callback to a non-empty value. Expected result 2 is obtained.
* @expect  1. return HITLS_NULL_INPUT
*          2. return HITLS_SUCCES
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_KeyLogCb_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetKeyLogCb(NULL, Test_HITLS_KeyLogCb) ==  HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetKeyLogCb(config, Test_HITLS_KeyLogCb) ==  HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetKeyLogCb(NULL), NULL);
    ASSERT_EQ(HITLS_CFG_GetKeyLogCb(config), Test_HITLS_KeyLogCb);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

int g_recordPaddingCbArg = 1;
uint64_t RecordPaddingCb(HITLS_Ctx *ctx, int32_t type, uint64_t length, void *arg)
{
    (void)ctx;
    (void)type;
    (void)length;
    ASSERT_TRUE(g_recordPaddingCbArg == (*(int *)arg));
    ASSERT_TRUE(&g_recordPaddingCbArg == arg);
EXIT:
    return 0;
}

/** @
* @test  UT_TLS_CFG_SET_RECORDPADDINGARG_API_TC002
* @title  HITLS_CFG_SetRecordPaddingCbArg Connection
* @precon  nan
* @brief    1. Create tls13 config, expected result 1.
            2. Set RecordPaddingCb and RecordPaddingCbArg to 1 for the client, Expected result 2.
            3. Establish a connection, Verify that the arg passed in RecordPaddingCb matches the set arg.
            Expected result 3.
* @expect
* 1. The creating is successful.
* 2. The setting is successful.
* 3. The arg value is the same，TLS1.3 connection are established.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_RECORDPADDINGARG_API_TC002()
{
    HitlsInit();
    HITLS_Config *config_c = NULL;
    HITLS_Config *config_s = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config_c = HITLS_CFG_NewTLS13Config();
    config_s = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCb(config_c, RecordPaddingCb) ==  HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordPaddingCbArg(config_c, &g_recordPaddingCbArg) ==  HITLS_SUCCESS);

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/* @
* @test  UT_TLS_CFG_LOADVERIFYDIR_MULTI_PATH_TC001
* @title  Test HITLS_CFG_LoadVerifyDir with multiple CA paths
* @brief
*   1. Create a config object.
*   2. Pass in a string containing multiple paths (such as "/tmp/ca1:/tmp/ca2:/tmp/ca3").
*   3. Call HITLS_CFG_LoadVerifyDir.
*   4. Check that the number and content of caPaths in the cert store are consistent with the input.
* @expect
*   1. The interface returns success.
*   2. The number and content of paths in the cert store are consistent with the input.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_LOADVERIFYDIR_MULTI_PATH_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    const char *multi_path = "/tmp/ca1:/tmp/ca2:/tmp/ca3:/tmp/ca3";
    int32_t ret = HITLS_CFG_LoadVerifyDir(config, multi_path);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    HITLS_CERT_Store *store = SAL_CERT_GET_CERT_STORE_EX(config->certMgrCtx);
    ASSERT_TRUE(store != NULL);

    HITLS_X509_StoreCtx *storeCtx = (HITLS_X509_StoreCtx *)store;
    BslList *caPaths = storeCtx->caPaths;
    ASSERT_TRUE(caPaths != NULL);

    int expect_count = 3;
    int actual_count = BSL_LIST_COUNT(caPaths);
    ASSERT_TRUE(actual_count == expect_count);

    const char *expect_paths[] = {"/tmp/ca1", "/tmp/ca2", "/tmp/ca3"};
    for (int i = 0; i < expect_count; ++i) {
        const char *path = (const char *)BSL_LIST_GetIndexNode(i, caPaths);
        ASSERT_TRUE(path != NULL);
        ASSERT_TRUE(strcmp(path, expect_paths[i]) == 0);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_LOADVERIFYFILE_TC001
* @title  Test HITLS_CFG_LoadVerifyFile with a single CA path
* @brief
*   1. Create a config object.
*   2. Pass in a string containing a single path.
*   3. Call HITLS_CFG_LoadVerifyFile.
*   4. Load a client certificate signed by the CA in the specified path.
*   5. Call HITLS_CFG_BuildCertChain to verify the client certificate.
* @expect
*   1. The interface returns success.
*   2. The client certificate is successfully verified.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_LOADVERIFYFILE_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    const char *path = "../testdata/tls/certificate/pem/rsa_sha256/inter.pem";
    int32_t ret = HITLS_CFG_LoadVerifyFile(config, path);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    const char *path1 = "../testdata/tls/certificate/pem/rsa_sha256/ca.pem";
    ret = HITLS_CFG_LoadVerifyFile(config, path1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    const char *certToVerify = "../testdata/tls/certificate/pem/rsa_sha256/client.pem";
    ret = HITLS_CFG_LoadCertFile(config, certToVerify, TLS_PARSE_FORMAT_PEM);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ASSERT_EQ(HITLS_CFG_BuildCertChain(config, HITLS_BUILD_CHAIN_FLAG_NO_ROOT), HITLS_SUCCESS);
    HITLS_CERT_Chain *chain = HITLS_CFG_GetChainCerts(config);
    ASSERT_TRUE(chain != NULL);
    ASSERT_TRUE(chain->count == 1);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_LOADVERIFYFILE_TC002
* @title  Test HITLS_CFG_LoadVerifyFile with a single CA path
* @brief
*   1. Create a config object.
*   2. Pass in a string containing a single path.
*   3. Call HITLS_CFG_LoadVerifyFile.
*   4. Load a client certificate signed by the CA in the specified path.
*   5. Call HITLS_CFG_BuildCertChain to verify the client certificate.
* @expect
*   1. The interface returns success.
*   2. The client certificate verification fails.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_LOADVERIFYFILE_TC002(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    const char *path = "../testdata/tls/certificate/pem/ecdsa_sha256/inter.pem";
    int32_t ret = HITLS_CFG_LoadVerifyFile(config, path);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    const char *certToVerify = "../testdata/tls/certificate/pem/rsa_sha256/client.pem";
    ret = HITLS_CFG_LoadCertFile(config, certToVerify, TLS_PARSE_FORMAT_PEM);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ASSERT_EQ(HITLS_CFG_BuildCertChain(config, HITLS_BUILD_CHAIN_FLAG_NO_ROOT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetChainCerts(config) == NULL);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_USECERTCHAINFILE_TC001
* @title  Test HITLS_CFG_UseCertificateChainFile with a single file path
* @brief
*   1. Create a config object.
*   2. Pass in a string containing a single path.
*   3. Call HITLS_CFG_UseCertificateChainFile.
*   4. Load a client certificate signed by the CA in the specified path.
*   5. Call HITLS_CFG_BuildCertChain to verify the client certificate.
* @expect
*   1. The interface returns success.
*   2. The client certificate verification verified.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_USECERTCHAINFILE_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    const char *path = "../testdata/tls/certificate/pem/rsa_sha256/cert_chain.pem";
    int32_t ret = HITLS_CFG_UseCertificateChainFile(config, path);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ASSERT_EQ(HITLS_CFG_BuildCertChain(config, HITLS_BUILD_CHAIN_FLAG_CHECK), HITLS_SUCCESS);
    HITLS_CERT_Chain *chain = HITLS_CFG_GetChainCerts(config);
    ASSERT_TRUE(chain != NULL);
    ASSERT_TRUE(chain->count == 1);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_USECERTCHAINFILE_TC002
* @title  Test HITLS_CFG_UseCertificateChainFile with a single CA path
* @brief
*   1. Create a config object.
*   2. Pass in a string containing a single path.
*   3. Call HITLS_CFG_UseCertificateChainFile.
*   4. Load a client certificate signed by the CA in the specified path.
*   5. Call HITLS_CFG_BuildCertChain to verify the client certificate.
* @expect
*   1. The interface returns success.
*   2. The client certificate verification fails.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_USECERTCHAINFILE_TC002(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    const char *path = "../testdata/tls/certificate/pem/rsa_sha256/cert_chain_damaged_ca.pem";
    int32_t ret = HITLS_CFG_UseCertificateChainFile(config, path);
    ASSERT_EQ(ret, HITLS_CFG_ERR_LOAD_CERT_FILE);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_USECERTCHAINFILE_TC003
* @title  Test HITLS_CFG_LoadVerifyFile with a single CA path
* @brief
*   1. Create a config object.
*   2. Pass in a string containing a single path.
*   3. Call HITLS_CFG_UseCertificateChainFile.
*   4. Load a client certificate signed by the CA in the specified path.
*   5. Call HITLS_CFG_BuildCertChain to verify the client certificate.
* @expect
*   1. The interface returns success.
*   2. The client certificate verification fails.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_USECERTCHAINFILE_TC003(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    const char *path = "../testdata/tls/certificate/pem/rsa_sha256/cert_chain_duplicate_ca.pem";
    int32_t ret = HITLS_CFG_UseCertificateChainFile(config, path);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ASSERT_EQ(HITLS_CFG_BuildCertChain(config, HITLS_BUILD_CHAIN_FLAG_CHECK), HITLS_X509_ERR_CERT_EXIST);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_LOADDEFAULTCAPATH_TC002
* @title  Test HITLS_CFG_LoadDefaultCAPath with NULL input
* @brief
*   1. Call HITLS_CFG_LoadDefaultCAPath with NULL config.
* @expect
*   1. Returns HITLS_NULL_INPUT.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_LOADDEFAULTCAPATH_TC002(void)
{
    FRAME_Init();

    // Test with NULL config
    int32_t ret = HITLS_CFG_LoadDefaultCAPath(NULL);
    ASSERT_EQ(ret, HITLS_NULL_INPUT);

EXIT:
    return;
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_LOADDEFAULTCAPATH_TC003
* @title  Test HITLS_CFG_LoadDefaultCAPath sets correct default path
* @brief
*   1. Create a config object.
*   2. Call HITLS_CFG_LoadDefaultCAPath.
*   3. Verify that the CA store contains the expected default path.
* @expect
*   1. HITLS_CFG_LoadDefaultCAPath returns HITLS_SUCCESS.
*   2. Default path is correctly configured.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_LOADDEFAULTCAPATH_TC003(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Load default CA path
    int32_t ret = HITLS_CFG_LoadDefaultCAPath(config);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Verify the path was set correctly by checking CA store
    HITLS_CERT_Store *store = SAL_CERT_GET_CERT_STORE_EX(config->certMgrCtx);
    ASSERT_TRUE(store != NULL);

    // Cast to HITLS_X509_StoreCtx to access internal structure
    HITLS_X509_StoreCtx *storeCtx = (HITLS_X509_StoreCtx *)store;
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_TRUE(storeCtx->caPaths != NULL);
    ASSERT_TRUE(BSL_LIST_COUNT(storeCtx->caPaths) > 0);

    // Get the first path from the caPaths list
    char *pathPtr = (char *)BSL_LIST_GET_FIRST(storeCtx->caPaths);
    ASSERT_TRUE(pathPtr != NULL);

    // Construct expected default path
    char expectedPath[MAX_PATH_LEN] = {0};
    ret = snprintf_s(expectedPath, sizeof(expectedPath), sizeof(expectedPath) - 1,
                     "%s/ssl/certs", OPENHITLSDIR);
    ASSERT_TRUE(ret > 0);

    // Compare the actual path with expected path
    ASSERT_TRUE(strcmp(pathPtr, expectedPath) == 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_LOADVERIFYFILE_BUNDLE_TC001
* @title  Test HITLS_CFG_LoadVerifyFile with bundle file containing multiple certificates
* @brief
*   1. Create a config object.
*   2. Load a bundle file containing multiple CA certificates.
*   3. Load client certificates signed by different CAs in the bundle.
*   4. Verify all certificates can be validated.
* @expect
*   1. HITLS_CFG_LoadVerifyFile returns HITLS_SUCCESS.
*   2. All certificates in bundle are loaded and can be used for verification.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_LOADVERIFYFILE_BUNDLE_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Load bundle file containing multiple CA certificates
    const char *bundlePath = "../testdata/tls/certificate/pem/rsa_sha256/ca_bundle.pem";
    int32_t ret = HITLS_CFG_LoadVerifyFile(config, bundlePath);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test verification with first CA's client cert
    const char *clientCert1 = "../testdata/tls/certificate/pem/rsa_sha256/client.pem";
    ret = HITLS_CFG_LoadCertFile(config, clientCert1, TLS_PARSE_FORMAT_PEM);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ret = HITLS_CFG_BuildCertChain(config, HITLS_BUILD_CHAIN_FLAG_NO_ROOT);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Clean up for next test
    HITLS_CFG_RemoveCertAndKey(config);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_LOADVERIFYFILE_BUNDLE_TC002
* @title  Test HITLS_CFG_LoadVerifyFile with empty bundle file
* @brief
*   1. Create a config object.
*   2. Try to load an empty bundle file.
* @expect
*   1. Returns HITLS_CFG_ERR_LOAD_CERT_FILE.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_LOADVERIFYFILE_BUNDLE_TC002(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Try to load empty bundle file
    const char *emptyBundlePath = "../testdata/tls/certificate/pem/rsa_sha256/empty_bundle.pem";
    int32_t ret = HITLS_CFG_LoadVerifyFile(config, emptyBundlePath);
    ASSERT_EQ(ret, HITLS_CFG_ERR_LOAD_CERT_FILE);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_LOADVERIFYFILE_BUNDLE_TC003
* @title  Test HITLS_CFG_LoadVerifyFile with corrupted bundle file
* @brief
*   1. Create a config object.
*   2. Try to load a bundle file with corrupted certificate data.
* @expect
*   1. Returns HITLS_CFG_ERR_LOAD_CERT_FILE.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_LOADVERIFYFILE_BUNDLE_TC003(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Try to load corrupted bundle file
    const char *corruptedBundlePath = "../testdata/tls/certificate/pem/rsa_sha256/corrupted_bundle.pem";
    int32_t ret = HITLS_CFG_LoadVerifyFile(config, corruptedBundlePath);
    ASSERT_EQ(ret, HITLS_CFG_ERR_LOAD_CERT_FILE);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_LOADVERIFYFILE_COMPAT_TC001
* @title  Test HITLS_CFG_LoadVerifyFile backward compatibility with single certificate
* @brief
*   1. Create a config object.
*   2. Load a single certificate file (existing functionality).
*   3. Verify it works the same as before.
* @expect
*   1. HITLS_CFG_LoadVerifyFile returns HITLS_SUCCESS.
*   2. Single certificate loading works as expected.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_LOADVERIFYFILE_COMPAT_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Load single certificate file (existing functionality)
    const char *singleCertPath = "../testdata/tls/certificate/pem/rsa_sha256/ca.pem";
    int32_t ret = HITLS_CFG_LoadVerifyFile(config, singleCertPath);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Verify certificate can be used for validation
    const char *clientCert = "../testdata/tls/certificate/pem/rsa_sha256/client.pem";
    ret = HITLS_CFG_LoadCertFile(config, clientCert, TLS_PARSE_FORMAT_PEM);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ret = HITLS_CFG_BuildCertChain(config, HITLS_BUILD_CHAIN_FLAG_NO_ROOT);
    ASSERT_EQ(ret, HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_SET_SESSION_CACHE_SIZE_FUNC_TC001
* @title  Test the cache session capability when sessCacheSize is set to 0
* @brief
*   1. Create a config object.
*   2. Set sessCacheSize to 0.
*   3. Set session ticket support to false.
*   4. Verify the number of session caches.
* @expect
*   1. HITLS_CFG_SetSessionCacheSize returns HITLS_SUCCESS.
*   2. Expected session cache quantity is 1.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_SESSION_CACHE_SIZE_FUNC_TC001(void)
{
    HitlsInit();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetSessionCacheSize(config, 0) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetSessionTicketSupport(config, false) == HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(BSL_HASH_Size(client->ssl->globalConfig->sessMgr->hash), 1);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS_CFG_GET_CCM8_CIPHERSUITE_TC001(char *stdName)
{
    const HITLS_Cipher *cipher = NULL;
    cipher = HITLS_CFG_GetCipherSuiteByStdName((const uint8_t *)stdName);
    ASSERT_TRUE(cipher != NULL);
    ASSERT_EQ(cipher->strengthBits, 64);
EXIT:
    return;
}
/* END_CASE */

/* @
* @test  SDV_HITLS_CFG_SET_KEEP_PEER_CERT_API_TC001
* @spec  -
* @title  Covering abnormal input parameters for the HITLS_CFG_SetKeepPeerCertificate interface
* @precon  nan
* @brief  1.Call the HITLS_CFG_SetKeepPeerCertificate interface with config set to null; expected result 2 occurs.
*         2.Call the HITLS_CFG_SetKeepPeerCertificate interface with config not being empty and isKeepPeerCert set to
*           true. Expected result 1 occurs.
*         3.Call the HITLS_CFG_SetKeepPeerCertificate interface with config not being empty and isKeepPeerCert set to
*           false. Expected result 1 occurs.
* @expect  1.return HITLS_SUCCESS
*          2.return error code
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_CFG_SET_KEEP_PEER_CERT_API_TC001(void)
{
    HitlsInit();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);

    int32_t ret = HITLS_CFG_SetKeepPeerCertificate(NULL, true);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_CFG_SetKeepPeerCertificate(tlsConfig, true);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HITLS_CFG_SetKeepPeerCertificate(tlsConfig, false);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ret = HITLS_SetKeepPeerCertificate(NULL, false);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);
    ret = HITLS_SetKeepPeerCertificate(ctx, false);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
 * @test  HITLS_UT_TLS_SET_CURRENT_CERT_TC001
 * @spec  -
 * @title  Cover Abnormal Input Parameters of the HITLS_CFG_SetCurrentCert Interface
 * @precon  nan
 * @brief  1.Invoke the HITLS_CFG_SetCurrentCert interface. Config is NULL. Expected result 2.
 *         2.Invoke the HITLS_CFG_SetCurrentCert interface. Config is not NULL. Expected result 1.
 * @expect  1.Return HITLS_SUCCESS
 *          2.Return HITLS_NULL_INPUT
 * @prior  Level 1
 * @auto  TRUE
 **/
/* BEGIN_CASE */
void HITLS_UT_TLS_SET_CURRENT_CERT_TC001(void)
{
    HitlsInit();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    int32_t ret = HITLS_CFG_SetCurrentCert(NULL, 1);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_CFG_SetCurrentCert(tlsConfig, 1);
    ASSERT_TRUE(ret = HITLS_CERT_ERR_SET_CERT);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    return;
}
/* END_CASE */

/* @
* @test  HITLS_UT_TLS_SET_CURRENTCERT_API_TC001
* @spec  -
* @title  Cover Abnormal Input Parameters of the HITLS_SetCurrentCert Interface
* @precon  nan
* @brief  1.Invoke the HITLS_SetCurrentCert interface. Ctx is NULL, option is HITLS_CERT_SET_FIRST. Expected result 2.
*         2.Invoke the HITLS_SetCurrentCert interface. Ctx is not NULL, option is HITLS_CERT_SET_FIRST. Expected result 1.
* @expect  1.Return HITLS_CERT_ERR_SET_CERT
*          2.Return HITLS_NULL_INPUT
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_UT_TLS_SET_CURRENTCERT_API_TC001(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    long option = HITLS_CERT_SET_FIRST;

    int32_t ret = HITLS_SetCurrentCert(NULL, option);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetCurrentCert(ctx, option);
    ASSERT_EQ(ret, HITLS_CERT_ERR_SET_CERT);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_CONFIG_GET_CIPHERSUITESBYSTDNAME_TC001
* @spec  -
* @title  test for HITLS_CFG_GetCipherSuites
* @precon  nan
* @brief   1. Input a null pointer. Expected result 1.
*          2. Input a smaller array length. Expected result 2.
*          3. Input normal parameters. Expected result 3
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_CONFIG_INVALID_LENGTH
*          3. Return HITLS_SUCCESS
@ */

/* BEGIN_CASE */
void UT_CONFIG_GET_CIPHERSUITES_TC001(void)
{
    FRAME_Init();
    uint16_t data[1024] = {0};
    uint32_t dataLen = sizeof(data) / sizeof(uint16_t);
    uint32_t cipherSuiteSize = 0;
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(HITLS_CFG_GetCipherSuites(NULL, data, dataLen, &cipherSuiteSize) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetCipherSuites(config, NULL, dataLen, &cipherSuiteSize) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetCipherSuites(config, data, dataLen, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetCipherSuites(config, data, 0, &cipherSuiteSize) == HITLS_CONFIG_INVALID_LENGTH);
    ASSERT_TRUE(HITLS_CFG_GetCipherSuites(config, data, dataLen, &cipherSuiteSize) == HITLS_SUCCESS);
    ASSERT_TRUE(data[0] == HITLS_AES_256_GCM_SHA384);
    ASSERT_TRUE(data[1] == HITLS_CHACHA20_POLY1305_SHA256);
    ASSERT_TRUE(data[2] == HITLS_AES_128_GCM_SHA256);
    ASSERT_TRUE(cipherSuiteSize == 3);
EXIT:
    HITLS_CFG_FreeConfig(config);
    return;
}
/* END_CASE */

/* @
* @test  HITLS_CCA_GLOBALCONFIG_005
* @spec  -
* @title  HITLS_SetNewConfig changes the session ID based on the config.
* @precon  nan
* @brief
1. Apply for a configuration file.
2. Apply for newconfig and set the session ID of newconfig to 123456789123456789123456.
3. Link establishment
4. Invoke the HITLS_SetNewConfig interface to change the session ID.
5. Establish a link and check the session ID of client hello.
* @expect
1. The initialization is successful.
2. The setting is successful.
3. The link is set up successfully.
4. The interface is successfully invoked.
5. The session ID is 123456789123456789123456.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_HITLS_GLOBALCONFIG_005()
{
    // 1. Apply for a configuration file.
    FRAME_Init();
    HITLS_Config *Config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(Config != NULL);
    HITLS_Ctx *ctx = HITLS_New(Config);
    ASSERT_TRUE(ctx != NULL);
    // 2. Apply for newconfig and set the session ID of newconfig to 123456789123456789123456.
    HITLS_Config *NewConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(NewConfig != NULL);
    uint8_t sessIdCtx[HITLS_SESSION_ID_CTX_MAX_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    // 3. Link establishment
    NewConfig->sessionIdCtxSize = 50;
    ASSERT_TRUE(memcpy_s(NewConfig->sessionIdCtx, HITLS_SESSION_ID_CTX_MAX_SIZE, sessIdCtx, sizeof(sessIdCtx)) == EOK);
    // 4. Invoke the HITLS_SetNewConfig interface to change the session ID.
    ctx->globalConfig = HITLS_SetNewConfig(ctx, NewConfig);
    // 5. Establish a link and check the session ID of client hello.
    ASSERT_TRUE(memcmp(ctx->globalConfig->sessionIdCtx, sessIdCtx, sizeof(sessIdCtx)) == 0);
    ASSERT_TRUE(ctx->globalConfig->sessionIdCtxSize == NewConfig->sessionIdCtxSize);
EXIT:
    HITLS_CFG_FreeConfig(Config);
    HITLS_CFG_FreeConfig(NewConfig);
    HITLS_Free(ctx);
}
/* END_CASE */