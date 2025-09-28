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
#include "stub_replace.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "tls.h"
#include "hs_ctx.h"
#include "pack.h"
#include "send_process.h"
#include "frame_link.h"
#include "frame_tls.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "cert.h"
#include "securec.h"
#include "rec_wrapper.h"
#include "conn_init.h"
#include "rec.h"
#include "parse.h"
#include "hs_msg.h"
#include "hs.h"
#include "alert.h"
#include "hitls_type.h"
#include "session_type.h"
#include "hitls_crypt_init.h"
#include "common_func.h"
#include "hlt.h"
#include "process.h"
#include "rec_read.h"
/* END_HEADER */

int GetTls13CipherSuite(const char *cipherSuite, uint16_t *suite, size_t *suiteLen)
{
    if (strcmp(cipherSuite, "HITLS_SM4_GCM_SM3") == 0) {
        suite[0] = HITLS_SM4_GCM_SM3;
        *suiteLen = 1;
        return 0;
    }
    if (strcmp(cipherSuite, "HITLS_SM4_CCM_SM3") == 0) {
        suite[0] = HITLS_SM4_CCM_SM3;
        *suiteLen = 1;
        return 0;
    }
    if (strcmp(cipherSuite, "HITLS_SM4_GCM_SM3:HITLS_SM4_CCM_SM3") == 0) {
        suite[0] = HITLS_SM4_GCM_SM3;
        suite[1] = HITLS_SM4_CCM_SM3;
        *suiteLen = 2;
        return 0;
    }
    if (strcmp(cipherSuite, "HITLS_SM4_CCM_SM3:HITLS_SM4_GCM_SM3") == 0) {
        suite[0] = HITLS_SM4_CCM_SM3;
        suite[1] = HITLS_SM4_GCM_SM3;
        *suiteLen = 2;
        return 0;
    }
    if (strcmp(cipherSuite, "HITLS_AES_128_GCM_SHA256") == 0) {
        suite[0] = HITLS_AES_128_GCM_SHA256;
        *suiteLen = 1;
        return 0;
    }
    if (strcmp(cipherSuite, "HITLS_SM4_GCM_SM3:HITLS_SM4_CCM_SM3") == 0) {
        suite[0] = HITLS_SM4_GCM_SM3;
        suite[1] = HITLS_SM4_CCM_SM3;
        *suiteLen = 2;
        return 0;
    }
    if (strcmp(cipherSuite, "HITLS_SM4_GCM_SM3:HITLS_AES_128_GCM_SHA256") == 0) {
        suite[0] = HITLS_SM4_GCM_SM3;
        suite[1] = HITLS_AES_128_GCM_SHA256;
        *suiteLen = 2;
        return 0;
    }
    return 0;
}

int GetTls13Sign(const char *sign, uint16_t *signs, size_t *signsLen)
{
    if (strcmp(sign, "sm2sig_sm3") == 0) {
        signs[0] = CERT_SIG_SCHEME_SM2_SM3;
        *signsLen = 1;
        return 0;
    }
    if (strcmp(sign, "rsa_pss_rsae_sha256:sm2sig_sm3") == 0) {
        signs[0] = CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256;
        signs[1] = CERT_SIG_SCHEME_SM2_SM3;
        *signsLen = 2;
        return 0;
    }
    if (strcmp(sign, "rsa_pss_rsae_sha256") == 0) {
        signs[0] = CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256;
        *signsLen = 1;
        return 0;
    }
    return 0;
}

int GetTls13Group(const char *group, uint16_t *groups, size_t *groupsLen)
{
    if (strcmp(group, "curveSM2") == 0) {
        groups[0] = HITLS_EC_GROUP_CURVESM2;
        *groupsLen = 1;
        return 0;
    }
    if (strcmp(group, "X25519:curveSM2") == 0) {
        groups[0] = HITLS_EC_GROUP_CURVE25519;
        groups[1] = HITLS_EC_GROUP_CURVESM2;
        *groupsLen = 2;
        return 0;
    }
    if (strcmp(group, "X25529:Secp56r1") == 0) {
        groups[0] = HITLS_EC_GROUP_CURVE25519;
        groups[1] = HITLS_EC_GROUP_SECP256R1;
        *groupsLen = 2;
        return 0;
    }
    return 0;
}

/**
 * @test  SDV_TLS_TLS13_RFC8998_CONSISTENCY_FUNC_TC001
 * @brief
 *   1. Initialize configuration
 *   2. Set the client and server CipherSuites/signAlgs/Groups/Certs and to establish connect. The
 *      expected connection setup is successful.
 * @expect
 *   1.Initialization succeeded.
 *   2.The connection is successfully established.
 */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8998_CONSISTENCY_FUNC_TC001(char *sCipherSuite, char *cCipherSuite, char *sSign, char *cSign,
                                                  char *sGroup, char *cGroup, char *sCert, char *cCert, int sVerifyMode,
                                                  int cVerifyMode, int expectedRes, int negotiateCipherSuite,
                                                  int negotiateGroup, int negotiateHashId, int version)
{
    FRAME_Init();
    HITLS_Config *config_c = HITLS_CFG_NewTLSConfig();
    HITLS_Config *config_s = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    ASSERT_EQ(HITLS_CFG_EnableTls13SM(config_c, false), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_EnableTls13SM(config_s, false), HITLS_SUCCESS);
    if (sVerifyMode == 1) {
        HITLS_CFG_SetVerifyNoneSupport(config_s, false);
    }
    if (sVerifyMode == 2 || sVerifyMode == 3) {
        HITLS_CFG_SetVerifyNoneSupport(config_s, false);
        HITLS_CFG_SetNoClientCertSupport(config_s, false);
        HITLS_CFG_SetClientVerifySupport(config_s, true);
    }
    if (sVerifyMode == 3) {
        HITLS_CFG_EnableTls13SM(config_c, true);
    }
    if (cVerifyMode == 1) {
        HITLS_CFG_SetVerifyNoneSupport(config_c, false);
    }
    if (cVerifyMode == 2) {
        HITLS_CFG_SetVerifyNoneSupport(config_c, false);
        HITLS_CFG_EnableTls13SM(config_c, true);
    }
    if (sCipherSuite != NULL) {
        uint16_t sCipherSuites[2] = {0};
        size_t sCipherSuitesLen = 0;
        GetTls13CipherSuite(sCipherSuite, sCipherSuites, &sCipherSuitesLen);
        HITLS_CFG_SetCipherSuites(config_s, sCipherSuites, sCipherSuitesLen);
    }
    if (cCipherSuite != NULL) {
        uint16_t cCipherSuites[2] = {0};
        size_t cCipherSuitesLen = 0;
        GetTls13CipherSuite(cCipherSuite, cCipherSuites, &cCipherSuitesLen);
        HITLS_CFG_SetCipherSuites(config_c, cCipherSuites, cCipherSuitesLen);
    }
    if (sSign != NULL) {
        uint16_t signAlgs_s[2] = {0};
        size_t signAlgs_s_len = 0;
        GetTls13Sign(sSign, signAlgs_s, &signAlgs_s_len);
        HITLS_CFG_SetSignature(config_s, signAlgs_s, signAlgs_s_len);
    }
    if (cSign != NULL) {
        uint16_t signAlgs_c[2] = {0};
        size_t signAlgs_c_len = 0;
        GetTls13Sign(cSign, signAlgs_c, &signAlgs_c_len);
        HITLS_CFG_SetSignature(config_c, signAlgs_c, signAlgs_c_len);
    }
    if (sGroup != NULL) {
        uint16_t groups_s[3] = {0};
        size_t groups_s_len = 0;
        GetTls13Group(sGroup, groups_s, &groups_s_len);
        HITLS_CFG_SetGroups(config_s, groups_s, groups_s_len);
    }
    if (cGroup != NULL) {
        uint16_t groups_c[3] = {0};
        size_t groups_c_len = 0;
        GetTls13Group(cGroup, groups_c, &groups_c_len);
        HITLS_CFG_SetGroups(config_c, groups_c, groups_c_len);
    }
    FRAME_CertInfo sSm2CertInfo[3] = {
        {RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH1, NULL, RSA_SHA256_PRIV_PATH1, NULL},
        {
            SM2_VERIFY_PATH,
            SM2_CHAIN_PATH,
            NULL,
            SM2_SERVER_SIGN_CERT_PATH,
            NULL,
            SM2_SERVER_SIGN_KEY_PATH,
        },
        {
            SM2_VERIFY_PATH,
            SM2_CHAIN_PATH,
            NULL,
            SM2_SERVER_ENC_CERT_PATH,
            NULL,
            SM2_SERVER_ENC_KEY_PATH,
        }};
    FRAME_CertInfo cSm2CertInfo[5] = {
        {RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, NULL, RSA_SHA256_PRIV_PATH3, NULL},
        {
            SM2_VERIFY_PATH,
            SM2_CHAIN_PATH,
            NULL,
            SM2_CLIENT_SIGN_CERT_PATH,
            NULL,
            SM2_CLIENT_SIGN_KEY_PATH,
        },
        {RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, NULL, RSA_SHA256_PRIV_PATH3, NULL},
        {SM2_VERIFY_PATH, SM2_CHAIN_PATH, RSA_SHA256_EE_PATH3, NULL, RSA_SHA256_PRIV_PATH3, NULL},
        {
            SM2_VERIFY_PATH,
            SM2_CHAIN_PATH,
            NULL,
            NULL,
            NULL,
            NULL,
        },

    };

    FRAME_LinkObj *server = NULL;
    if (sCert != NULL && (strcmp(sCert, "rsa:sm2") == 0 || strcmp(sCert, "sm2:rsa") == 0)) {
        server = FRAME_CreateLinkWithCerts(config_s, BSL_UIO_TCP, sSm2CertInfo, 2);
    } else if (sCert != NULL && strcmp(sCert, "sm2") == 0) {
        server = FRAME_CreateLinkWithCerts(config_s, BSL_UIO_TCP, &sSm2CertInfo[1], 1);
    } else if (sCert != NULL && strcmp(sCert, "rsa") == 0) {
        server = FRAME_CreateLinkWithCerts(config_s, BSL_UIO_TCP, &sSm2CertInfo[0], 1);
    } else if (sCert != NULL && strcmp(sCert, "sm2-enc") == 0) {
        server = FRAME_CreateLinkWithCerts(config_s, BSL_UIO_TCP, &sSm2CertInfo[2], 1);
    }
    FRAME_LinkObj *client = NULL;
    if (cCert != NULL && strcmp(cCert, "rsa:sm2") == 0) {
        client = FRAME_CreateLinkWithCerts(config_c, BSL_UIO_TCP, cSm2CertInfo, 2);
    } else if (cCert != NULL && strcmp(cCert, "sm2") == 0) {
        client = FRAME_CreateLinkWithCerts(config_c, BSL_UIO_TCP, &cSm2CertInfo[1], 1);
    } else if (cCert != NULL && strcmp(cCert, "rsa") == 0) {
        client = FRAME_CreateLinkWithCerts(config_c, BSL_UIO_TCP, &cSm2CertInfo[3], 1);
    } else if (cCert != NULL && strstr(cCert, "ca") != NULL) {
        client = FRAME_CreateLinkWithCerts(config_c, BSL_UIO_TCP, &cSm2CertInfo[4], 1);
    } else if (cCert != NULL && strstr(cCert, "sm2:rsa") != NULL) {
        client = FRAME_CreateLinkWithCerts(config_c, BSL_UIO_TCP, &cSm2CertInfo[1], 2);
    }

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, expectedRes);
    if (expectedRes == HITLS_SUCCESS) {
        ASSERT_EQ(server->ssl->negotiatedInfo.negotiatedGroup, negotiateGroup);
        ASSERT_EQ(client->ssl->negotiatedInfo.negotiatedGroup, negotiateGroup);
        ASSERT_EQ(server->ssl->negotiatedInfo.cipherSuiteInfo.cipherSuite, negotiateCipherSuite);
        ASSERT_EQ(client->ssl->negotiatedInfo.cipherSuiteInfo.cipherSuite, negotiateCipherSuite);
        ASSERT_EQ(server->ssl->negotiatedInfo.cipherSuiteInfo.hashAlg, negotiateHashId);
        ASSERT_EQ(client->ssl->negotiatedInfo.cipherSuiteInfo.hashAlg, negotiateHashId);
        ASSERT_EQ(server->ssl->negotiatedInfo.version, version);
        ASSERT_EQ(client->ssl->negotiatedInfo.version, version);
    }

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  SDV_TLS_TLS13_RFC8998_CONSISTENCY_FUNC_TC002
 * @brief
 *   1. Initialize configuration
 *   2. Set tls1.3 sm CipherSuites/signAlgs/Groups. The expected is successful.
 * @expect
 *   1.Initialization succeeded.
 *   2.The expected is successfully.
 */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8998_CONSISTENCY_FUNC_TC002(char *cipherSuite, char *sign, char *group)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config != NULL);
    const uint16_t smCiphersuites13[] = {
        HITLS_SM4_GCM_SM3,
        HITLS_SM4_CCM_SM3,
    };
    const uint16_t smSignAlg = CERT_SIG_SCHEME_SM2_SM3;
    const uint16_t smGroup = HITLS_EC_GROUP_CURVESM2;
    if (cipherSuite != NULL) {
        uint16_t cipherSuites[2] = {0};
        size_t cipherSuitesLen = 0;
        GetTls13CipherSuite(cipherSuite, cipherSuites, &cipherSuitesLen);
        HITLS_CFG_SetCipherSuites(config, cipherSuites, cipherSuitesLen);
    }
    if (sign != NULL) {
        uint16_t signAlgs_s[2] = {0};
        size_t signAlgs_s_len = 0;
        GetTls13Sign(sign, signAlgs_s, &signAlgs_s_len);
        HITLS_CFG_SetSignature(config, signAlgs_s, signAlgs_s_len);
    }
    if (group != NULL) {
        uint16_t groups_s[3] = {0};
        size_t groups_s_len = 0;
        GetTls13Group(group, groups_s, &groups_s_len);
        HITLS_CFG_SetGroups(config, groups_s, groups_s_len);
    }
    int32_t ret = HITLS_CFG_EnableTls13SM(config, false);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(config->tls13cipherSuitesSize, 5);
    ASSERT_EQ(memcmp(config->tls13CipherSuites, smCiphersuites13, sizeof(smCiphersuites13)), 0);
    ASSERT_EQ(config->signAlgorithms[0], smSignAlg);
    ASSERT_EQ(config->groups[0], smGroup);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/**
 * @test  SDV_TLS_TLS13_RFC8998_CONSISTENCY_FUNC_TC002
 * @brief
 *   1. Initialize configuration
 *   2. Set tls1.3 only support sm. The expected is successful.
 * @expect
 *   1.Initialization succeeded.
 *   2.The expected is successfully.
 */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8998_CONSISTENCY_FUNC_TC003()
{
    FRAME_Init();
    HITLS_Config *config_c = HITLS_CFG_NewTLSConfig();
    HITLS_Config *config_s = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    const uint16_t smCiphersuites13[] = {
        HITLS_SM4_GCM_SM3,
        HITLS_SM4_CCM_SM3,
    };
    const uint16_t smSignAlg = CERT_SIG_SCHEME_SM2_SM3;
    const uint16_t smGroup = HITLS_EC_GROUP_CURVESM2;
    int32_t ret = HITLS_CFG_EnableTls13SM(config_c, true);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_CFG_EnableTls13SM(config_s, true);
    ASSERT_EQ(config_c->cipherSuitesSize, 0);
    ASSERT_EQ(config_c->tls13cipherSuitesSize, sizeof(smCiphersuites13) / sizeof(uint16_t));
    ASSERT_EQ(memcmp(config_c->tls13CipherSuites, smCiphersuites13, sizeof(smCiphersuites13)), 0);
    ASSERT_EQ(config_c->signAlgorithmsSize, 1);
    ASSERT_EQ(config_c->signAlgorithms[0], smSignAlg);
    ASSERT_EQ(config_c->groupsSize, 1);
    ASSERT_EQ(config_c->groups[0], smGroup);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
}
/* END_CASE */