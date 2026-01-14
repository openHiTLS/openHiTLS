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
#include <unistd.h>
#include <stdbool.h>
#include <semaphore.h>
#include "securec.h"
#include "hlt.h"
#include "logger.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "crypt_util_rand.h"
#include "helper.h"
#include "hitls.h"
#include "frame_tls.h"
#include "hitls_type.h"
/* END_HEADER */

#define READ_BUF_LEN_18K (18 * 1024)
#define PORT 10086
int32_t g_testSecurityLevel = 0;

void SetCert(HLT_Ctx_Config *ctxConfig, char *cert)
{
    if (strncmp(cert, "RSA", strlen("RSA")) == 0) {
        HLT_SetCertPath(ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, RSA_SHA256_PRIV_PATH3,
            "NULL", "NULL");
    } else if (strncmp(cert, "ECDSA", strlen("ECDSA")) == 0) {
        HLT_SetCertPath(ctxConfig, ECDSA_SHA_CA_PATH, ECDSA_SHA_CHAIN_PATH, ECDSA_SHA256_EE_PATH,
            ECDSA_SHA256_PRIV_PATH, "NULL", "NULL");
    }
}

void SetGMCert(HLT_Ctx_Config *serverCtxConfig, HLT_Ctx_Config *clientCtxConfig, char *cert)
{
    if (strncmp(cert, "SM2", strlen("SM2")) == 0) {
        HLT_SetCertPath(serverCtxConfig, SM2_VERIFY_PATH, SM2_CHAIN_PATH, SM2_SERVER_ENC_CERT_PATH, SM2_SERVER_ENC_KEY_PATH,
                    SM2_SERVER_SIGN_CERT_PATH, SM2_SERVER_SIGN_KEY_PATH);
        HLT_SetCertPath(clientCtxConfig, SM2_VERIFY_PATH, SM2_CHAIN_PATH, SM2_CLIENT_ENC_CERT_PATH, SM2_CLIENT_ENC_KEY_PATH,
                    SM2_CLIENT_SIGN_CERT_PATH, SM2_CLIENT_SIGN_KEY_PATH);
    }
}

char *HITLS_TLS13_Ciphersuite[] = {
    "HITLS_AES_128_GCM_SHA256",
    "HITLS_AES_256_GCM_SHA384",
    "HITLS_CHACHA20_POLY1305_SHA256",
    "HITLS_AES_128_CCM_SHA256",
    "HITLS_AES_128_CCM_8_SHA256",
};

// RSA Authentication
char *HITLS_RSA_Ciphersuite[] = {
    "HITLS_RSA_WITH_AES_128_CBC_SHA",
    "HITLS_RSA_WITH_AES_256_CBC_SHA",
    "HITLS_RSA_WITH_AES_128_CBC_SHA256",
    "HITLS_RSA_WITH_AES_256_CBC_SHA256",
    "HITLS_RSA_WITH_AES_128_GCM_SHA256",
    "HITLS_RSA_WITH_AES_256_GCM_SHA384",
    "HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "HITLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "HITLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "HITLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "HITLS_DHE_RSA_WITH_AES_128_CCM",
    "HITLS_DHE_RSA_WITH_AES_256_CCM",
    "HITLS_RSA_WITH_AES_256_CCM",
    "HITLS_RSA_WITH_AES_256_CCM_8",
    "HITLS_RSA_WITH_AES_128_CCM",
    "HITLS_RSA_WITH_AES_128_CCM_8",
};

// ECDSA Authentication
char *HITLS_ECDSA_Ciphersuite[] = {
    "HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "HITLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    "HITLS_ECDHE_ECDSA_WITH_AES_256_CCM",
};

char *HITLS_ANON_Ciphersuite[] = {
    "HITLS_DH_ANON_WITH_AES_128_CBC_SHA",
    "HITLS_DH_ANON_WITH_AES_256_CBC_SHA",
    "HITLS_DH_ANON_WITH_AES_128_CBC_SHA256",
    "HITLS_DH_ANON_WITH_AES_256_CBC_SHA256",
    "HITLS_DH_ANON_WITH_AES_128_GCM_SHA256",
    "HITLS_DH_ANON_WITH_AES_256_GCM_SHA384",
    "HITLS_ECDH_ANON_WITH_AES_128_CBC_SHA",
    "HITLS_ECDH_ANON_WITH_AES_256_CBC_SHA",
};

// PSK Authentication
char *HITLS_PSK_Ciphersuite[] = {
    "HITLS_PSK_WITH_AES_128_CBC_SHA",
    "HITLS_PSK_WITH_AES_256_CBC_SHA",
    "HITLS_PSK_WITH_AES_128_GCM_SHA256",
    "HITLS_PSK_WITH_AES_256_GCM_SHA384",
    "HITLS_PSK_WITH_AES_128_CBC_SHA256",
    "HITLS_PSK_WITH_AES_256_CBC_SHA384",
    "HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    "HITLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    "HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    "HITLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
    "HITLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
    "HITLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    "HITLS_RSA_PSK_WITH_AES_128_CBC_SHA",
    "HITLS_RSA_PSK_WITH_AES_256_CBC_SHA",
    "HITLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
    "HITLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
    "HITLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
    "HITLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
    "HITLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
    "HITLS_DHE_PSK_WITH_AES_128_CBC_SHA",
    "HITLS_DHE_PSK_WITH_AES_256_CBC_SHA",
    "HITLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    "HITLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    "HITLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
    "HITLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
    "HITLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    "HITLS_DHE_PSK_WITH_AES_128_CCM",
    "HITLS_DHE_PSK_WITH_AES_256_CCM",
    "HITLS_PSK_WITH_AES_256_CCM",
    "HITLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
    "HITLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
    "HITLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
};

char *HITLS_GM_Ciphersuite[] = {
    "HITLS_ECDHE_SM4_CBC_SM3",
    "HITLS_ECC_SM4_CBC_SM3",
    "HITLS_ECDHE_SM4_GCM_SM3",
    "HITLS_ECC_SM4_GCM_SM3",
};

static void CONNECT(int version, int connType, char *Ciphersuite, int hasPsk, char *cert)
{
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, PORT, true);
    ASSERT_TRUE(localProcess != NULL);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    if (version == TLCP1_1 || version == DTLCP1_1) {
        serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
        clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    } else {
        serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
        clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    }
    
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(clientCtxConfig != NULL);

    uint8_t psk[] = "12121212121212";
    if (hasPsk) {
        memcpy_s(serverCtxConfig->psk, PSK_MAX_LEN, psk, sizeof(psk));
        memcpy_s(clientCtxConfig->psk, PSK_MAX_LEN, psk, sizeof(psk));
    }

    serverCtxConfig->securitylevel = g_testSecurityLevel;
    clientCtxConfig->securitylevel = g_testSecurityLevel;
    if (version == TLCP1_1 || version == DTLCP1_1) {
        SetGMCert(serverCtxConfig, clientCtxConfig, cert);
    } else {
        SetCert(serverCtxConfig, cert);
        SetCert(clientCtxConfig, cert);
    }

    HLT_SetCipherSuites(serverCtxConfig, Ciphersuite);
    HLT_SetCipherSuites(clientCtxConfig, Ciphersuite);

    HLT_Tls_Res *serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Tls_Res *clientRes = HLT_ProcessTlsConnect(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HLT_FreeAllProcess();
}

/* BEGIN_CASE */
void SDV_TLS_TLS13_CIPHER_SUITE(void)
{
    for (uint16_t i = 0; i < sizeof(HITLS_TLS13_Ciphersuite) / sizeof(HITLS_TLS13_Ciphersuite[0]); i++) {
        CONNECT(TLS1_3, TCP, HITLS_TLS13_Ciphersuite[i], 0, "RSA");
    }
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_RSA_CIPHER_SUITE(void)
{
    for (uint16_t i = 0; i < sizeof(HITLS_RSA_Ciphersuite) / sizeof(HITLS_RSA_Ciphersuite[0]); i++) {
        SUB_PROC_BEGIN(continue);
        CONNECT(TLS1_2, TCP, HITLS_RSA_Ciphersuite[i], 0, "RSA");
        if (IsEnableSctpAuth()) {
            CONNECT(DTLS1_2, SCTP, HITLS_RSA_Ciphersuite[i], 0, "RSA");
        }
        CONNECT(DTLS1_2, UDP, HITLS_RSA_Ciphersuite[i], 0, "RSA");
        SUB_PROC_END();
    }
    SUB_PROC_WAIT(sizeof(HITLS_RSA_Ciphersuite) / sizeof(HITLS_RSA_Ciphersuite[0]));
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_ECDSA_CIPHER_SUITE(void)
{
    for (uint16_t i = 0; i < sizeof(HITLS_ECDSA_Ciphersuite) / sizeof(HITLS_ECDSA_Ciphersuite[0]); i++) {
        SUB_PROC_BEGIN(continue);
        CONNECT(TLS1_2, TCP, HITLS_ECDSA_Ciphersuite[i], 0, "ECDSA");
        if (IsEnableSctpAuth()) {
            CONNECT(DTLS1_2, SCTP, HITLS_ECDSA_Ciphersuite[i], 0, "ECDSA");
        }
        CONNECT(DTLS1_2, UDP, HITLS_ECDSA_Ciphersuite[i], 0, "ECDSA");
        SUB_PROC_END();
    }
    SUB_PROC_WAIT(sizeof(HITLS_ECDSA_Ciphersuite) / sizeof(HITLS_ECDSA_Ciphersuite[0]));
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_PSK_CIPHER_SUITE(void)
{
    for (uint16_t i = 0; i < sizeof(HITLS_PSK_Ciphersuite) / sizeof(HITLS_PSK_Ciphersuite[0]); i++)
    {
        SUB_PROC_BEGIN(continue);
        CONNECT(TLS1_2, TCP, HITLS_PSK_Ciphersuite[i], 1, "RSA");
        if (IsEnableSctpAuth()) {
            CONNECT(DTLS1_2, SCTP, HITLS_PSK_Ciphersuite[i], 1, "RSA");
        }
        CONNECT(DTLS1_2, UDP, HITLS_PSK_Ciphersuite[i], 1, "RSA");
        SUB_PROC_END();
    }
    SUB_PROC_WAIT(sizeof(HITLS_PSK_Ciphersuite) / sizeof(HITLS_PSK_Ciphersuite[0]));
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_ANON_CIPHER_SUITE(void)
{
    for (uint16_t i = 0; i < sizeof(HITLS_ANON_Ciphersuite) / sizeof(HITLS_ANON_Ciphersuite[0]); i++) {
        SUB_PROC_BEGIN(continue);
        CONNECT(TLS1_2, TCP, HITLS_ANON_Ciphersuite[i], 0, "RSA");
        if (IsEnableSctpAuth()) {
            CONNECT(DTLS1_2, SCTP, HITLS_ANON_Ciphersuite[i], 0, "RSA");
        }
        CONNECT(DTLS1_2, UDP, HITLS_ANON_Ciphersuite[i], 0, "RSA");
        SUB_PROC_END();
    }
    SUB_PROC_WAIT(sizeof(HITLS_ANON_Ciphersuite) / sizeof(HITLS_ANON_Ciphersuite[0]));
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_GM_CIPHER_SUITE(void)
{
    for (uint16_t i = 0; i < sizeof(HITLS_GM_Ciphersuite) / sizeof(HITLS_GM_Ciphersuite[0]); i++) {
        SUB_PROC_BEGIN(continue);
        CONNECT(TLCP1_1, TCP, HITLS_GM_Ciphersuite[i], 0, "SM2");
        if (IsEnableSctpAuth()) {
            CONNECT(DTLCP1_1, SCTP, HITLS_GM_Ciphersuite[i], 0, "SM2");
        }
        SUB_PROC_END();
    }
    SUB_PROC_WAIT(sizeof(HITLS_GM_Ciphersuite) / sizeof(HITLS_GM_Ciphersuite[0]));
}
/* END_CASE */