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
    if (strncmp(cert, "ECDSA-384", strlen("ECDSA-384")) == 0) {
        HLT_SetCertPath(ctxConfig, ECDSA_SHA_CA_PATH, ECDSA_SHA_CHAIN_PATH, ECDSA_SHA384_EE_PATH,
            ECDSA_SHA384_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(cert, "ECDSA-512", strlen("ECDSA-512")) == 0) {
        HLT_SetCertPath(ctxConfig, ECDSA_SHA_CA_PATH, ECDSA_SHA_CHAIN_PATH, ECDSA_SHA512_EE_PATH,
            ECDSA_SHA512_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(cert, "ECDSA", strlen("ECDSA")) == 0) {
        HLT_SetCertPath(ctxConfig, ECDSA_SHA_CA_PATH, ECDSA_SHA_CHAIN_PATH, ECDSA_SHA256_EE_PATH,
            ECDSA_SHA256_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(cert, "RSAE", strlen("RSAE")) == 0) {
        HLT_SetCertPath(ctxConfig, RSAPSS_RSAE_CA_PATH, RSAPSS_RSAE_CHAIN_PATH, RSAPSS_RSAE_EE_PATH,
            RSAPSS_RSAE_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(cert, "RSAPSS", strlen("RSAPSS")) == 0) {
        HLT_SetCertPath(ctxConfig, RSAPSS_SHA256_CA_PATH, RSAPSS_SHA256_CHAIN_PATH, RSAPSS_SHA256_EE_PATH,
            RSAPSS_SHA256_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(cert, "RSA", strlen("RSA")) == 0) {
        HLT_SetCertPath(ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, RSA_SHA256_PRIV_PATH3,
            "NULL", "NULL");
    } else if (strncmp(cert, "ED25519", strlen("ED25519")) == 0) {
        HLT_SetCertPath(ctxConfig, ED25519_SHA512_CA_PATH, ED25519_SHA512_CHAIN_PATH, ED25519_SHA512_EE_PATH,
            ED25519_SHA512_PRIV_PATH, "NULL", "NULL");
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

char *HITLS_Groups[] = {
    "HITLS_EC_GROUP_BRAINPOOLP256R1",
    "HITLS_EC_GROUP_BRAINPOOLP384R1",
    "HITLS_EC_GROUP_BRAINPOOLP512R1",
    "HITLS_EC_GROUP_SECP256R1",
    "HITLS_EC_GROUP_SECP384R1",
    "HITLS_EC_GROUP_SECP521R1",
    "HITLS_EC_GROUP_CURVE25519",
    "HITLS_FF_DHE_2048",
    "HITLS_FF_DHE_3072",
    "HITLS_FF_DHE_4096",
    "HITLS_FF_DHE_6144",
    "HITLS_FF_DHE_8192",
};

char *HITLS_Signatures[] = {
    "CERT_SIG_SCHEME_RSA_PKCS1_SHA1",
    "CERT_SIG_SCHEME_RSA_PKCS1_SHA224",
    "CERT_SIG_SCHEME_RSA_PKCS1_SHA256",
    "CERT_SIG_SCHEME_RSA_PKCS1_SHA384",
    "CERT_SIG_SCHEME_RSA_PKCS1_SHA512",
    "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256",
    "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384",
    "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512",
    "CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256",
    "CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384",
    "CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512",
    "CERT_SIG_SCHEME_ECDSA_SHA1",
    "CERT_SIG_SCHEME_ECDSA_SHA224",
    "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
    "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384",
    "CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512",
};

static void CONNECT(int version, int connType, char *Ciphersuite, char *groups, char *signature, int hasPsk, char *cert)
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

    HLT_SetGroups(clientCtxConfig, groups);
    HLT_SetGroups(serverCtxConfig, groups);

    HLT_SetSignature(clientCtxConfig, signature);
    HLT_SetSignature(serverCtxConfig, signature);

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

static void CONNECT_V12(char *Ciphersuite, char *groups, char *signature, int hasPsk, char *cert)
{
    CONNECT(TLS1_2, TCP, Ciphersuite, groups, signature, hasPsk, cert);
    if (IsEnableSctpAuth()) {
        CONNECT(DTLS1_2, SCTP, Ciphersuite, groups, signature, hasPsk, cert);
    }
    CONNECT(DTLS1_2, UDP, Ciphersuite, groups, signature, hasPsk, cert);
}

/* BEGIN_CASE */
void SDV_TLS_13_GROUP(void)
{
    for (uint16_t i = 3; i < sizeof(HITLS_Groups) / sizeof(HITLS_Groups[0]); i++) {
        CONNECT(TLS1_3, TCP, "HITLS_AES_256_GCM_SHA384", HITLS_Groups[i], NULL, 0, "RSA");
    }
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_12_GROUP(char *groups)
{
    CONNECT_V12("HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", groups, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256", 0, "RSA");
}
/* END_CASE */


/* 
tls12 dtls12
"CERT_SIG_SCHEME_ECDSA_SHA1",
"CERT_SIG_SCHEME_ECDSA_SHA224",
"CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
"CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384",
"CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512",
 */
/* BEGIN_CASE */
void SDV_TLS_ECDSA_SIGNATURE(char *signature)
{    
    CONNECT_V12("HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "HITLS_EC_GROUP_SECP256R1", signature, 0, "ECDSA");
}
/* END_CASE */

/* 
tls12 dtls12
"CERT_SIG_SCHEME_RSA_PKCS1_SHA1",
"CERT_SIG_SCHEME_RSA_PKCS1_SHA224",
"CERT_SIG_SCHEME_RSA_PKCS1_SHA256",
"CERT_SIG_SCHEME_RSA_PKCS1_SHA384",
"CERT_SIG_SCHEME_RSA_PKCS1_SHA512",
"CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256",
"CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384",
"CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512",
 */
/* BEGIN_CASE */
void SDV_TLS_RSA_SIGNATURE(char *signature)
{
    CONNECT_V12("HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "HITLS_EC_GROUP_SECP256R1", signature, 0, "RSAE");
}
/* END_CASE */

/* 
tls12 dtls12 tls13
"CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256",
"CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384",
"CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512",
*/
/* BEGIN_CASE */
void SDV_TLS_RSAPSS_SIGNATURE(char *signature)
{
    CONNECT(TLS1_3, TCP, "HITLS_AES_256_GCM_SHA384", "HITLS_EC_GROUP_SECP256R1", signature, 0, "RSAPSS");
    CONNECT_V12("HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "HITLS_EC_GROUP_SECP256R1", signature, 0, "RSAPSS");
}
/* END_CASE */

/* 
tls13
"CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256",
"CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384",
"CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512",
 */
/* BEGIN_CASE */
void SDV_TLS13_RSA_SIGNATURE(char *signature)
{
    CONNECT(TLS1_3, TCP, "HITLS_AES_256_GCM_SHA384", "HITLS_EC_GROUP_SECP256R1", signature, 0, "RSA");
}
/* END_CASE */

/*
tls13
"CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
"CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384",
"CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512",
 */
/* BEGIN_CASE */
void SDV_TLS13_ECDSA_SIGNATURE(char *signature, char *cert)
{
    CONNECT(TLS1_3, TCP, "HITLS_AES_256_GCM_SHA384", "HITLS_EC_GROUP_SECP256R1", signature, 0, cert);
}
/* END_CASE */

/*
tls13
"CERT_SIG_SCHEME_ED25519"
 */
/* BEGIN_CASE */
void SDV_TLS13_EDDSA_SIGNATURE(char *signature)
{
    CONNECT(TLS1_3, TCP, "HITLS_AES_256_GCM_SHA384", "HITLS_EC_GROUP_CURVE25519", signature, 0, "ED25519");
}
/* END_CASE */
