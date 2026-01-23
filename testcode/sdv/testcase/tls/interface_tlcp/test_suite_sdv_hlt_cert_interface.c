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

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <stdbool.h>

#include "hitls_error.h"
#include "hitls_cert.h"
#include "hitls.h"
#include "hitls_func.h"
#include "securec.h"
#include "cert_method.h"
#include "cert_mgr.h"
#include "cert_mgr_ctx.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "hlt_type.h"
#include "process.h"
#include "hlt.h"
#include "session.h"
#include "bsl_sal.h"
#include "alert.h"
#include "cert_callback.h"
#include "crypt_eal_rand.h"
#include "hitls_crypt_reg.h"
#include "hitls_crypt_init.h"
#include "logger.h"
#include "uio_base.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#include "hitls_cert_reg.h"
#include "hitls_config.h"
#include "hitls_cert_init.h"
#include "bsl_log.h"
#include "bsl_err.h"
#include "tls_config.h"
#include "tls.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_uio.h"
#include "bsl_obj.h"
#include "bsl_errno.h"
#include "hitls_x509_adapt.h"

/* END_HEADER */

#define BUF_MAX_SIZE 4096
int32_t g_uiPort = 18886;

#define DEFAULT_CERT_PATH       "../../testcode/testdata/tls/certificate/der/"
#define CERT_PATH_LEN 120
#define SUCCESS (0)
#define ERROR (1)
#define MAX_BUFFER (8192)
#define READ_BUF_LEN_18K (18 * 1024)
#define READ_DATA_18432 18432
#define PASSWDLEN (10)
#define CERT_PATH_BUFFER (100)

#define RSA_ROOT_CERT_DER         "rsa_sha/ca-3072.der"
#define RSA_CA_CERT_DER           "rsa_sha/inter-3072.der"
#define RSA_EE_CERT_DER           "rsa_sha/end-sha1.der"
#define RSA_PRIV_KEY_DER          "rsa_sha/end-sha1.key.der"
#define RSA_EE_CERT_DER           "rsa_sha/end-sha1.der"
#define RSA_PRIV_KEY_DER          "rsa_sha/end-sha1.key.der"

#define RSA_ROOT_CERT2_DER         "rsa_sha256/ca.der"
#define RSA_CA_CERT2_DER           "rsa_sha256/inter.der"
#define RSA_EE_CERT2_DER           "rsa_sha256/server.der"
#define RSA_PRIV_KEY2_DER          "rsa_sha256/server.key.der"

#define ECDSA_ROOT_CERT_DER        "ecdsa/ca-nist521.der"
#define ECDSA_CA_CERT_DER          "ecdsa/inter-nist521.der"
#define ECDSA_EE_CERT_DER          "ecdsa/end256-sha256.der"
#define ECDSA_PRIV_KEY_DER         "ecdsa/end256-sha256.key.der"

typedef enum {
    SHALLOW_COPY = 0,
    DEEP_COPY,
} COPY_WAY;

typedef enum {
    ECDSA_CERT,
    ED25519_CERT,
    RSA_CERT,
    RSA_CERT_TWO,
    RSA_CERT_THREE,
} EE_CERT_TYPE;

typedef enum {
    FROM_CONFIG,
    FROM_CTX,
    FROM_BUFFER_TO_CONFIG,
    FROM_BUFFER_TO_CTX
} LOAD_CERT_WAY;
typedef LOAD_CERT_WAY LOAD_KEY_WAY;

int GetCertPathFrom(int eeCertType, char **rootCA, char **ca, char **ee, char **prvKey)
{
    switch (eeCertType) {
        case RSA_CERT:
            *rootCA = RSA_ROOT_CERT_DER;
            *ca = RSA_CA_CERT_DER;
            *ee = RSA_EE_CERT_DER;
            *prvKey = RSA_PRIV_KEY_DER;
            return SUCCESS;
        case RSA_CERT_TWO:
            *rootCA = RSA_ROOT_CERT2_DER;
            *ca = RSA_CA_CERT2_DER;
            *ee = RSA_EE_CERT2_DER;
            *prvKey = RSA_PRIV_KEY2_DER;
            return SUCCESS;
        case RSA_CERT_THREE:
            *rootCA = RSA_ROOT_CERT_DER;
            *ca = RSA_CA_CERT_DER;
            *ee = RSA_EE_CERT_DER;
            *prvKey = RSA_PRIV_KEY_DER;
            return SUCCESS;
        case ECDSA_CERT:
            *rootCA = ECDSA_ROOT_CERT_DER;
            *ca = ECDSA_CA_CERT_DER;
            *ee = ECDSA_EE_CERT_DER;
            *prvKey = ECDSA_PRIV_KEY_DER;
            return SUCCESS;
        default:
            return ERROR;
    }
}

int NormalizePath(char* normalizedPath, const char* path) {
    int ret;
    ret = sprintf_s(normalizedPath, CERT_PATH_LEN, "%s%s", DEFAULT_CERT_PATH, path);
    if (ret <= 0) {
        LOG_ERROR("sprintf_s Error");
        return ERROR;
    }
    return SUCCESS;
}

int Dtls_DataTransfer(HITLS_Ctx *clientCtx, HLT_Process *remoteProcess, HLT_Tls_Res *serverRes)
{
    uint8_t *writeBuf = (uint8_t *)"hello world";
    uint32_t writeLen = strlen((char *)writeBuf);
    uint8_t readBuf[READ_DATA_18432] = { 0 };
    uint32_t readLen = 0;
    ASSERT_EQ(HLT_TlsWrite(clientCtx,  writeBuf, writeLen), SUCCESS);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, serverRes, readBuf, READ_DATA_18432, &readLen), 0);
    ASSERT_COMPARE("COMPARE DATA", writeBuf, writeLen, readBuf, readLen);
    return SUCCESS;
EXIT:
    return ERROR;
}

HITLS_Ctx *Dtls_New_Ctx(HLT_Process *localProcess, HITLS_Config* clientConfig)
{
    HITLS_Ctx *clientCtx =  HLT_TlsNewSsl(clientConfig);
    ASSERT_TRUE(clientCtx != NULL);
    HLT_Ssl_Config clientCtxConfig;
    clientCtxConfig.sockFd = localProcess->connFd;
    clientCtxConfig.connType = SCTP;
    ASSERT_TRUE_AND_LOG("HLT_TlsSetSsl", HLT_TlsSetSsl(clientCtx, &clientCtxConfig) == 0);
    return clientCtx;

EXIT:
    return NULL;
}

void TestSetCertPath(HLT_Ctx_Config *ctxConfig, char *SignatureType)
{
    if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA1", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA1")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA256")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, RSA_SHA256_PRIV_PATH3, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA384", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA384")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA384_EE_PATH, RSA_SHA384_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA512", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA512")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA512_EE_PATH, RSA_SHA512_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA256_EE_PATH,
            ECDSA_SHA256_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA384_EE_PATH,
            ECDSA_SHA384_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA512_EE_PATH,
            ECDSA_SHA512_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_ECDSA_SHA1", strlen("CERT_SIG_SCHEME_ECDSA_SHA1")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA1_CA_PATH,
            ECDSA_SHA1_CHAIN_PATH,
            ECDSA_SHA1_EE_PATH,
            ECDSA_SHA1_PRIV_PATH,
            "NULL",
            "NULL");
    }
}

HITLS_CERT_X509 *HiTLS_X509_LoadCertFile(HITLS_Config *tlsCfg, const char *file);

/* @
* @test  SDV_TLS_LoadAndDelCert_FUNC_TC001
* @title  Loading and Deleting Certificates
* @precon  nan
* @brief  1. Initialize the client and server. Expected result 1
          2. Load the certificate to the certificate chain. Expected result 2
          3. Load the first certificate and private key to the certificate chain. Expected result 2
          4. Load the second certificate to the certificate chain. Expected result 2
          5. Run the config command to remove all certificates. Expected result 3
          6. Load the third certificate to the certificate chain. Expected result 2
          7. Remove all certificates in CTX mode. Expected result 3
          8. Load the third certificate to the certificate chain. Expected result 2
          9. Initiate link establishment. Expected result 4 is obtained
* @expect 1. Initialization succeeded.
          2. Loading succeeded.
          3. Removing succeeded.
          4. Link setup succeeded
@ */
/* BEGIN_CASE */
void SDV_TLS_CERT_LoadAndDelCert_FUNC_TC001(int delWay)
{
    if (!IsEnableSctpAuth()) {
        return;
    }
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HITLS_Config* serverConfig = NULL;

    // Stores the path where the certificate is loaded for the first time.
    char *rootCAFilePath1 = NULL;
    char *caFilePath1 = NULL;
    char *eeFilePath1 = NULL;
    char *eeKeyPath1 = NULL;
    // Stores the path where the certificate is loaded for the second time.
    char *rootCAFilePath2 = NULL;
    char *caFilePath2 = NULL;
    char *eeFilePath2 = NULL;
    char *eeKeyPath2 = NULL;
    HITLS_CERT_X509 *eeCert3 = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    HILT_TransportType connType = SCTP;
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, g_uiPort, false);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    TestSetCertPath(clientCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");
    rootCAFilePath1 = DEFAULT_CERT_PATH""RSA_ROOT_CERT_DER;
    caFilePath1 = DEFAULT_CERT_PATH""RSA_CA_CERT_DER;
    eeFilePath1 = DEFAULT_CERT_PATH""RSA_EE_CERT_DER;
    eeKeyPath1 = DEFAULT_CERT_PATH""RSA_PRIV_KEY_DER;
    rootCAFilePath2 = DEFAULT_CERT_PATH""ECDSA_ROOT_CERT_DER;
    caFilePath2 = DEFAULT_CERT_PATH""ECDSA_CA_CERT_DER;
    eeFilePath2 = DEFAULT_CERT_PATH""ECDSA_EE_CERT_DER;
    eeKeyPath2 = DEFAULT_CERT_PATH""ECDSA_PRIV_KEY_DER;

    ASSERT_EQ(HLT_TlsRegCallback(HITLS_CALLBACK_DEFAULT), SUCCESS);
    serverConfig = HLT_TlsNewCtx(DTLS1_2);
    ASSERT_TRUE(serverConfig != NULL);
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    ASSERT_EQ(HITLS_CFG_SetGroups(serverConfig, &group, 1), SUCCESS);
    // Load the certificate to the Chain Store.
    HITLS_CERT_Store *chainStore = HITLS_X509_Adapt_StoreNew();
    ASSERT_TRUE(chainStore != NULL);
    ASSERT_EQ(HITLS_CFG_SetVerifyStore(serverConfig, chainStore, SHALLOW_COPY), SUCCESS);
    HITLS_CERT_X509 *rootCACert2 = HiTLS_X509_LoadCertFile(serverConfig, rootCAFilePath2);
    ASSERT_TRUE(rootCACert2 != NULL);
    ASSERT_EQ(HITLS_CFG_AddCertToStore(serverConfig, rootCACert2, TLS_CERT_STORE_TYPE_VERIFY, false), HITLS_SUCCESS);
    HITLS_CERT_X509 *caCert2 = HiTLS_X509_LoadCertFile(serverConfig, caFilePath2);
    ASSERT_TRUE(caCert2 != NULL);
    ASSERT_EQ(HITLS_CFG_AddCertToStore(serverConfig, caCert2, TLS_CERT_STORE_TYPE_VERIFY, false), HITLS_SUCCESS);

    // Loading the device certificate and corresponding private key for the first time
    HITLS_CERT_X509 *eeCert1 = HiTLS_X509_LoadCertFile(serverConfig, eeFilePath2);
    ASSERT_TRUE(eeCert1 != NULL);
    ASSERT_EQ(HITLS_CFG_SetCertificate(serverConfig, eeCert1, SHALLOW_COPY), SUCCESS);
    HITLS_CERT_Key *prvKey1 = HITLS_CFG_ParseKey(serverConfig, (const uint8_t *)eeKeyPath2, strlen(eeKeyPath1),
        TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(prvKey1 != NULL);
    ASSERT_EQ(HITLS_CFG_SetPrivateKey(serverConfig, prvKey1, SHALLOW_COPY), SUCCESS);

    // The private key is not loaded when the certificate is loaded for the second time.
    HITLS_CERT_X509 *eeCert2 = HiTLS_X509_LoadCertFile(serverConfig, eeFilePath2);
    ASSERT_TRUE(eeCert2 != NULL);
    ASSERT_EQ(HITLS_CFG_SetCertificate(serverConfig, eeCert2, SHALLOW_COPY), SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetCertificate(serverConfig) == eeCert2);

    if (delWay == FROM_CONFIG) {
        ASSERT_EQ(HITLS_CFG_RemoveCertAndKey(serverConfig), SUCCESS);
        // Reload the certificate without loading the private key.
        eeCert3 = HiTLS_X509_LoadCertFile(serverConfig, eeFilePath2);
        ASSERT_TRUE(eeCert3 != NULL);
        ASSERT_EQ(HITLS_CFG_SetCertificate(serverConfig, eeCert3, SHALLOW_COPY), SUCCESS);
#ifdef HITLS_TLS_FEATURE_PROVIDER
        HITLS_CERT_Key *prvKey2 = HITLS_X509_Adapt_ProviderKeyParse(serverConfig, (const uint8_t *)eeKeyPath2,
            strlen(eeKeyPath2), TLS_PARSE_TYPE_FILE, "ASN1", NULL);
#else
        HITLS_CERT_Key *prvKey2 = HITLS_X509_Adapt_KeyParse(serverConfig, (const uint8_t *)eeKeyPath2,
            strlen(eeKeyPath2), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
#endif
        ASSERT_TRUE(prvKey2 != NULL);
        ASSERT_EQ(HITLS_CFG_SetPrivateKey(serverConfig, prvKey2, SHALLOW_COPY), SUCCESS);
        ASSERT_TRUE(HITLS_CFG_GetPrivateKey(serverConfig) == prvKey2);
    }
    HITLS_Ctx *serverCtx = Dtls_New_Ctx(localProcess, serverConfig);
    ASSERT_TRUE(serverCtx != NULL);

    if (delWay == FROM_CTX) {
        // After the certificate is loaded from Config, the certificate is copied to CTX.
        ASSERT_TRUE(HITLS_GetCertificate(serverCtx) != eeCert2);
        ASSERT_EQ(HITLS_RemoveCertAndKey(serverCtx), SUCCESS);
        // Reload the certificate without loading the private key.
        eeCert3 = HiTLS_X509_LoadCertFile(serverConfig, eeFilePath2);
        ASSERT_TRUE(eeCert3 != NULL);
        ASSERT_EQ(HITLS_SetCertificate(serverCtx, eeCert3, SHALLOW_COPY), SUCCESS);
#ifdef HITLS_TLS_FEATURE_PROVIDER
        HITLS_CERT_Key *prvKey2 = HITLS_X509_Adapt_ProviderKeyParse(serverConfig, (const uint8_t *)eeKeyPath2,
            strlen(eeKeyPath2), TLS_PARSE_TYPE_FILE, "ASN1", NULL);
#else
        HITLS_CERT_Key *prvKey2 = HITLS_X509_Adapt_KeyParse(serverConfig, (const uint8_t *)eeKeyPath2,
            strlen(eeKeyPath2), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
#endif
        ASSERT_TRUE(prvKey2 != NULL);
        ASSERT_EQ(HITLS_SetPrivateKey(serverCtx, prvKey2, SHALLOW_COPY), SUCCESS);
        ASSERT_TRUE(HITLS_GetCertificate(serverCtx) == eeCert3);
        ASSERT_TRUE(HITLS_GetPrivateKey(serverCtx) == prvKey2);
    }
    unsigned long int tlsAcceptId = HLT_TlsAccept(serverCtx);
    clientRes = HLT_ProcessTlsConnect(remoteProcess, DTLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResultFromId(tlsAcceptId), 0);
    ASSERT_EQ(Dtls_DataTransfer(serverCtx, remoteProcess, clientRes), SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());
    
EXIT:
    HLT_FreeAllProcess();
    return;
}
/* END_CASE */
