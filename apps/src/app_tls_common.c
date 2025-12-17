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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include "securec.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_utils.h"
#include "app_provider.h"
#include "app_keymgmt.h"
#include "hitls_config.h"
#include "hitls_cert.h"
#include "hitls_pki_cert.h"
#include "hitls_type.h"
#include "cipher_suite.h"
#include "hitls_session.h"
#include "hitls_cert_type.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "sal_file.h"
#include "app_tls_common.h"

#define HEARTBEAT_STR "heartbeat"

APP_ProtocolType ParseProtocolType(const char *protocolStr)
{
    if (protocolStr == NULL) {
        return APP_PROTOCOL_TLS;  // Default to TLS protocol
    }

    if (strcmp(protocolStr, "tls") == 0) {
        return APP_PROTOCOL_TLS;
    } else if (strcmp(protocolStr, "tlcp") == 0) {
        return APP_PROTOCOL_TLCP;
    } else if (strcmp(protocolStr, "dtlcp") == 0) {
        return APP_PROTOCOL_DTLCP;
    }

    return APP_PROTOCOL_TLS; /* Default fallback */
}

HITLS_Config *CreateProtocolConfig(APP_ProtocolType protocol, AppProvider *provider)
{
    HITLS_Config *config = NULL;

    switch (protocol) {
        case APP_PROTOCOL_TLS:
            config = HITLS_CFG_ProviderNewTLSConfig(APP_GetCurrent_LibCtx(), provider->providerAttr);
            break;
        case APP_PROTOCOL_TLCP:
            config = HITLS_CFG_ProviderNewTLCPConfig(APP_GetCurrent_LibCtx(), provider->providerAttr);
            break;
        case APP_PROTOCOL_DTLCP:
            config = HITLS_CFG_ProviderNewDTLCPConfig(APP_GetCurrent_LibCtx(), provider->providerAttr);
            break;
        default:
            AppPrintError("Unsupported protocol type: %d\n", protocol);
            return NULL;
    }

    if (config == NULL) {
        AppPrintError("Failed to create protocol configuration\n");
    }
#ifdef HITLS_APP_SM_MODE
    int32_t ret = HITLS_CFG_SetSessionTicketSupport(config, false);
    if (ret != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        AppPrintError("Failed to set session ticket support, errCode: 0x%x.\n", ret);
        return NULL;
    }
#endif
    return config;
}

int ConfigureCipherSuites(HITLS_Config *config, const char *cipherStr, APP_ProtocolType protocol)
{
    if (config == NULL || cipherStr == NULL) {
        return HITLS_APP_INVALID_ARG;
    }

    int32_t ret;
    uint32_t protocolVersion = 0;
    bool needVersionCheck = false;

    // Only check version for TLCP/DTLCP, TLS does not need version check
    if (protocol == APP_PROTOCOL_DTLCP || protocol == APP_PROTOCOL_TLCP) {
        protocolVersion = HITLS_VERSION_TLCP_DTLCP11;
        needVersionCheck = true;
    }

    // Support multiple cipher suites separated by colon
    // Example: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
    char *cipherStrCopy = BSL_SAL_Malloc(strlen(cipherStr) + 1);
    if (cipherStrCopy == NULL) {
        AppPrintError("Failed to allocate memory for cipher string\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    strcpy_s(cipherStrCopy, strlen(cipherStr) + 1, cipherStr);

    // Count number of cipher suites (based on colon count)
    uint32_t cipherCount = 1;
    for (const char *p = cipherStr; *p != '\0'; p++) {
        if (*p == ':') {
            cipherCount++;
        }
    }

    // Allocate cipher suite array
    uint16_t *cipherSuites = BSL_SAL_Malloc(sizeof(uint16_t) * cipherCount);
    if (cipherSuites == NULL) {
        BSL_SAL_Free(cipherStrCopy);
        AppPrintError("Failed to allocate memory for cipher suites\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }

    // Parse each cipher suite
    uint32_t index = 0;
    char *token = strtok(cipherStrCopy, ":");
    while (token != NULL && index < cipherCount) {
        const HITLS_Cipher *cipher = HITLS_CFG_GetCipherSuiteByStdName((const uint8_t *)token);
        if (cipher == NULL) {
            AppPrintError("Invalid cipher suite: %s\n", token);
            BSL_SAL_Free(cipherStrCopy);
            BSL_SAL_Free(cipherSuites);
            return HITLS_APP_ERR_SET_CIPHER;
        }

        // Only check version range for TLCP/DTLCP
        if (needVersionCheck) {
            if (protocolVersion < cipher->minVersion || protocolVersion > cipher->maxVersion) {
                AppPrintError("Protocol (%d) not in cipher suite version range [%d, %d]!\n",
                    protocolVersion, cipher->minVersion, cipher->maxVersion);
                BSL_SAL_Free(cipherStrCopy);
                BSL_SAL_Free(cipherSuites);
                return HITLS_APP_ERR_SET_CIPHER;
            }
        }

        ret = HITLS_CFG_GetCipherSuite(cipher, &cipherSuites[index]);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to get cipher suite for %s: 0x%x\n", token, ret);
            BSL_SAL_Free(cipherStrCopy);
            BSL_SAL_Free(cipherSuites);
            return HITLS_APP_ERR_SET_CIPHER;
        }

        index++;
        token = strtok(NULL, ":");
    }

    // Set cipher suite array
    ret = HITLS_CFG_SetCipherSuites(config, cipherSuites, index);
    BSL_SAL_Free(cipherStrCopy);
    BSL_SAL_Free(cipherSuites);
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to set cipher suites: 0x%x\n", ret);
        return HITLS_APP_ERR_SET_CIPHER;
    }
    return HITLS_APP_SUCCESS;
}

typedef struct {
    const char *name;
    BSL_ParseFormat format;
} FormatMapEntry;

static const FormatMapEntry FORMAT_MAP[] = {
    {"ASN1", BSL_FORMAT_ASN1},
    {"PEM", BSL_FORMAT_PEM},
};

const char *GetFormatName(BSL_ParseFormat format)
{
    for (size_t i = 0; i < sizeof(FORMAT_MAP)/sizeof(FORMAT_MAP[0]); ++i) {
        if (FORMAT_MAP[i].format == format) {
            return FORMAT_MAP[i].name;
        }
    }
    return NULL;
}

HITLS_X509_Cert *LoadCertFromFile(const char *certFile, BSL_ParseFormat format, AppProvider *provider)
{
    if (certFile == NULL) {
        return NULL;
    }
    const char *formatName = GetFormatName(format);
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = BSL_SAL_ReadFile(certFile, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        return NULL;
    }
    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_X509_ProviderCertParseBuff(APP_GetCurrent_LibCtx(), provider->providerAttr, formatName, &encode, &cert);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_Free(data);
        AppPrintError("Failed to load certificate from %s: 0x%x\n", certFile, ret);
        return NULL;
    }
    BSL_SAL_Free(data);
    return cert;
}

#ifdef HITLS_APP_SM_MODE
static int32_t GetPkeyCtxFromUuid(AppProvider *provider, HITLS_APP_SM_Param *smParam, char *uuid,
    CRYPT_EAL_PkeyCtx **ctx)
{
    HITLS_APP_KeyInfo keyInfo = {0};
    HITLS_APP_SM_Param param = {0};
    (void)memcpy_s(&param, sizeof(HITLS_APP_SM_Param), smParam, sizeof(HITLS_APP_SM_Param));
    param.uuid = uuid;
    int32_t ret = HITLS_APP_FindKey(provider, &param, CRYPT_PKEY_SM2, &keyInfo);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to find key, errCode: 0x%x\n", ret);
        return ret;
    }
    *ctx = keyInfo.pkeyCtx;
    return HITLS_APP_SUCCESS;
}
#endif

static CRYPT_EAL_PkeyCtx *LoadKeyFromFile(APP_CertConfig *certConfig, bool isSignKey)
{
    char *keyFile = isSignKey ? certConfig->tlcpSignKey : certConfig->tlcpEncKey;
    BSL_ParseFormat format = certConfig->keyFormat;
    const char *password = certConfig->keyPass;
    AppProvider *provider = certConfig->provider;

    if (keyFile == NULL) {
        return NULL;
    }
    
    CRYPT_EAL_PkeyCtx *pkey = NULL;
#ifdef HITLS_APP_SM_MODE
    if (isSignKey && certConfig->smParam->smTag == 1) {
        int32_t ret = GetPkeyCtxFromUuid(provider, certConfig->smParam, keyFile, &pkey);
        if (ret == HITLS_APP_SUCCESS) {
            return pkey;
        }
    }
#endif
    
    /* Load private key using the existing utility function */
    char *pass = NULL;
    if (password != NULL) {
        size_t len = strlen(password) + 1;
        pass = BSL_SAL_Malloc(len);
        if (pass != NULL) {
            strcpy_s(pass, len, password);
        }
    }

    pkey = HITLS_APP_ProviderLoadPrvKey(APP_GetCurrent_LibCtx(), provider->providerAttr, keyFile, format, &pass);
    if (pkey == NULL) {
        AppPrintError("Failed to load private key from %s\n", keyFile);
    }
    
    if (pass != NULL) {
        BSL_SAL_ClearFree(pass, strlen(pass));
    }
    
    return pkey;
}

int ConfCertVerification(HITLS_Config *config, APP_CertConfig *certConfig,
    bool verifyPeer, int verifyDepth)
{
    if (config == NULL) {
        return HITLS_APP_INVALID_ARG;
    }

    int ret = HITLS_SUCCESS;
    bool hasLoadedCA = false;

    /* Load CA certificates */
    if (certConfig && certConfig->caFile) {
        HITLS_X509_Cert *ca_cert = LoadCertFromFile(certConfig->caFile, certConfig->certFormat, certConfig->provider);
        if (ca_cert != NULL) {
            ret = HITLS_CFG_AddCertToStore(config, ca_cert, TLS_CERT_STORE_TYPE_DEFAULT, true);
            if (ret != HITLS_SUCCESS) {
                AppPrintError("Failed to add CA certificate to store: 0x%x\n", ret);
                HITLS_X509_CertFree(ca_cert);
                return HITLS_APP_ERR_LOAD_CA;
            }
            HITLS_X509_CertFree(ca_cert);
            hasLoadedCA = true;
        }
    }

    if (certConfig && certConfig->caChain) {
        HITLS_X509_List *certlist = NULL;
        ret = HITLS_X509_CertParseBundleFile(certConfig->certFormat, certConfig->caChain, &certlist);
        if (ret != BSL_SUCCESS) {
            AppPrintError("Failed to parse certificate <%s>, errCode = %d.\n", certConfig->caChain, ret);
            return HITLS_APP_X509_FAIL;
        }
        HITLS_X509_Cert **cert = BSL_LIST_First(certlist);
        while (cert != NULL) {
            ret = HITLS_CFG_AddCertToStore(config, *cert, TLS_CERT_STORE_TYPE_DEFAULT, true);
            if (ret != HITLS_SUCCESS) {
                AppPrintError("Failed to add CA-chain certificate to store: 0x%x\n", ret);
                ret = HITLS_APP_ERR_LOAD_CA;
                break;
            }
            cert = BSL_LIST_Next(certlist);
        }

        BSL_LIST_FREE(certlist, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        hasLoadedCA = true;
    }

    /* If no CA certificate is configured, load default CA path */
    if (!hasLoadedCA) {
        ret = HITLS_CFG_LoadDefaultCAPath(config);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to load default CA path: 0x%x\n", ret);
            // Don't return error, just log warning - allow to continue without CA if needed
        }
    }

    ret = HITLS_CFG_SetVerifyNoneSupport(config, !verifyPeer);
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to disable server verification: 0x%x\n", ret);
        return HITLS_APP_ERR_SET_VERIFY;
    }
    ret = HITLS_CFG_SetClientVerifySupport(config, verifyPeer);
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to set client verification: 0x%x\n", ret);
        return HITLS_APP_ERR_SET_VERIFY;
    }

    /* Set verification depth */
    if (verifyDepth > 0) {
        ret = HITLS_CFG_SetVerifyDepth(config, verifyDepth);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to set verification depth: 0x%x\n", ret);
            return HITLS_APP_ERR_SET_VERIFY;
        }
    }

    return HITLS_APP_SUCCESS;
}

int ConfigureTLCPCertificates(HITLS_Config *config, APP_CertConfig *certConfig)
{
    if (config == NULL || certConfig == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    int ret = HITLS_SUCCESS;
    
    /* Configure signature certificate */
    if (certConfig->tlcpSignCert && certConfig->tlcpSignKey) {
        HITLS_X509_Cert *sign_cert = LoadCertFromFile(certConfig->tlcpSignCert, certConfig->certFormat,
            certConfig->provider);
        CRYPT_EAL_PkeyCtx *sign_key = LoadKeyFromFile(certConfig, true);
        
        if (sign_cert && sign_key) {
            ret = HITLS_CFG_SetTlcpCertificate(config, sign_cert, false, false); /* Signature cert */
            if (ret != HITLS_SUCCESS) {
                HITLS_X509_CertFree(sign_cert);
                CRYPT_EAL_PkeyFreeCtx(sign_key);
                AppPrintError("Failed to set TLCP signature certificate: 0x%x\n", ret);
                return HITLS_APP_ERR_SET_TLCP_CERT;
            }
            ret = HITLS_CFG_SetTlcpPrivateKey(config, sign_key, false, false);
            if (ret != HITLS_SUCCESS) {
                CRYPT_EAL_PkeyFreeCtx(sign_key);
                AppPrintError("Failed to set TLCP signature private key: 0x%x\n", ret);
                return HITLS_APP_ERR_SET_TLCP_CERT;
            }
        } else {
            HITLS_X509_CertFree(sign_cert);
            CRYPT_EAL_PkeyFreeCtx(sign_key);
            return HITLS_APP_ERR_SET_TLCP_CERT;
        }
    }
    
    /* Configure encryption certificate */
    if (certConfig->tlcpEncCert && certConfig->tlcpEncKey) {
        HITLS_X509_Cert *enc_cert = LoadCertFromFile(certConfig->tlcpEncCert, certConfig->certFormat,
            certConfig->provider);
        CRYPT_EAL_PkeyCtx *enc_key = LoadKeyFromFile(certConfig, false);
        
        if (enc_cert && enc_key) {
            ret = HITLS_CFG_SetTlcpCertificate(config, enc_cert, false, true); /* Encryption cert */
            if (ret != HITLS_SUCCESS) {
                HITLS_X509_CertFree(enc_cert);
                CRYPT_EAL_PkeyFreeCtx(enc_key);
                AppPrintError("Failed to set TLCP encryption certificate: 0x%x\n", ret);
                return HITLS_APP_ERR_SET_TLCP_CERT;
            }
            ret = HITLS_CFG_SetTlcpPrivateKey(config, enc_key, false, true);
            if (ret != HITLS_SUCCESS) {
                CRYPT_EAL_PkeyFreeCtx(enc_key);
                AppPrintError("Failed to set TLCP encryption private key: 0x%x\n", ret);
                return HITLS_APP_ERR_SET_TLCP_CERT;
            }
        } else {
            HITLS_X509_CertFree(enc_cert);
            CRYPT_EAL_PkeyFreeCtx(enc_key);
            return HITLS_APP_ERR_SET_TLCP_CERT;
        }
    }
    
    return HITLS_APP_SUCCESS;
}

int CreateTCPSocket(APP_NetworkAddr *addr, int timeout)
{
    if (addr == NULL || addr->host == NULL) {
        return -1;
    }
    
    int sockfd = BSL_SAL_Socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        AppPrintError("Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    /* Set socket timeout if specified */
    if (timeout > 0) {
        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        BSL_SAL_SetSockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        BSL_SAL_SetSockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    
    /* Connect to server */
    struct sockaddr_in serverAdd;
    memset_s(&serverAdd, sizeof(serverAdd), 0, sizeof(serverAdd));
    serverAdd.sin_family = AF_INET;
    serverAdd.sin_port = htons(addr->port);
    
    if (inet_pton(AF_INET, addr->host, &serverAdd.sin_addr) <= 0) {
        /* Try to resolve hostname */
        struct hostent *hostEntry = gethostbyname(addr->host);
        if (hostEntry == NULL) {
            AppPrintError("Failed to resolve hostname: %s\n", addr->host);
            BSL_SAL_SockClose(sockfd);
            return -1;
        }
        memcpy_s(&serverAdd.sin_addr, sizeof(serverAdd.sin_addr), hostEntry->h_addr_list[0], hostEntry->h_length);
    }
    
    if (BSL_SAL_SockConnect(sockfd, (BSL_SAL_SockAddr)&serverAdd, sizeof(serverAdd)) < 0) {
        AppPrintError("Failed to connect to %s:%d: %s\n", addr->host, addr->port, strerror(errno));
        BSL_SAL_SockClose(sockfd);
        return -1;
    }
    
    return sockfd;
}

int CreateUDPSocket(APP_NetworkAddr *addr, int timeout)
{
    (void)timeout; /* Suppress unused parameter warning */
    if (addr == NULL || addr->host == NULL) {
        return -1;
    }
    
    int sockfd = BSL_SAL_Socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        AppPrintError("Failed to create UDP socket: %s\n", strerror(errno));
        return -1;
    }
    
    /* Connect UDP socket to server */
    struct sockaddr_in serverAdd;
    memset_s(&serverAdd, sizeof(serverAdd), 0, sizeof(serverAdd));
    serverAdd.sin_family = AF_INET;
    serverAdd.sin_port = htons(addr->port);
    
    if (inet_pton(AF_INET, addr->host, &serverAdd.sin_addr) <= 0) {
        /* Try to resolve hostname */
        struct hostent *hostEntry = gethostbyname(addr->host);
        if (hostEntry == NULL) {
            AppPrintError("Failed to resolve hostname: %s\n", addr->host);
            BSL_SAL_SockClose(sockfd);
            return -1;
        }
        memcpy_s(&serverAdd.sin_addr, sizeof(serverAdd.sin_addr), hostEntry->h_addr_list[0], hostEntry->h_length);
    }
    
    if (BSL_SAL_SockConnect(sockfd, (BSL_SAL_SockAddr)&serverAdd, sizeof(serverAdd)) < 0) {
        AppPrintError("Failed to connect UDP socket to %s:%d: %s\n", addr->host, addr->port, strerror(errno));
        BSL_SAL_SockClose(sockfd);
        return -1;
    }
    
    return sockfd;
}

int CreateTCPListenSocket(APP_NetworkAddr *addr, int backlog)
{
    int sockfd = BSL_SAL_Socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        AppPrintError("Failed to create listen socket: %s\n", strerror(errno));
        return -1;
    }
    
    /* Set socket options */
    int opt = 1;
    BSL_SAL_SetSockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    /* Bind to address */
    struct sockaddr_in bindAddr;
    memset_s(&bindAddr, sizeof(bindAddr), 0, sizeof(bindAddr));
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(addr->port);
    
    if (addr->host && strcmp(addr->host, "0.0.0.0") != 0) {
        if (inet_pton(AF_INET, addr->host, &bindAddr.sin_addr) <= 0) {
            AppPrintError("Invalid bind address: %s\n", addr->host);
            BSL_SAL_SockClose(sockfd);
            return -1;
        }
    } else {
        bindAddr.sin_addr.s_addr = INADDR_ANY;
    }
    
    if (BSL_SAL_SockBind(sockfd, (BSL_SAL_SockAddr)&bindAddr, sizeof(bindAddr)) < 0) {
        AppPrintError("Failed to bind to %s:%d: %s\n",
                      addr->host ? addr->host : "0.0.0.0", addr->port, strerror(errno));
        BSL_SAL_SockClose(sockfd);
        return -1;
    }
    
    if (BSL_SAL_SockListen(sockfd, backlog) < 0) {
        AppPrintError("Failed to listen: %s\n", strerror(errno));
        BSL_SAL_SockClose(sockfd);
        return -1;
    }
    
    return sockfd;
}

int CreateUDPListenSocket(APP_NetworkAddr *addr, int timeout)
{
    int sockfd = BSL_SAL_Socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        AppPrintError("Failed to create UDP listen socket: %s\n", strerror(errno));
        return -1;
    }

    if (timeout > 0) {
        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        BSL_SAL_SetSockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        BSL_SAL_SetSockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    
    /* Bind to address */
    struct sockaddr_in bindAddr;
    memset_s(&bindAddr, sizeof(bindAddr), 0, sizeof(bindAddr));
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(addr->port);
    
    if (addr->host && strcmp(addr->host, "0.0.0.0") != 0) {
        if (inet_pton(AF_INET, addr->host, &bindAddr.sin_addr) <= 0) {
            AppPrintError("Invalid bind address: %s\n", addr->host);
            BSL_SAL_SockClose(sockfd);
            return -1;
        }
    } else {
        bindAddr.sin_addr.s_addr = INADDR_ANY;
    }
    
    if (BSL_SAL_SockBind(sockfd, (BSL_SAL_SockAddr)&bindAddr, sizeof(bindAddr)) < 0) {
        AppPrintError("Failed to bind UDP to %s:%d: %s\n",
                      addr->host ? addr->host : "0.0.0.0", addr->port, strerror(errno));
        BSL_SAL_SockClose(sockfd);
        return -1;
    }
    return sockfd;
}

int AcceptTCPConnection(int listenFd)
{
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    int flags = fcntl(listenFd, F_GETFL, 0);
    fcntl(listenFd, F_SETFL, flags | O_NONBLOCK);
    int clientFd = accept(listenFd, (struct sockaddr *)&clientAddr, &addrLen);
    if (clientFd < 0) {
        return -1;
    }
    
    /* Print client information */
    char clientIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, INET_ADDRSTRLEN);
    AppPrintInfo("Accepted connection from %s:%d\n", clientIp, ntohs(clientAddr.sin_port));
    
    return clientFd;
}

void PrintConnectionInfo(HITLS_Ctx *ctx, bool showState)
{
    if (ctx == NULL) {
        return;
    }
    
    /* Print protocol version */
    uint16_t version;
    if (HITLS_GetNegotiatedVersion(ctx, &version) == HITLS_SUCCESS) {
        AppPrintInfo("Protocol version: ");
        switch (version) {
            case HITLS_VERSION_TLS12:
                AppPrintInfo("TLSv1.2\n");
                break;
            case HITLS_VERSION_TLS13:
                AppPrintInfo("TLSv1.3\n");
                break;
            case HITLS_VERSION_DTLS12:
                AppPrintInfo("DTLSv1.2\n");
                break;
            case HITLS_VERSION_TLCP_DTLCP11:
                AppPrintInfo("TLCP v1.1\n");
                break;
            default:
                AppPrintInfo("Unknown (0x%04x)\n", version);
                break;
        }
    }
    
    /* Print cipher suite */
    const HITLS_Cipher *cipher = HITLS_GetCurrentCipher(ctx);
    if (cipher != NULL) {
        AppPrintError("Cipher: %p\n", (const void*)cipher);
    }
    
    if (showState) {
        PrintHandshakeState(ctx);
    }
}

void PrintHandshakeState(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    uint32_t state;
    if (HITLS_GetHandShakeState(ctx, &state) == HITLS_SUCCESS) {
        const char *stateStr = HITLS_GetStateString(state);
        AppPrintInfo("Handshake state: %s\n", stateStr ? stateStr : "Unknown");
    }
}

int ParseConnectString(const char *connectStr, APP_NetworkAddr *addr)
{
    if (connectStr == NULL || addr == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    size_t len = strlen(connectStr) + 1;
    char *strCopy = BSL_SAL_Malloc(len);
    if (strCopy == NULL) {
        AppPrintError("Failed to alloc memory.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    strcpy_s(strCopy, len, connectStr);
    
    char *colon_pos = strrchr(strCopy, ':');
    if (colon_pos == NULL) {
        /* No port specified, use default */
        addr->host = strCopy;
        addr->port = 443; /* Default HTTPS port */
        return HITLS_APP_SUCCESS;
    }
    
    *colon_pos = '\0';
    size_t host_len = strlen(strCopy) + 1;
    addr->host = BSL_SAL_Malloc(host_len);
    if (addr->host != NULL) {
        strcpy_s(addr->host, host_len, strCopy);
    }
    addr->port = atoi(colon_pos + 1);
    
    BSL_SAL_Free(strCopy);
    
    if (addr->port <= 0 || addr->port > 65535) {
        BSL_SAL_Free(addr->host);
        addr->host = NULL;
        return HITLS_APP_INVALID_ARG;
    }
    
    return HITLS_APP_SUCCESS;
}

#ifdef HITLS_APP_SM_MODE
int32_t GetHeartBeat(uint8_t *buffer, uint32_t *len)
{
    if (buffer == NULL || len == NULL || *len < APP_HEARTBEAT_LEN) {
        AppPrintError("Invalid buffer or length.\n");
        return HITLS_APP_INVALID_ARG;
    }

    int64_t time = 0;
    int ret = HITLS_APP_GetTime(&time);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to get time, errCode: 0x%x.\n", ret);
        return ret;
    }
    BSL_Uint64ToByte(time, (uint8_t *)&time);
    const char *heartBeat = HEARTBEAT_STR;
    (void)memcpy_s(buffer, APP_HEARTBEAT_LEN, heartBeat, strlen(heartBeat));
    (void)memcpy_s(buffer + strlen(heartBeat), APP_HEARTBEAT_LEN - strlen(heartBeat), &time, sizeof(time));
    *len = APP_HEARTBEAT_LEN;
    return HITLS_APP_SUCCESS;
}

int32_t ParseHeartBeat(uint8_t *buffer, uint32_t len)
{
    if (buffer == NULL || len != APP_HEARTBEAT_LEN) {
        AppPrintError("Invalid buffer or length.\n");
        return HITLS_APP_INVALID_ARG;
    }

    int ret = strncmp((const char *)buffer, HEARTBEAT_STR, strlen(HEARTBEAT_STR));
    if (ret != 0) {
        AppPrintError("Invalid heartbeat string.\n");
        return HITLS_APP_INVALID_ARG;
    }
    int64_t time = 0;
    (void)memcpy_s(&time, sizeof(time), buffer + strlen(HEARTBEAT_STR), sizeof(time));
    time = BSL_ByteToUint64((uint8_t *)&time);
    return HITLS_APP_SUCCESS;
}
#endif
