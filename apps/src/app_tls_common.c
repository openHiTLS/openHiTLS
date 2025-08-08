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

#include "app_tls_common.h"
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
#include "hitls_config.h"
#include "hitls_cert.h"
#include "hitls_pki_cert.h"
#include "hitls_type.h"
#include "hitls_session.h"
#include "hitls_cert_type.h"
#include "bsl_sal.h"
#include "bsl_err.h"

APP_ProtocolType ParseProtocolType(const char *protocol_str)
{
    if (protocol_str == NULL) {
        return APP_PROTOCOL_TLS;
    }
    
    if (strcmp(protocol_str, "tls12") == 0 || strcmp(protocol_str, "tls1.2") == 0) {
        return APP_PROTOCOL_TLS12;
    } else if (strcmp(protocol_str, "tls13") == 0 || strcmp(protocol_str, "tls1.3") == 0) {
        return APP_PROTOCOL_TLS13;
    } else if (strcmp(protocol_str, "dtls12") == 0 || strcmp(protocol_str, "dtls1.2") == 0) {
        return APP_PROTOCOL_DTLS12;
    } else if (strcmp(protocol_str, "tlcp") == 0) {
        return APP_PROTOCOL_TLCP;
    }
    
    return APP_PROTOCOL_TLS; /* Default fallback */
}

HITLS_Config *CreateProtocolConfig(APP_ProtocolType protocol)
{
    HITLS_Config *config = NULL;
    
    switch (protocol) {
        case APP_PROTOCOL_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            break;
        case APP_PROTOCOL_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            break;
        case APP_PROTOCOL_DTLS12:
            config = HITLS_CFG_NewDTLSConfig();
            break;
        case APP_PROTOCOL_TLCP:
            config = HITLS_CFG_NewTLCPConfig();
            break;
        case APP_PROTOCOL_TLS:
            config = HITLS_CFG_NewTLSConfig();
            break;
        default:
            AppPrintError("Unsupported protocol type: %d\n", protocol);
            return NULL;
    }
    
    if (config == NULL) {
        AppPrintError("Failed to create protocol configuration\n");
    }
    
    return config;
}

int ConfigureCipherSuites(HITLS_Config *config, const char *cipher_str, bool is_tls13)
{
    if (config == NULL || cipher_str == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    /* Parse cipher string and convert to cipher suite array */
    /* This is a simplified implementation - in practice, you'd need to parse 
       the cipher string and map to actual cipher suite IDs */
    
    /* For now, just set a common cipher suite based on protocol */
    uint16_t cipher_suites[] = {
        HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_RSA_WITH_AES_128_GCM_SHA256
    };
    
    int ret;
    if (is_tls13) {
        ret = HITLS_CFG_SetCipherSuites(config, cipher_suites, sizeof(cipher_suites) / sizeof(uint16_t));
    } else {
        ret = HITLS_CFG_SetCipherSuites(config, cipher_suites, sizeof(cipher_suites) / sizeof(uint16_t));
    }
    
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to set cipher suites: 0x%x\n", ret);
        return HITLS_APP_ERR_SET_CIPHER;
    }
    
    return HITLS_APP_SUCCESS;
}

int ConfigureSignatureAlgorithms(HITLS_Config *config, const char *sig_algs_str)
{
    if (config == NULL || sig_algs_str == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    /* Parse signature algorithms string and set */
    /* This is a simplified implementation */
    uint16_t sig_algs[] = {
        CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256,
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384,
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256,
        CERT_SIG_SCHEME_RSA_PKCS1_SHA384
    };
    
    int ret = HITLS_CFG_SetSignature(config, sig_algs, sizeof(sig_algs) / sizeof(uint16_t));
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to set signature algorithms: 0x%x\n", ret);
        return HITLS_APP_ERR_SET_SIGNATURE;
    }
    
    return HITLS_APP_SUCCESS;
}

int ConfigureCurves(HITLS_Config *config, const char *curves_str)
{
    if (config == NULL || curves_str == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    /* Parse curves string and set */
    /* This is a simplified implementation */
    uint16_t curves[] = {
        HITLS_EC_GROUP_SECP256R1,
        HITLS_EC_GROUP_SECP384R1,
        HITLS_EC_GROUP_SECP521R1
    };
    
    int ret = HITLS_CFG_SetGroups(config, curves, sizeof(curves) / sizeof(uint16_t));
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to set curves: 0x%x\n", ret);
        return HITLS_APP_ERR_SET_GROUPS;
    }
    
    return HITLS_APP_SUCCESS;
}

HITLS_X509_Cert *LoadCertFromFile(const char *cert_file, BSL_ParseFormat format)
{
    if (cert_file == NULL) {
        return NULL;
    }
    
    HITLS_X509_Cert *cert = NULL;
    int ret = HITLS_X509_CertParseFile(format, cert_file, &cert);
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to load certificate from %s: 0x%x\n", cert_file, ret);
        return NULL;
    }
    
    return cert;
}

CRYPT_EAL_PkeyCtx *LoadKeyFromFile(const char *key_file, BSL_ParseFormat format, const char *password)
{
    if (key_file == NULL) {
        return NULL;
    }
    
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    
    /* Load private key using the existing utility function */
    char *pass = NULL;
    if (password != NULL) {
        size_t len = strlen(password) + 1;
        pass = BSL_SAL_Malloc(len);
        if (pass != NULL) {
            strcpy(pass, password);
        }
    }
    
    pkey = HITLS_APP_LoadPrvKey(key_file, format, &pass);
    if (pkey == NULL) {
        AppPrintError("Failed to load private key from %s\n", key_file);
    }
    
    if (pass != NULL) {
        BSL_SAL_Free(pass);
    }
    
    return pkey;
}

int ConfigureCertificateVerification(HITLS_Config *config, APP_CertConfig *cert_config, 
                                   bool is_client, bool verify_peer, int verify_depth)
{
    if (config == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    int ret = HITLS_SUCCESS;
    
    /* Load CA certificates */
    if (cert_config && cert_config->ca_file) {
        HITLS_X509_Cert *ca_cert = LoadCertFromFile(cert_config->ca_file, cert_config->cert_format);
        if (ca_cert != NULL) {
            ret = HITLS_CFG_AddCertToStore(config, ca_cert, TLS_CERT_STORE_TYPE_DEFAULT, true);
            if (ret != HITLS_SUCCESS) {
                AppPrintError("Failed to add CA certificate to store: 0x%x\n", ret);
                HITLS_X509_CertFree(ca_cert);
                return HITLS_APP_ERR_LOAD_CA;
            }
            HITLS_X509_CertFree(ca_cert);
        }
    }
    
    /* Configure verification behavior */
    if (is_client) {
        /* Client: verify server certificate by default */
        if (!verify_peer) {
            ret = HITLS_CFG_SetVerifyNoneSupport(config, true);
            if (ret != HITLS_SUCCESS) {
                AppPrintError("Failed to disable server verification: 0x%x\n", ret);
                return HITLS_APP_ERR_SET_VERIFY;
            }
        }
    } else {
        /* Server: configure client certificate verification */
        ret = HITLS_CFG_SetClientVerifySupport(config, verify_peer);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to set client verification: 0x%x\n", ret);
            return HITLS_APP_ERR_SET_VERIFY;
        }
    }
    
    /* Set verification depth */
    if (verify_depth > 0) {
        ret = HITLS_CFG_SetVerifyDepth(config, verify_depth);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to set verification depth: 0x%x\n", ret);
            return HITLS_APP_ERR_SET_VERIFY;
        }
    }
    
    return HITLS_APP_SUCCESS;
}

int ConfigureCertificate(HITLS_Config *config, APP_CertConfig *cert_config, bool is_client)
{
    (void)is_client; /* Suppress unused parameter warning */
    if (config == NULL || cert_config == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    if (cert_config->cert_file == NULL || cert_config->key_file == NULL) {
        return HITLS_APP_SUCCESS; /* No certificate to configure */
    }
    
    /* Load certificate */
    HITLS_X509_Cert *cert = LoadCertFromFile(cert_config->cert_file, cert_config->cert_format);
    if (cert == NULL) {
        return HITLS_APP_ERR_LOAD_CERT;
    }
    
    /* Load private key */
    CRYPT_EAL_PkeyCtx *pkey = LoadKeyFromFile(cert_config->key_file, cert_config->key_format, cert_config->key_pass);
    if (pkey == NULL) {
        HITLS_X509_CertFree(cert);
        return HITLS_APP_ERR_LOAD_KEY;
    }
    
    /* Set certificate and key */
    int ret = HITLS_CFG_SetCertificate(config, cert, true);
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to set certificate: 0x%x\n", ret);
        HITLS_X509_CertFree(cert);
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return HITLS_APP_ERR_SET_CERT;
    }
    
    ret = HITLS_CFG_SetPrivateKey(config, pkey, true);
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to set private key: 0x%x\n", ret);
        HITLS_X509_CertFree(cert);
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return HITLS_APP_ERR_SET_KEY;
    }
    
    HITLS_X509_CertFree(cert);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    
    return HITLS_APP_SUCCESS;
}

int ConfigureTLCPCertificates(HITLS_Config *config, APP_CertConfig *cert_config, bool is_client)
{
    if (config == NULL || cert_config == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    int ret = HITLS_SUCCESS;
    
    /* Configure signature certificate */
    if (cert_config->tlcp_sign_cert && cert_config->tlcp_sign_key) {
        HITLS_X509_Cert *sign_cert = LoadCertFromFile(cert_config->tlcp_sign_cert, cert_config->cert_format);
        CRYPT_EAL_PkeyCtx *sign_key = LoadKeyFromFile(cert_config->tlcp_sign_key, cert_config->key_format, cert_config->key_pass);
        
        if (sign_cert && sign_key) {
            ret = HITLS_CFG_SetTlcpCertificate(config, sign_cert, is_client, false); /* Signature cert */
            if (ret == HITLS_SUCCESS) {
                ret = HITLS_CFG_SetTlcpPrivateKey(config, sign_key, is_client, false);
            }
            
            if (ret != HITLS_SUCCESS) {
                AppPrintError("Failed to set TLCP signature certificate: 0x%x\n", ret);
            }
        }
        
        if (sign_cert) HITLS_X509_CertFree(sign_cert);
        if (sign_key) CRYPT_EAL_PkeyFreeCtx(sign_key);
        
        if (ret != HITLS_SUCCESS) {
            return HITLS_APP_ERR_SET_TLCP_CERT;
        }
    }
    
    /* Configure encryption certificate */
    if (cert_config->tlcp_enc_cert && cert_config->tlcp_enc_key) {
        HITLS_X509_Cert *enc_cert = LoadCertFromFile(cert_config->tlcp_enc_cert, cert_config->cert_format);
        CRYPT_EAL_PkeyCtx *enc_key = LoadKeyFromFile(cert_config->tlcp_enc_key, cert_config->key_format, cert_config->key_pass);
        
        if (enc_cert && enc_key) {
            ret = HITLS_CFG_SetTlcpCertificate(config, enc_cert, is_client, true); /* Encryption cert */
            if (ret == HITLS_SUCCESS) {
                ret = HITLS_CFG_SetTlcpPrivateKey(config, enc_key, is_client, true);
            }
            
            if (ret != HITLS_SUCCESS) {
                AppPrintError("Failed to set TLCP encryption certificate: 0x%x\n", ret);
            }
        }
        
        if (enc_cert) HITLS_X509_CertFree(enc_cert);
        if (enc_key) CRYPT_EAL_PkeyFreeCtx(enc_key);
        
        if (ret != HITLS_SUCCESS) {
            return HITLS_APP_ERR_SET_TLCP_CERT;
        }
    }
    
    return HITLS_APP_SUCCESS;
}

int ConfigureDTLSOptions(HITLS_Config *config, int mtu, bool cookie_exchange)
{
    if (config == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    int ret = HITLS_SUCCESS;
    
    /* Set MTU if specified (Note: MTU should be set on HITLS_Ctx, not config) */
    if (mtu > 0) {
        /* MTU will be set later on the context using HITLS_SetMtu() */
        AppPrintInfo("MTU %d will be set on TLS context\n", mtu);
    }
    
    /* Set cookie exchange */
    ret = HITLS_CFG_SetDtlsCookieExchangeSupport(config, cookie_exchange);
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to set cookie exchange: 0x%x\n", ret);
        return HITLS_APP_ERR_SET_COOKIE;
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
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(addr->port);
    
    if (inet_pton(AF_INET, addr->host, &server_addr.sin_addr) <= 0) {
        /* Try to resolve hostname */
        struct hostent *host_entry = gethostbyname(addr->host);
        if (host_entry == NULL) {
            AppPrintError("Failed to resolve hostname: %s\n", addr->host);
            BSL_SAL_SockClose(sockfd);
            return -1;
        }
        memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
    }
    
    if (BSL_SAL_SockConnect(sockfd, (BSL_SAL_SockAddr)&server_addr, sizeof(server_addr)) < 0) {
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
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(addr->port);
    
    if (inet_pton(AF_INET, addr->host, &server_addr.sin_addr) <= 0) {
        /* Try to resolve hostname */
        struct hostent *host_entry = gethostbyname(addr->host);
        if (host_entry == NULL) {
            AppPrintError("Failed to resolve hostname: %s\n", addr->host);
            BSL_SAL_SockClose(sockfd);
            return -1;
        }
        memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
    }
    
    if (BSL_SAL_SockConnect(sockfd, (BSL_SAL_SockAddr)&server_addr, sizeof(server_addr)) < 0) {
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
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(addr->port);
    
    if (addr->host && strcmp(addr->host, "0.0.0.0") != 0) {
        if (inet_pton(AF_INET, addr->host, &bind_addr.sin_addr) <= 0) {
            AppPrintError("Invalid bind address: %s\n", addr->host);
            BSL_SAL_SockClose(sockfd);
            return -1;
        }
    } else {
        bind_addr.sin_addr.s_addr = INADDR_ANY;
    }
    
    if (BSL_SAL_SockBind(sockfd, (BSL_SAL_SockAddr)&bind_addr, sizeof(bind_addr)) < 0) {
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

int CreateUDPListenSocket(APP_NetworkAddr *addr)
{
    int sockfd = BSL_SAL_Socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        AppPrintError("Failed to create UDP listen socket: %s\n", strerror(errno));
        return -1;
    }
    
    /* Bind to address */
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(addr->port);
    
    if (addr->host && strcmp(addr->host, "0.0.0.0") != 0) {
        if (inet_pton(AF_INET, addr->host, &bind_addr.sin_addr) <= 0) {
            AppPrintError("Invalid bind address: %s\n", addr->host);
            BSL_SAL_SockClose(sockfd);
            return -1;
        }
    } else {
        bind_addr.sin_addr.s_addr = INADDR_ANY;
    }
    
    if (BSL_SAL_SockBind(sockfd, (BSL_SAL_SockAddr)&bind_addr, sizeof(bind_addr)) < 0) {
        AppPrintError("Failed to bind UDP to %s:%d: %s\n", 
                     addr->host ? addr->host : "0.0.0.0", addr->port, strerror(errno));
        BSL_SAL_SockClose(sockfd);
        return -1;
    }
    
    return sockfd;
}

int AcceptTCPConnection(int listen_fd)
{
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
        AppPrintError("Failed to accept connection: %s\n", strerror(errno));
        return -1;
    }
    
    /* Print client information */
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    AppPrintInfo("Accepted connection from %s:%d\n", client_ip, ntohs(client_addr.sin_port));
    
    return client_fd;
}

void PrintConnectionInfo(HITLS_Ctx *ctx, bool show_certs, bool show_state)
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
        AppPrintInfo("Cipher: %p\n", (const void*)cipher);
    }
    
    if (show_certs) {
        PrintCertificateChain(ctx);
    }
    
    if (show_state) {
        PrintHandshakeState(ctx);
    }
}

void PrintCertificateInfo(HITLS_X509_Cert *cert, const char *label)
{
    if (cert == NULL) {
        return;
    }
    
    AppPrintInfo("--- %s ---\n", label ? label : "Certificate");
    
    /* Certificate details would require more complex implementation */
    AppPrintInfo("Certificate: %p\n", (void*)cert);
    
    AppPrintInfo("--- End Certificate ---\n");
}

void PrintCertificateChain(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    AppPrintInfo("Certificate chain\n");
    
    /* This is a simplified implementation - in practice, you'd iterate through the certificate chain */
    HITLS_X509_Cert *peer_cert = HITLS_GetPeerCertificate(ctx);
    if (peer_cert != NULL) {
        PrintCertificateInfo(peer_cert, "Peer Certificate");
        HITLS_X509_CertFree(peer_cert);
    }
}

void PrintHandshakeState(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    uint32_t state;
    if (HITLS_GetHandShakeState(ctx, &state) == HITLS_SUCCESS) {
        const char *state_str = HITLS_GetStateString(state);
        AppPrintInfo("Handshake state: %s\n", state_str ? state_str : "Unknown");
    }
}

int ParseConnectString(const char *connect_str, APP_NetworkAddr *addr)
{
    if (connect_str == NULL || addr == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    size_t len = strlen(connect_str) + 1;
    char *str_copy = BSL_SAL_Malloc(len);
    if (str_copy == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    strcpy(str_copy, connect_str);
    
    char *colon_pos = strrchr(str_copy, ':');
    if (colon_pos == NULL) {
        /* No port specified, use default */
        addr->host = str_copy;
        addr->port = 443; /* Default HTTPS port */
        return HITLS_APP_SUCCESS;
    }
    
    *colon_pos = '\0';
    size_t host_len = strlen(str_copy) + 1;
    addr->host = BSL_SAL_Malloc(host_len);
    if (addr->host != NULL) {
        strcpy(addr->host, str_copy);
    }
    addr->port = atoi(colon_pos + 1);
    
    BSL_SAL_Free(str_copy);
    
    if (addr->port <= 0 || addr->port > 65535) {
        BSL_SAL_Free(addr->host);
        addr->host = NULL;
        return HITLS_APP_INVALID_ARG;
    }
    
    return HITLS_APP_SUCCESS;
}

int ResolveHostname(const char *hostname, char *ip_addr, size_t addr_len, bool prefer_ipv6)
{
    if (hostname == NULL || ip_addr == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = prefer_ipv6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    int ret = getaddrinfo(hostname, NULL, &hints, &result);
    if (ret != 0) {
        AppPrintError("Failed to resolve hostname %s: %s\n", hostname, gai_strerror(ret));
        return HITLS_APP_ERR_RESOLVE_HOST;
    }
    
    if (result->ai_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)result->ai_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_addr, addr_len);
    } else if (result->ai_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)result->ai_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_addr, addr_len);
    } else {
        freeaddrinfo(result);
        return HITLS_APP_ERR_RESOLVE_HOST;
    }
    
    freeaddrinfo(result);
    return HITLS_APP_SUCCESS;
}