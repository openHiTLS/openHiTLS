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

#ifndef HITLS_APP_TLS_COMMON_H
#define HITLS_APP_TLS_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_types.h"
#include "bsl_uio.h"
#include "hitls_config.h"
#include "hitls_pki_cert.h"
#include "hitls.h"
#include "hitls_cert.h"
#include "crypt_eal_pkey.h"
#include "app_provider.h"
#include "app_sm.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APP_HEARTBEAT_LEN 17
#define DEFAULT_DTLCP_PORT 54000
#define HTTP_BUF_MAXLEN (18 * 1024) /* 18KB */

/* Protocol types */
typedef enum {
    APP_PROTOCOL_TLS,      // International standard TLS protocol (default)
    APP_PROTOCOL_TLCP,
    APP_PROTOCOL_DTLCP,
} APP_ProtocolType;

/* Network address structure */
typedef struct {
    char *host;
    int port;
} APP_NetworkAddr;

/* Certificate configuration structure */
typedef struct {
    char *keyPass;
    char *caFile;
    char *caChain;
    BSL_ParseFormat certFormat;
    BSL_ParseFormat keyFormat;
    
    /* TLCP specific certificates */
    char *tlcpEncCert;
    char *tlcpEncKey;
    char *tlcpSignCert;
    char *tlcpSignKey;
    AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} APP_CertConfig;

/**
 * @brief Parse protocol type from string
 * @param protocolStr Protocol string (tls12, tls13, dtls12, tlcp)
 * @return Protocol type or -1 on error
 */
APP_ProtocolType ParseProtocolType(const char *protocolStr);

/**
 * @brief Create TLS configuration based on protocol type
 * @param protocol Protocol type
 * @return HITLS configuration or NULL on error
 */
HITLS_Config *CreateProtocolConfig(APP_ProtocolType protocol, AppProvider *provider);

/**
 * @brief Configure cipher suites
 * @param config TLS configuration
 * @param cipherStr Cipher suite string
 * @param is_tls13 Whether it's TLS1.3 cipher suites
 * @return Success or error code
 */
int ConfigureCipherSuites(HITLS_Config *config, const char *cipherStr, APP_ProtocolType protocol);

/**
 * @brief Load certificate from file
 * @param certFile Certificate file path
 * @param format Certificate format
 * @param provider Provider configuration
 * @return Certificate object or NULL on error
 */
HITLS_X509_Cert *LoadCertFromFile(const char *certFile, BSL_ParseFormat format, AppProvider *provider);

/**
 * @brief Configure certificate verification
 * @param config TLS configuration
 * @param certConfig Certificate configuration
 * @param  isClient Whether it's client configuration
 * @param verifyPeer Whether to verify peer certificate
 * @param verifyDepth Certificate chain verification depth
 * @return Success or error code
 */
int ConfCertVerification(HITLS_Config *config, APP_CertConfig *certConfig,
    bool verifyPeer, int verifyDepth);

/**
 * @brief Configure TLCP certificates (dual certificates)
 * @param config TLS configuration
 * @param certConfig Certificate configuration
 * @param  isClient Whether it's client configuration
 * @return Success or error code
 */
int ConfigureTLCPCertificates(HITLS_Config *config, APP_CertConfig *certConfig);

/**
 * @brief Create TCP socket and connect to server
 * @param addr Network address
 * @param timeout Connection timeout in seconds
 * @return Socket file descriptor or -1 on error
 */
int CreateTCPSocket(APP_NetworkAddr *addr, int timeout);

/**
 * @brief Create UDP socket and connect to server
 * @param addr Network address
 * @param timeout Connection timeout in seconds
 * @return Socket file descriptor or -1 on error
 */
int CreateUDPSocket(APP_NetworkAddr *addr, int timeout);

/**
 * @brief Create TCP listening socket
 * @param addr Network address
 * @param backlog Listen backlog
 * @return Socket file descriptor or -1 on error
 */
int CreateTCPListenSocket(APP_NetworkAddr *addr, int backlog);

/**
 * @brief Create UDP listening socket
 * @param addr Network address
 * @return Socket file descriptor or -1 on error
 */
int CreateUDPListenSocket(APP_NetworkAddr *addr, int timeout);

/**
 * @brief Accept TCP connection
 * @param listenFd Listening socket
 * @return Client socket file descriptor or -1 on error
 */
int AcceptTCPConnection(int listenFd);

/**
 * @brief Print TLS connection information
 * @param ctx TLS context
 * @param showState Whether to show handshake state
 */
void PrintConnectionInfo(HITLS_Ctx *ctx, bool showState);

/**
 * @brief Print certificate chain
 * @param ctx TLS context
 */
void PrintCertificateChain(HITLS_Ctx *ctx);

/**
 * @brief Print handshake state
 * @param ctx TLS context
 */
void PrintHandshakeState(HITLS_Ctx *ctx);

/**
 * @brief Parse host:port string
 * @param connectStr Connection string in format "host:port"
 * @param addr Output network address
 * @return Success or error code
 */
int ParseConnectString(const char *connectStr, APP_NetworkAddr *addr);

int32_t GetHeartBeat(uint8_t *buffer, uint32_t *len);

int32_t ParseHeartBeat(uint8_t *buffer, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_APP_TLS_COMMON_H */