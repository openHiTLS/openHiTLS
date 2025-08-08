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

#ifndef APP_TLS_COMMON_H
#define APP_TLS_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_types.h"
#include "bsl_uio.h"
#include "hitls_config.h"
#include "hitls_pki_cert.h"
#include "hitls.h"
#include "hitls_cert.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol types */
typedef enum {
    APP_PROTOCOL_TLS,
    APP_PROTOCOL_TLS12,
    APP_PROTOCOL_TLS13,
    APP_PROTOCOL_DTLS12,
    APP_PROTOCOL_TLCP
} APP_ProtocolType;

/* Network address structure */
typedef struct {
    char *host;
    int port;
    bool ipv4;
    bool ipv6;
} APP_NetworkAddr;

/* Certificate configuration structure */
typedef struct {
    char *cert_file;
    char *key_file;
    char *key_pass;
    char *ca_file;
    char *ca_dir;
    BSL_ParseFormat cert_format;
    BSL_ParseFormat key_format;
    
    /* TLCP specific certificates */
    char *tlcp_enc_cert;
    char *tlcp_enc_key;
    char *tlcp_sign_cert;
    char *tlcp_sign_key;
} APP_CertConfig;

/**
 * @brief Parse protocol type from string
 * @param protocol_str Protocol string (tls12, tls13, dtls12, tlcp)
 * @return Protocol type or -1 on error
 */
APP_ProtocolType ParseProtocolType(const char *protocol_str);

/**
 * @brief Create TLS configuration based on protocol type
 * @param protocol Protocol type
 * @return HITLS configuration or NULL on error
 */
HITLS_Config *CreateProtocolConfig(APP_ProtocolType protocol);

/**
 * @brief Configure cipher suites
 * @param config TLS configuration
 * @param cipher_str Cipher suite string
 * @param is_tls13 Whether it's TLS1.3 cipher suites
 * @return Success or error code
 */
int ConfigureCipherSuites(HITLS_Config *config, const char *cipher_str, bool is_tls13);

/**
 * @brief Configure signature algorithms
 * @param config TLS configuration
 * @param sig_algs_str Signature algorithms string
 * @return Success or error code
 */
int ConfigureSignatureAlgorithms(HITLS_Config *config, const char *sig_algs_str);

/**
 * @brief Configure supported curves
 * @param config TLS configuration
 * @param curves_str Curves string
 * @return Success or error code
 */
int ConfigureCurves(HITLS_Config *config, const char *curves_str);

/**
 * @brief Load certificate from file
 * @param cert_file Certificate file path
 * @param format Certificate format
 * @return Certificate object or NULL on error
 */
HITLS_X509_Cert *LoadCertFromFile(const char *cert_file, BSL_ParseFormat format);

/**
 * @brief Load private key from file
 * @param key_file Private key file path
 * @param format Key format
 * @param password Key password (can be NULL)
 * @return Private key object or NULL on error
 */
CRYPT_EAL_PkeyCtx *LoadKeyFromFile(const char *key_file, BSL_ParseFormat format, const char *password);

/**
 * @brief Configure certificate verification
 * @param config TLS configuration
 * @param cert_config Certificate configuration
 * @param is_client Whether it's client configuration
 * @param verify_peer Whether to verify peer certificate
 * @param verify_depth Certificate chain verification depth
 * @return Success or error code
 */
int ConfigureCertificateVerification(HITLS_Config *config, APP_CertConfig *cert_config, 
                                   bool is_client, bool verify_peer, int verify_depth);

/**
 * @brief Configure client/server certificate
 * @param config TLS configuration
 * @param cert_config Certificate configuration
 * @param is_client Whether it's client configuration
 * @return Success or error code
 */
int ConfigureCertificate(HITLS_Config *config, APP_CertConfig *cert_config, bool is_client);

/**
 * @brief Configure TLCP certificates (dual certificates)
 * @param config TLS configuration
 * @param cert_config Certificate configuration
 * @param is_client Whether it's client configuration
 * @return Success or error code
 */
int ConfigureTLCPCertificates(HITLS_Config *config, APP_CertConfig *cert_config, bool is_client);

/**
 * @brief Configure DTLS specific options
 * @param config TLS configuration
 * @param mtu MTU size
 * @param cookie_exchange Whether to enable cookie exchange
 * @return Success or error code
 */
int ConfigureDTLSOptions(HITLS_Config *config, int mtu, bool cookie_exchange);

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
int CreateUDPListenSocket(APP_NetworkAddr *addr);

/**
 * @brief Accept TCP connection
 * @param listen_fd Listening socket
 * @return Client socket file descriptor or -1 on error
 */
int AcceptTCPConnection(int listen_fd);

/**
 * @brief Print TLS connection information
 * @param ctx TLS context
 * @param show_certs Whether to show certificates
 * @param show_state Whether to show handshake state
 */
void PrintConnectionInfo(HITLS_Ctx *ctx, bool show_certs, bool show_state);

/**
 * @brief Print certificate information
 * @param cert Certificate object
 * @param label Certificate label
 */
void PrintCertificateInfo(HITLS_X509_Cert *cert, const char *label);

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
 * @param connect_str Connection string in format "host:port"
 * @param addr Output network address
 * @return Success or error code
 */
int ParseConnectString(const char *connect_str, APP_NetworkAddr *addr);

/**
 * @brief Resolve hostname to IP address
 * @param hostname Hostname to resolve
 * @param ip_addr Output IP address buffer
 * @param addr_len IP address buffer length
 * @param prefer_ipv6 Whether to prefer IPv6
 * @return Success or error code
 */
int ResolveHostname(const char *hostname, char *ip_addr, size_t addr_len, bool prefer_ipv6);

#ifdef __cplusplus
}
#endif

#endif /* APP_TLS_COMMON_H */