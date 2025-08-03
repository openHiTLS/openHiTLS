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

#ifndef APP_SERVER_H
#define APP_SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_types.h"
#include "bsl_uio.h"
#include "hitls_config.h"
#include "hitls_pki_cert.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Server option types */
typedef enum {
    HITLS_SERVER_OPT_ACCEPT = 200,
    HITLS_SERVER_OPT_PORT,
    HITLS_SERVER_OPT_IPV4,
    HITLS_SERVER_OPT_IPV6,
    HITLS_SERVER_OPT_BIND,
    
    /* Protocol options */
    HITLS_SERVER_OPT_TLS12,
    HITLS_SERVER_OPT_TLS13,
    HITLS_SERVER_OPT_DTLS12,
    HITLS_SERVER_OPT_TLCP,
    HITLS_SERVER_OPT_CIPHER,
    HITLS_SERVER_OPT_TLS13_CIPHER,
    HITLS_SERVER_OPT_SIGALGS,
    HITLS_SERVER_OPT_CURVES,
    HITLS_SERVER_OPT_CIPHER_SERVER_PREFERENCE,
    
    /* Certificate options */
    HITLS_SERVER_OPT_CERT,
    HITLS_SERVER_OPT_KEY,
    HITLS_SERVER_OPT_PASS,
    HITLS_SERVER_OPT_CAFILE,
    HITLS_SERVER_OPT_CAPATH,
    HITLS_SERVER_OPT_VERIFY,
    HITLS_SERVER_OPT_VERIFY_FORCE,
    HITLS_SERVER_OPT_VERIFY_ONCE,
    
    /* TLCP options */
    HITLS_SERVER_OPT_TLCP_ENC_CERT,
    HITLS_SERVER_OPT_TLCP_ENC_KEY,
    HITLS_SERVER_OPT_TLCP_SIGN_CERT,
    HITLS_SERVER_OPT_TLCP_SIGN_KEY,
    
    /* DTLS options */
    HITLS_SERVER_OPT_MTU,
    HITLS_SERVER_OPT_COOKIE_EXCHANGE,
    
    /* Session options */
    HITLS_SERVER_OPT_SESSION_CACHE_FILE,
    HITLS_SERVER_OPT_NO_SESSION_CACHE,
    HITLS_SERVER_OPT_SESSION_TIMEOUT,
    
    /* Service options */
    HITLS_SERVER_OPT_DAEMON,
    HITLS_SERVER_OPT_ACCEPT_ONCE,
    HITLS_SERVER_OPT_NACCEPT,
    
    /* Output options */
    HITLS_SERVER_OPT_QUIET,
    HITLS_SERVER_OPT_DEBUG,
    HITLS_SERVER_OPT_STATE,
    HITLS_SERVER_OPT_SHOWCERTS,
    HITLS_SERVER_OPT_MSG,
    
    /* Format options */
    HITLS_SERVER_OPT_CERTFORM,
    HITLS_SERVER_OPT_KEYFORM,
    
    HITLS_SERVER_OPT_MAX
} HITLS_ServerOptType;

/* Server parameters structure */
typedef struct {
    /* Listen parameters */
    char *bind_addr;
    int port;
    int backlog;
    bool ipv4;
    bool ipv6;
    
    /* Protocol parameters */
    char *protocol;
    char *cipher_suites;
    char *tls13_cipher_suites;
    char *sig_algs;
    char *curves;
    bool cipher_server_preference;
    
    /* Certificate parameters */
    char *cert_file;
    char *key_file;
    char *key_pass;
    char *ca_file;
    char *ca_dir;
    bool verify_client;
    bool verify_client_force;
    bool verify_client_once;
    int verify_depth;
    
    /* TLCP parameters */
    char *tlcp_enc_cert;
    char *tlcp_enc_key;
    char *tlcp_sign_cert;
    char *tlcp_sign_key;
    
    /* DTLS parameters */
    int mtu;
    bool cookie_exchange;
    
    /* Session parameters */
    char *session_cache_file;
    bool no_session_cache;
    int session_timeout;
    
    /* Service parameters */
    bool daemon;
    bool accept_once;
    int max_connections;
    
    /* Output parameters */
    bool quiet;
    bool debug;
    bool state;
    bool showcerts;
    char *msg;
    
    /* Format parameters */
    BSL_ParseFormat cert_format;
    BSL_ParseFormat key_format;
    
} HITLS_ServerParams;

/**
 * @brief Main entry point for s_server tool
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return Application exit code
 */
int HITLS_ServerMain(int argc, char *argv[]);

/**
 * @brief Parse server command line options
 * @param argc Number of arguments
 * @param argv Argument array
 * @param params Output parameters structure
 * @return Success or error code
 */
int ParseServerOptions(int argc, char *argv[], HITLS_ServerParams *params);

/**
 * @brief Create server TLS/DTLS configuration
 * @param params Server parameters
 * @return HITLS configuration or NULL on error
 */
HITLS_Config *CreateServerConfig(HITLS_ServerParams *params);

/**
 * @brief Create listening socket
 * @param params Server parameters
 * @return Socket file descriptor or -1 on error
 */
int CreateListenSocket(HITLS_ServerParams *params);

/**
 * @brief Server main loop to handle connections
 * @param config TLS configuration
 * @param listen_fd Listening socket
 * @param params Server parameters
 * @return Success or error code
 */
int ServerMainLoop(HITLS_Config *config, int listen_fd, HITLS_ServerParams *params);

/**
 * @brief Handle individual client connection
 * @param ctx TLS context
 * @param params Server parameters
 * @return Success or error code
 */
int HandleClientConnection(HITLS_Ctx *ctx, HITLS_ServerParams *params);

/**
 * @brief Clean up server resources
 * @param config TLS configuration
 * @param listen_fd Listening socket
 * @param params Server parameters
 */
void CleanupServerResources(HITLS_Config *config, int listen_fd, HITLS_ServerParams *params);

#ifdef __cplusplus
}
#endif

#endif /* APP_SERVER_H */