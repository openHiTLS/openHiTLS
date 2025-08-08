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

#ifndef APP_CLIENT_H
#define APP_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_types.h"
#include "bsl_uio.h"
#include "hitls_config.h"
#include "hitls_pki_cert.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Client option types */
typedef enum {
    HITLS_CLIENT_OPT_HOST = 100,
    HITLS_CLIENT_OPT_PORT,
    HITLS_CLIENT_OPT_CONNECT,
    HITLS_CLIENT_OPT_IPV4,
    HITLS_CLIENT_OPT_IPV6,
    HITLS_CLIENT_OPT_TIMEOUT,
    
    /* Protocol options */
    HITLS_CLIENT_OPT_TLS12,
    HITLS_CLIENT_OPT_TLS13,
    HITLS_CLIENT_OPT_DTLS12,
    HITLS_CLIENT_OPT_TLCP,
    HITLS_CLIENT_OPT_CIPHER,
    HITLS_CLIENT_OPT_TLS13_CIPHER,
    HITLS_CLIENT_OPT_SIGALGS,
    HITLS_CLIENT_OPT_CURVES,
    
    /* Certificate options */
    HITLS_CLIENT_OPT_CERT,
    HITLS_CLIENT_OPT_KEY,
    HITLS_CLIENT_OPT_PASS,
    HITLS_CLIENT_OPT_CAFILE,
    HITLS_CLIENT_OPT_CAPATH,
    HITLS_CLIENT_OPT_VERIFY,
    HITLS_CLIENT_OPT_VERIFY_ERROR,
    HITLS_CLIENT_OPT_NO_VERIFY,
    
    /* TLCP options */
    HITLS_CLIENT_OPT_TLCP_ENC_CERT,
    HITLS_CLIENT_OPT_TLCP_ENC_KEY,
    HITLS_CLIENT_OPT_TLCP_SIGN_CERT,
    HITLS_CLIENT_OPT_TLCP_SIGN_KEY,
    
    /* DTLS options */
    HITLS_CLIENT_OPT_MTU,
    HITLS_CLIENT_OPT_SCTP,
    
    /* Session options */
    HITLS_CLIENT_OPT_SESSION_FILE,
    HITLS_CLIENT_OPT_SESSION_OUT,
    HITLS_CLIENT_OPT_NO_SESSION_CACHE,
    
    /* Output options */
    HITLS_CLIENT_OPT_QUIET,
    HITLS_CLIENT_OPT_DEBUG,
    HITLS_CLIENT_OPT_STATE,
    HITLS_CLIENT_OPT_SHOWCERTS,
    HITLS_CLIENT_OPT_PREXIT,
    
    /* Data options */
    HITLS_CLIENT_OPT_MSG,
    HITLS_CLIENT_OPT_MSG_FILE,
    HITLS_CLIENT_OPT_TEST_DATA,
    
    /* Format options */
    HITLS_CLIENT_OPT_CERTFORM,
    HITLS_CLIENT_OPT_KEYFORM,
    
    HITLS_CLIENT_OPT_MAX
} HITLS_ClientOptType;

/* Client parameters structure */
typedef struct {
    /* Connection parameters */
    char *host;
    int port;
    int connect_timeout;
    bool ipv4;
    bool ipv6;
    
    /* Protocol parameters */
    char *protocol;
    char *cipher_suites;
    char *tls13_cipher_suites;
    char *sig_algs;
    char *curves;
    bool disable_ems;
    
    /* Certificate parameters */
    char *cert_file;
    char *key_file;
    char *key_pass;
    char *ca_file;
    char *ca_dir;
    bool verify_none;
    int verify_depth;
    bool verify_return_error;
    
    /* TLCP parameters */
    char *tlcp_enc_cert;
    char *tlcp_enc_key;
    char *tlcp_sign_cert;
    char *tlcp_sign_key;
    
    /* DTLS parameters */
    int mtu;
    bool sctp;
    
    /* Session parameters */
    char *session_file;
    bool session_out;
    bool no_session_cache;
    
    /* Output parameters */
    bool quiet;
    bool debug;
    bool showcerts;
    bool state;
    bool prexit;
    
    /* Data parameters */
    char *msg;
    char *msg_file;
    bool test_data;
    
    /* Format parameters */
    BSL_ParseFormat cert_format;
    BSL_ParseFormat key_format;
    
} HITLS_ClientParams;

/**
 * @brief Main entry point for s_client tool
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return Application exit code
 */
int HITLS_ClientMain(int argc, char *argv[]);

/**
 * @brief Parse client command line options
 * @param argc Number of arguments
 * @param argv Argument array
 * @param params Output parameters structure
 * @return Success or error code
 */
int ParseClientOptions(int argc, char *argv[], HITLS_ClientParams *params);

/**
 * @brief Create client TLS/DTLS configuration
 * @param params Client parameters
 * @return HITLS configuration or NULL on error
 */
HITLS_Config *CreateClientConfig(HITLS_ClientParams *params);

/**
 * @brief Establish network connection to server
 * @param params Client parameters
 * @return UIO object or NULL on error
 */
BSL_UIO *CreateClientConnection(HITLS_ClientParams *params);

/**
 * @brief Perform TLS/DTLS handshake
 * @param ctx TLS context
 * @param params Client parameters
 * @return Success or error code
 */
int PerformClientHandshake(HITLS_Ctx *ctx, HITLS_ClientParams *params);

/**
 * @brief Handle data exchange with server
 * @param ctx TLS context
 * @param params Client parameters
 * @return Success or error code
 */
int HandleClientDataExchange(HITLS_Ctx *ctx, HITLS_ClientParams *params);

/**
 * @brief Clean up client resources
 * @param ctx TLS context
 * @param config TLS configuration
 * @param uio UIO object
 * @param params Client parameters
 */
void CleanupClientResources(HITLS_Ctx *ctx, HITLS_Config *config, BSL_UIO *uio, HITLS_ClientParams *params);

#ifdef __cplusplus
}
#endif

#endif /* APP_CLIENT_H */