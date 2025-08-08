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

#include "app_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <signal.h>
#include "securec.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_tls_common.h"
#include "hitls.h"
#include "hitls_cert_init.h"
#include "hitls_session.h"
#include "crypt_errno.h"
#include "hitls_crypt_init.h"
#include "bsl_uio.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"
#include "bsl_sal.h"
#include "bsl_err.h"

/* Command line options for s_client */
static const HITLS_CmdOption g_clientOptions[] = {
    /* Connection options */
    {"host",        HITLS_CLIENT_OPT_HOST,        HITLS_APP_OPT_VALUETYPE_STRING,      "Target hostname or IP address"},
    {"port",        HITLS_CLIENT_OPT_PORT,        HITLS_APP_OPT_VALUETYPE_UINT,        "Target port number (default 443)"},
    {"connect",     HITLS_CLIENT_OPT_CONNECT,     HITLS_APP_OPT_VALUETYPE_STRING,      "Connect to host:port"},
    {"4",           HITLS_CLIENT_OPT_IPV4,        HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Force IPv4"},
    {"6",           HITLS_CLIENT_OPT_IPV6,        HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Force IPv6"},
    {"timeout",     HITLS_CLIENT_OPT_TIMEOUT,     HITLS_APP_OPT_VALUETYPE_UINT,        "Connection timeout in seconds"},
    
    /* Protocol options */
    {"tls1_2",      HITLS_CLIENT_OPT_TLS12,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use TLS 1.2 protocol"},
    {"tls1_3",      HITLS_CLIENT_OPT_TLS13,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use TLS 1.3 protocol"},
    {"dtls1_2",     HITLS_CLIENT_OPT_DTLS12,      HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use DTLS 1.2 protocol"},
    {"tlcp",        HITLS_CLIENT_OPT_TLCP,        HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use TLCP protocol"},
    {"cipher",      HITLS_CLIENT_OPT_CIPHER,      HITLS_APP_OPT_VALUETYPE_STRING,      "Specify cipher suites"},
    {"ciphersuites", HITLS_CLIENT_OPT_TLS13_CIPHER, HITLS_APP_OPT_VALUETYPE_STRING,   "TLS 1.3 cipher suites"},
    {"sigalgs",     HITLS_CLIENT_OPT_SIGALGS,     HITLS_APP_OPT_VALUETYPE_STRING,      "Signature algorithms"},
    {"curves",      HITLS_CLIENT_OPT_CURVES,      HITLS_APP_OPT_VALUETYPE_STRING,      "Elliptic curves"},
    
    /* Certificate options */
    {"cert",        HITLS_CLIENT_OPT_CERT,        HITLS_APP_OPT_VALUETYPE_IN_FILE,     "Client certificate file"},
    {"key",         HITLS_CLIENT_OPT_KEY,         HITLS_APP_OPT_VALUETYPE_IN_FILE,     "Client private key file"},
    {"pass",        HITLS_CLIENT_OPT_PASS,        HITLS_APP_OPT_VALUETYPE_STRING,      "Private key password"},
    {"CAfile",      HITLS_CLIENT_OPT_CAFILE,      HITLS_APP_OPT_VALUETYPE_IN_FILE,     "CA certificate file"},
    {"CApath",      HITLS_CLIENT_OPT_CAPATH,      HITLS_APP_OPT_VALUETYPE_DIR,         "CA certificate directory"},
    {"verify",      HITLS_CLIENT_OPT_VERIFY,      HITLS_APP_OPT_VALUETYPE_UINT,        "Certificate verification depth"},
    {"verify_return_error", HITLS_CLIENT_OPT_VERIFY_ERROR, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Return error on verification failure"},
    {"noverify",    HITLS_CLIENT_OPT_NO_VERIFY,   HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Don't verify server certificate"},
    
    /* TLCP options */
    {"tlcp_enc_cert", HITLS_CLIENT_OPT_TLCP_ENC_CERT, HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP encryption certificate"},
    {"tlcp_enc_key",  HITLS_CLIENT_OPT_TLCP_ENC_KEY,  HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP encryption private key"},
    {"tlcp_sign_cert", HITLS_CLIENT_OPT_TLCP_SIGN_CERT, HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP signature certificate"},
    {"tlcp_sign_key",  HITLS_CLIENT_OPT_TLCP_SIGN_KEY,  HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP signature private key"},
    
    /* DTLS options */
    {"mtu",         HITLS_CLIENT_OPT_MTU,         HITLS_APP_OPT_VALUETYPE_UINT,        "DTLS MTU size"},
    {"sctp",        HITLS_CLIENT_OPT_SCTP,        HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use SCTP transport"},
    
    /* Session options */
    {"sess_out",    HITLS_CLIENT_OPT_SESSION_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE,    "Output session file"},
    {"sess_in",     HITLS_CLIENT_OPT_SESSION_FILE, HITLS_APP_OPT_VALUETYPE_IN_FILE,    "Input session file"},
    {"no_sess_cache", HITLS_CLIENT_OPT_NO_SESSION_CACHE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Disable session cache"},
    
    /* Output options */
    {"quiet",       HITLS_CLIENT_OPT_QUIET,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Quiet mode"},
    {"debug",       HITLS_CLIENT_OPT_DEBUG,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Debug mode"},
    {"state",       HITLS_CLIENT_OPT_STATE,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Show handshake state"},
    {"showcerts",   HITLS_CLIENT_OPT_SHOWCERTS,   HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Show certificate chain"},
    {"prexit",      HITLS_CLIENT_OPT_PREXIT,      HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Exit after handshake"},
    
    /* Data options */
    {"msg",         HITLS_CLIENT_OPT_MSG,         HITLS_APP_OPT_VALUETYPE_STRING,      "Message to send"},
    {"msgfile",     HITLS_CLIENT_OPT_MSG_FILE,    HITLS_APP_OPT_VALUETYPE_IN_FILE,     "Message file to send"},
    {"testdata",    HITLS_CLIENT_OPT_TEST_DATA,   HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Send test data"},
    
    /* Format options */
    {"certform",    HITLS_CLIENT_OPT_CERTFORM,    HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,  "Certificate format (PEM|DER)"},
    {"keyform",     HITLS_CLIENT_OPT_KEYFORM,     HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,  "Private key format (PEM|DER)"},
    
    {"help",        HITLS_APP_OPT_HELP,           HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Show help"},
    {NULL,          0,                            0,                                   NULL}
};

static void InitClientParams(HITLS_ClientParams *params)
{
    if (params == NULL) {
        return;
    }
    
    memset(params, 0, sizeof(HITLS_ClientParams));
    
    /* Set default values */
    params->port = 443;
    params->connect_timeout = 10;
    params->protocol = NULL;
    params->verify_depth = 9;
    params->cert_format = BSL_FORMAT_PEM;
    params->key_format = BSL_FORMAT_PEM;
    params->mtu = 1400;
}

static void CleanupClientParams(HITLS_ClientParams *params)
{
    if (params == NULL) {
        return;
    }
    
    BSL_SAL_Free(params->host);
    BSL_SAL_Free(params->cipher_suites);
    BSL_SAL_Free(params->tls13_cipher_suites);
    BSL_SAL_Free(params->sig_algs);
    BSL_SAL_Free(params->curves);
    BSL_SAL_Free(params->cert_file);
    BSL_SAL_Free(params->key_file);
    BSL_SAL_Free(params->key_pass);
    BSL_SAL_Free(params->ca_file);
    BSL_SAL_Free(params->ca_dir);
    BSL_SAL_Free(params->tlcp_enc_cert);
    BSL_SAL_Free(params->tlcp_enc_key);
    BSL_SAL_Free(params->tlcp_sign_cert);
    BSL_SAL_Free(params->tlcp_sign_key);
    BSL_SAL_Free(params->session_file);
    BSL_SAL_Free(params->msg);
    BSL_SAL_Free(params->msg_file);
}

int ParseClientOptions(int argc, char *argv[], HITLS_ClientParams *params)
{
    if (params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    InitClientParams(params);
    
    int opt = HITLS_APP_OptBegin(argc, argv, g_clientOptions);
    if (opt < 0) {
        AppPrintError("Failed to initialize option parser\n");
        return HITLS_APP_ERR_PARSE_OPT;
    }
    
    while ((opt = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        switch (opt) {
            case HITLS_CLIENT_OPT_HOST: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->host = BSL_SAL_Malloc(len);
                if (params->host != NULL) {
                    strcpy(params->host, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_PORT:
                HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), (uint32_t*)&params->port);
                break;
                
            case HITLS_CLIENT_OPT_CONNECT: {
                APP_NetworkAddr addr = {0};
                if (ParseConnectString(HITLS_APP_OptGetValueStr(), &addr) == HITLS_APP_SUCCESS) {
                    params->host = addr.host;
                    params->port = addr.port;
                }
                break;
            }
            
            case HITLS_CLIENT_OPT_IPV4:
                params->ipv4 = true;
                params->ipv6 = false;
                break;
                
            case HITLS_CLIENT_OPT_IPV6:
                params->ipv6 = true;
                params->ipv4 = false;
                break;
                
            case HITLS_CLIENT_OPT_TIMEOUT:
                HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), &params->connect_timeout);
                break;
                
            case HITLS_CLIENT_OPT_TLS12:
                params->protocol = "tls12";
                break;
                
            case HITLS_CLIENT_OPT_TLS13:
                params->protocol = "tls13";
                break;
                
            case HITLS_CLIENT_OPT_DTLS12:
                params->protocol = "dtls12";
                break;
                
            case HITLS_CLIENT_OPT_TLCP:
                params->protocol = "tlcp";
                break;
                
            case HITLS_CLIENT_OPT_CIPHER: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->cipher_suites = BSL_SAL_Malloc(len);
                if (params->cipher_suites != NULL) {
                    strcpy(params->cipher_suites, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_TLS13_CIPHER: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->tls13_cipher_suites = BSL_SAL_Malloc(len);
                if (params->tls13_cipher_suites != NULL) {
                    strcpy(params->tls13_cipher_suites, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_SIGALGS: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->sig_algs = BSL_SAL_Malloc(len);
                if (params->sig_algs != NULL) {
                    strcpy(params->sig_algs, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_CURVES: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->curves = BSL_SAL_Malloc(len);
                if (params->curves != NULL) {
                    strcpy(params->curves, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_CERT: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->cert_file = BSL_SAL_Malloc(len);
                if (params->cert_file != NULL) {
                    strcpy(params->cert_file, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_KEY: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->key_file = BSL_SAL_Malloc(len);
                if (params->key_file != NULL) {
                    strcpy(params->key_file, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_PASS: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->key_pass = BSL_SAL_Malloc(len);
                if (params->key_pass != NULL) {
                    strcpy(params->key_pass, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_CAFILE: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->ca_file = BSL_SAL_Malloc(len);
                if (params->ca_file != NULL) {
                    strcpy(params->ca_file, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_CAPATH: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->ca_dir = BSL_SAL_Malloc(len);
                if (params->ca_dir != NULL) {
                    strcpy(params->ca_dir, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_VERIFY:
                HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), &params->verify_depth);
                break;
                
            case HITLS_CLIENT_OPT_VERIFY_ERROR:
                params->verify_return_error = true;
                break;
                
            case HITLS_CLIENT_OPT_NO_VERIFY:
                params->verify_none = true;
                break;
                
            case HITLS_CLIENT_OPT_TLCP_ENC_CERT: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->tlcp_enc_cert = BSL_SAL_Malloc(len);
                if (params->tlcp_enc_cert != NULL) {
                    strcpy(params->tlcp_enc_cert, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_TLCP_ENC_KEY: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->tlcp_enc_key = BSL_SAL_Malloc(len);
                if (params->tlcp_enc_key != NULL) {
                    strcpy(params->tlcp_enc_key, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_TLCP_SIGN_CERT: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->tlcp_sign_cert = BSL_SAL_Malloc(len);
                if (params->tlcp_sign_cert != NULL) {
                    strcpy(params->tlcp_sign_cert, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_TLCP_SIGN_KEY: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->tlcp_sign_key = BSL_SAL_Malloc(len);
                if (params->tlcp_sign_key != NULL) {
                    strcpy(params->tlcp_sign_key, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_MTU:
                HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), &params->mtu);
                break;
                
            case HITLS_CLIENT_OPT_SCTP:
                params->sctp = true;
                break;
                
            case HITLS_CLIENT_OPT_SESSION_OUT:
                params->session_out = true;
                break;
                
            case HITLS_CLIENT_OPT_SESSION_FILE: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->session_file = BSL_SAL_Malloc(len);
                if (params->session_file != NULL) {
                    strcpy(params->session_file, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_NO_SESSION_CACHE:
                params->no_session_cache = true;
                break;
                
            case HITLS_CLIENT_OPT_QUIET:
                params->quiet = true;
                break;
                
            case HITLS_CLIENT_OPT_DEBUG:
                params->debug = true;
                break;
                
            case HITLS_CLIENT_OPT_STATE:
                params->state = true;
                break;
                
            case HITLS_CLIENT_OPT_SHOWCERTS:
                params->showcerts = true;
                break;
                
            case HITLS_CLIENT_OPT_PREXIT:
                params->prexit = true;
                break;
                
            case HITLS_CLIENT_OPT_MSG: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->msg = BSL_SAL_Malloc(len);
                if (params->msg != NULL) {
                    strcpy(params->msg, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_MSG_FILE: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->msg_file = BSL_SAL_Malloc(len);
                if (params->msg_file != NULL) {
                    strcpy(params->msg_file, value);
                }
                break;
            }
                
            case HITLS_CLIENT_OPT_TEST_DATA:
                params->test_data = true;
                break;
                
            case HITLS_CLIENT_OPT_CERTFORM:
                HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), 
                                         HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, &params->cert_format);
                break;
                
            case HITLS_CLIENT_OPT_KEYFORM:
                HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), 
                                         HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, &params->key_format);
                break;
                
            case HITLS_APP_OPT_HELP:
                HITLS_APP_OptHelpPrint(g_clientOptions);
                return HITLS_APP_HELP_PRINTED;
                
            default:
                AppPrintError("Unknown option\n");
                return HITLS_APP_ERR_PARSE_OPT;
        }
    }
    
    HITLS_APP_OptEnd();
    
    /* Validate required parameters */
    if (params->host == NULL) {
        AppPrintError("Host must be specified\n");
        return HITLS_APP_INVALID_ARG;
    }
    
    return HITLS_APP_SUCCESS;
}

HITLS_Config *CreateClientConfig(HITLS_ClientParams *params)
{
    if (params == NULL) {
        return NULL;
    }
    
    /* Determine protocol type */
    APP_ProtocolType protocol = ParseProtocolType(params->protocol);
    
    /* Create base configuration */
    HITLS_Config *config = CreateProtocolConfig(protocol);
    if (config == NULL) {
        return NULL;
    }
    
    int ret = HITLS_SUCCESS;
    
    /* Configure cipher suites */
    if (params->cipher_suites) {
        ret = ConfigureCipherSuites(config, params->cipher_suites, false);
        if (ret != HITLS_APP_SUCCESS) {
            HITLS_CFG_FreeConfig(config);
            return NULL;
        }
    }
    
    if (params->tls13_cipher_suites && protocol == APP_PROTOCOL_TLS13) {
        ret = ConfigureCipherSuites(config, params->tls13_cipher_suites, true);
        if (ret != HITLS_APP_SUCCESS) {
            HITLS_CFG_FreeConfig(config);
            return NULL;
        }
    }
    
    /* Configure signature algorithms */
    if (params->sig_algs) {
        ret = ConfigureSignatureAlgorithms(config, params->sig_algs);
        if (ret != HITLS_APP_SUCCESS) {
            HITLS_CFG_FreeConfig(config);
            return NULL;
        }
    }
    
    /* Configure curves */
    if (params->curves) {
        ret = ConfigureCurves(config, params->curves);
        if (ret != HITLS_APP_SUCCESS) {
            HITLS_CFG_FreeConfig(config);
            return NULL;
        }
    }
    
    /* Configure certificate verification */
    APP_CertConfig cert_config = {
        .cert_file = params->cert_file,
        .key_file = params->key_file,
        .key_pass = params->key_pass,
        .ca_file = params->ca_file,
        .ca_dir = params->ca_dir,
        .cert_format = params->cert_format,
        .key_format = params->key_format,
        .tlcp_enc_cert = params->tlcp_enc_cert,
        .tlcp_enc_key = params->tlcp_enc_key,
        .tlcp_sign_cert = params->tlcp_sign_cert,
        .tlcp_sign_key = params->tlcp_sign_key
    };
    
    ret = ConfigureCertificateVerification(config, &cert_config, true, !params->verify_none, params->verify_depth);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    
    /* Configure client certificate if provided */
    if (protocol == APP_PROTOCOL_TLCP) {
        ret = ConfigureTLCPCertificates(config, &cert_config, true);
    } else {
        ret = ConfigureCertificate(config, &cert_config, true);
    }
    
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    
    /* Configure DTLS specific options */
    if (protocol == APP_PROTOCOL_DTLS12) {
        ret = ConfigureDTLSOptions(config, params->mtu, true);
        if (ret != HITLS_APP_SUCCESS) {
            HITLS_CFG_FreeConfig(config);
            return NULL;
        }
    }
    
    /* Configure session options */
    if (params->no_session_cache) {
        ret = HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_NO);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to disable session cache: 0x%x\n", ret);
        }
    }
    
    return config;
}

BSL_UIO *CreateClientConnection(HITLS_ClientParams *params)
{
    if (params == NULL || params->host == NULL) {
        return NULL;
    }
    
    APP_NetworkAddr addr = {
        .host = params->host,
        .port = params->port,
        .ipv4 = params->ipv4,
        .ipv6 = params->ipv6
    };
    
    int sockfd = -1;
    BSL_UIO *uio = NULL;
    
    /* Create socket based on protocol */
    APP_ProtocolType protocol = ParseProtocolType(params->protocol);
    if (protocol == APP_PROTOCOL_DTLS12) {
        sockfd = CreateUDPSocket(&addr, params->connect_timeout);
        uio = BSL_UIO_New(BSL_UIO_UdpMethod());
    } else {
        sockfd = CreateTCPSocket(&addr, params->connect_timeout);
        uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    }
    
    if (sockfd < 0 || uio == NULL) {
        if (sockfd >= 0) BSL_SAL_SockClose(sockfd);
        if (uio) BSL_UIO_Free(uio);
        return NULL;
    }
    
    /* Set socket to UIO */
    int ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, sizeof(sockfd), &sockfd);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Failed to set socket to UIO: 0x%x\n", ret);
        BSL_SAL_SockClose(sockfd);
        BSL_UIO_Free(uio);
        return NULL;
    }
    
    if (!params->quiet) {
        AppPrintInfo("Connected to %s:%d\n", params->host, params->port);
    }
    
    return uio;
}

int PerformClientHandshake(HITLS_Ctx *ctx, HITLS_ClientParams *params)
{
    if (ctx == NULL || params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    if (!params->quiet) {
        AppPrintInfo("Starting TLS handshake...\n");
    }
    
    /* Perform handshake */
    int ret;
    do {
        ret = HITLS_Connect(ctx);
        if (ret == HITLS_SUCCESS) {
            break;
        }
        if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY && ret != HITLS_REC_NORMAL_IO_BUSY) {
            AppPrintError("TLS handshake failed: 0x%x\n", ret);
            return HITLS_APP_ERR_HANDSHAKE;
        }
        /* Non-blocking I/O, retry */
        usleep(10000); /* Sleep 10ms */
    } while (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY);
    
    if (!params->quiet) {
        AppPrintInfo("TLS handshake completed successfully\n");
        
        /* Print connection information */
        PrintConnectionInfo(ctx, params->showcerts, params->state);
    }
    
    return HITLS_APP_SUCCESS;
}

int HandleClientDataExchange(HITLS_Ctx *ctx, HITLS_ClientParams *params)
{
    if (ctx == NULL || params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    int ret = HITLS_APP_SUCCESS;
    
    /* Send message if specified */
    if (params->msg) {
        uint32_t written = 0;
        ret = HITLS_Write(ctx, (const uint8_t *)params->msg, strlen(params->msg), &written);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to send message: 0x%x\n", ret);
            return HITLS_APP_ERR_SEND_DATA;
        }
        
        if (!params->quiet) {
            AppPrintInfo("Sent %u bytes\n", written);
        }
    }
    
    /* Send test data if requested */
    if (params->test_data) {
        const char *test_msg = "GET / HTTP/1.1\r\nHost: ";
        char *full_msg = BSL_SAL_Malloc(strlen(test_msg) + strlen(params->host) + 20);
        if (full_msg) {
            sprintf(full_msg, "%s%s\r\nConnection: close\r\n\r\n", test_msg, params->host);
            
            uint32_t written = 0;
            ret = HITLS_Write(ctx, (const uint8_t *)full_msg, strlen(full_msg), &written);
            if (ret != HITLS_SUCCESS) {
                AppPrintError("Failed to send test data: 0x%x\n", ret);
                BSL_SAL_Free(full_msg);
                return HITLS_APP_ERR_SEND_DATA;
            }
            
            if (!params->quiet) {
                AppPrintInfo("Sent test HTTP request (%u bytes)\n", written);
            }
            
            BSL_SAL_Free(full_msg);
        }
    }
    
    /* Read response data */
    if (params->msg || params->test_data) {
        uint8_t buffer[8192];
        uint32_t read_len = 0;
        
        ret = HITLS_Read(ctx, buffer, sizeof(buffer) - 1, &read_len);
        if (ret == HITLS_SUCCESS && read_len > 0) {
            buffer[read_len] = '\0';
            if (!params->quiet) {
                AppPrintInfo("Received %u bytes:\n%s\n", read_len, buffer);
            }
        } else if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to read response: 0x%x\n", ret);
        }
    }
    
    /* Interactive mode if no specific data to send */
    if (!params->msg && !params->test_data && !params->prexit) {
        if (!params->quiet) {
            AppPrintInfo("Interactive mode - type messages (Ctrl+C to exit):\n");
        }
        
        char input_buffer[1024];
        while (fgets(input_buffer, sizeof(input_buffer), stdin)) {
            size_t len = strlen(input_buffer);
            if (len > 0 && input_buffer[len-1] == '\n') {
                input_buffer[len-1] = '\0';
                len--;
            }
            
            if (len == 0) continue;
            
            uint32_t written = 0;
            ret = HITLS_Write(ctx, (const uint8_t *)input_buffer, len, &written);
            if (ret != HITLS_SUCCESS) {
                AppPrintError("Failed to send data: 0x%x\n", ret);
                break;
            }
            
            /* Try to read response */
            uint8_t response[8192];
            uint32_t read_len = 0;
            ret = HITLS_Read(ctx, response, sizeof(response) - 1, &read_len);
            if (ret == HITLS_SUCCESS && read_len > 0) {
                response[read_len] = '\0';
                AppPrintInfo("Response: %s\n", response);
            }
        }
    }
    
    return HITLS_APP_SUCCESS;
}

void CleanupClientResources(HITLS_Ctx *ctx, HITLS_Config *config, BSL_UIO *uio, HITLS_ClientParams *params)
{
    if (ctx) {
        HITLS_Close(ctx);
        HITLS_Free(ctx);
    }
    
    if (config) {
        HITLS_CFG_FreeConfig(config);
    }
    
    if (uio) {
        /* Close socket */
        int fd = -1;
        BSL_UIO_Ctrl(uio, BSL_UIO_GET_FD, 0, &fd);
        if (fd >= 0) {
            BSL_SAL_SockClose(fd);
        }
        BSL_UIO_Free(uio);
    }
    
    if (params) {
        CleanupClientParams(params);
    }
}

int HITLS_ClientMain(int argc, char *argv[])
{
    HITLS_ClientParams params = {0};
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int ret = HITLS_APP_SUCCESS;
    
    /* Initialize library */
    /* BSL memory callbacks are already set up in BSL module */
    BSL_ERR_Init();
    
    /* Initialize print UIO for error and info output */
    ret = AppPrintErrorUioInit(stderr);
    if (ret != HITLS_APP_SUCCESS) {
        return HITLS_APP_INIT_FAILED;
    }
    
    ret = AppPrintInfoUioInit();
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to initialize info print UIO: 0x%x\n", ret);
        AppPrintErrorUioUnInit();
        return HITLS_APP_INIT_FAILED;
    }
    
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("Failed to initialize crypto library: 0x%x\n", ret);
        return HITLS_APP_INIT_FAILED;
    }
    
    ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("Failed to initialize random: 0x%x\n", ret);
        return HITLS_APP_INIT_FAILED;
    }
    
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    
    /* Parse command line options */
    ret = ParseClientOptions(argc, argv, &params);
    if (ret != HITLS_APP_SUCCESS) {
        if (ret == HITLS_APP_HELP_PRINTED) {
            ret = HITLS_APP_SUCCESS;
        }
        goto cleanup;
    }
    
    /* Create TLS configuration */
    config = CreateClientConfig(&params);
    if (config == NULL) {
        AppPrintError("Failed to create TLS configuration\n");
        ret = HITLS_APP_ERR_CREATE_CONFIG;
        goto cleanup;
    }
    
    /* Establish network connection */
    uio = CreateClientConnection(&params);
    if (uio == NULL) {
        AppPrintError("Failed to establish network connection\n");
        ret = HITLS_APP_ERR_CONNECT;
        goto cleanup;
    }
    
    /* Create TLS context */
    ctx = HITLS_New(config);
    if (ctx == NULL) {
        AppPrintError("Failed to create TLS context\n");
        ret = HITLS_APP_ERR_CREATE_CTX;
        goto cleanup;
    }
    
    /* Associate UIO with TLS context */
    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to set UIO: 0x%x\n", ret);
        ret = HITLS_APP_ERR_SET_UIO;
        goto cleanup;
    }
    
    /* Perform TLS handshake */
    ret = PerformClientHandshake(ctx, &params);
    if (ret != HITLS_APP_SUCCESS) {
        goto cleanup;
    }
    
    /* Exit after handshake if requested */
    if (params.prexit) {
        if (!params.quiet) {
            AppPrintInfo("Handshake completed, exiting as requested\n");
        }
        ret = HITLS_APP_SUCCESS;
        goto cleanup;
    }
    
    /* Handle data exchange */
    ret = HandleClientDataExchange(ctx, &params);
    
cleanup:
    CleanupClientResources(ctx, config, uio, &params);
    
    if (!params.quiet && ret == HITLS_APP_SUCCESS) {
        AppPrintInfo("Client completed successfully\n");
    }
    
    /* Cleanup print UIO */
    AppPrintInfoUioUnInit();
    AppPrintErrorUioUnInit();
    
    return ret;
}