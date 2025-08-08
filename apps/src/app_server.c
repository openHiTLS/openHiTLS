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

#include "app_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include "securec.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_tls_common.h"
#include "hitls.h"
#include "hitls_cert_init.h"
#include "hitls_crypt_init.h"
#include "hitls_session.h"
#include "crypt_errno.h"
#include "bsl_uio.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"
#include "bsl_sal.h"
#include "bsl_err.h"

/* Command line options for s_server */
static const HITLS_CmdOption g_serverOptions[] = {
    /* Listen options */
    {"accept",      HITLS_SERVER_OPT_ACCEPT,      HITLS_APP_OPT_VALUETYPE_STRING,      "Listen on host:port"},
    {"port",        HITLS_SERVER_OPT_PORT,        HITLS_APP_OPT_VALUETYPE_UINT,        "Listen port (default 4433)"},
    {"4",           HITLS_SERVER_OPT_IPV4,        HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Force IPv4"},
    {"6",           HITLS_SERVER_OPT_IPV6,        HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Force IPv6"},
    {"bind",        HITLS_SERVER_OPT_BIND,        HITLS_APP_OPT_VALUETYPE_STRING,      "Bind address"},
    
    /* Protocol options */
    {"tls1_2",      HITLS_SERVER_OPT_TLS12,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use TLS 1.2 protocol"},
    {"tls1_3",      HITLS_SERVER_OPT_TLS13,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use TLS 1.3 protocol"},
    {"dtls1_2",     HITLS_SERVER_OPT_DTLS12,      HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use DTLS 1.2 protocol"},
    {"tlcp",        HITLS_SERVER_OPT_TLCP,        HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use TLCP protocol"},
    {"cipher",      HITLS_SERVER_OPT_CIPHER,      HITLS_APP_OPT_VALUETYPE_STRING,      "Specify cipher suites"},
    {"ciphersuites", HITLS_SERVER_OPT_TLS13_CIPHER, HITLS_APP_OPT_VALUETYPE_STRING,   "TLS 1.3 cipher suites"},
    {"sigalgs",     HITLS_SERVER_OPT_SIGALGS,     HITLS_APP_OPT_VALUETYPE_STRING,      "Signature algorithms"},
    {"curves",      HITLS_SERVER_OPT_CURVES,      HITLS_APP_OPT_VALUETYPE_STRING,      "Elliptic curves"},
    {"serverpref",  HITLS_SERVER_OPT_CIPHER_SERVER_PREFERENCE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Use server cipher preference"},
    
    /* Certificate options */
    {"cert",        HITLS_SERVER_OPT_CERT,        HITLS_APP_OPT_VALUETYPE_IN_FILE,     "Server certificate file"},
    {"key",         HITLS_SERVER_OPT_KEY,         HITLS_APP_OPT_VALUETYPE_IN_FILE,     "Server private key file"},
    {"pass",        HITLS_SERVER_OPT_PASS,        HITLS_APP_OPT_VALUETYPE_STRING,      "Private key password"},
    {"CAfile",      HITLS_SERVER_OPT_CAFILE,      HITLS_APP_OPT_VALUETYPE_IN_FILE,     "CA certificate file"},
    {"CApath",      HITLS_SERVER_OPT_CAPATH,      HITLS_APP_OPT_VALUETYPE_DIR,         "CA certificate directory"},
    {"verify",      HITLS_SERVER_OPT_VERIFY,      HITLS_APP_OPT_VALUETYPE_UINT,        "Verify client certificate"},
    {"Verify",      HITLS_SERVER_OPT_VERIFY_FORCE, HITLS_APP_OPT_VALUETYPE_UINT,      "Force verify client certificate"},
    {"verify_once", HITLS_SERVER_OPT_VERIFY_ONCE, HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Verify client certificate once"},
    
    /* TLCP options */
    {"tlcp_enc_cert", HITLS_SERVER_OPT_TLCP_ENC_CERT, HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP encryption certificate"},
    {"tlcp_enc_key",  HITLS_SERVER_OPT_TLCP_ENC_KEY,  HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP encryption private key"},
    {"tlcp_sign_cert", HITLS_SERVER_OPT_TLCP_SIGN_CERT, HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP signature certificate"},
    {"tlcp_sign_key",  HITLS_SERVER_OPT_TLCP_SIGN_KEY,  HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP signature private key"},
    
    /* DTLS options */
    {"mtu",         HITLS_SERVER_OPT_MTU,         HITLS_APP_OPT_VALUETYPE_UINT,        "DTLS MTU size"},
    {"cookie",      HITLS_SERVER_OPT_COOKIE_EXCHANGE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Enable DTLS cookie exchange"},
    
    /* Session options */
    {"sess_cache_file", HITLS_SERVER_OPT_SESSION_CACHE_FILE, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Session cache file"},
    {"no_sess_cache", HITLS_SERVER_OPT_NO_SESSION_CACHE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Disable session cache"},
    {"sess_timeout", HITLS_SERVER_OPT_SESSION_TIMEOUT, HITLS_APP_OPT_VALUETYPE_UINT,    "Session timeout"},
    
    /* Service options */
    {"daemon",      HITLS_SERVER_OPT_DAEMON,      HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Run as daemon"},
    {"accept_once", HITLS_SERVER_OPT_ACCEPT_ONCE, HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Accept only one connection"},
    {"naccept",     HITLS_SERVER_OPT_NACCEPT,     HITLS_APP_OPT_VALUETYPE_UINT,        "Maximum connections"},
    
    /* Output options */
    {"quiet",       HITLS_SERVER_OPT_QUIET,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Quiet mode"},
    {"debug",       HITLS_SERVER_OPT_DEBUG,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Debug mode"},
    {"state",       HITLS_SERVER_OPT_STATE,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Show handshake state"},
    {"showcerts",   HITLS_SERVER_OPT_SHOWCERTS,   HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Show certificate chain"},
    {"msg",         HITLS_SERVER_OPT_MSG,         HITLS_APP_OPT_VALUETYPE_STRING,      "Response message"},
    
    /* Format options */
    {"certform",    HITLS_SERVER_OPT_CERTFORM,    HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,  "Certificate format (PEM|DER)"},
    {"keyform",     HITLS_SERVER_OPT_KEYFORM,     HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,  "Private key format (PEM|DER)"},
    
    {"help",        HITLS_APP_OPT_HELP,           HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Show help"},
    {NULL,          0,                            0,                                   NULL}
};

static void InitServerParams(HITLS_ServerParams *params)
{
    if (params == NULL) {
        return;
    }
    
    memset(params, 0, sizeof(HITLS_ServerParams));
    
    /* Set default values */
    params->port = 4433;
    params->backlog = 5;
    params->protocol = NULL;
    params->verify_depth = 9;
    params->cert_format = BSL_FORMAT_PEM;
    params->key_format = BSL_FORMAT_PEM;
    params->mtu = 1400;
    params->session_timeout = 300; /* 5 minutes */
    params->max_connections = 0;   /* No limit */
}

static void CleanupServerParams(HITLS_ServerParams *params)
{
    if (params == NULL) {
        return;
    }
    
    BSL_SAL_Free(params->bind_addr);
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
    BSL_SAL_Free(params->session_cache_file);
    BSL_SAL_Free(params->msg);
}

int ParseServerOptions(int argc, char *argv[], HITLS_ServerParams *params)
{
    if (params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    InitServerParams(params);
    
    int opt = HITLS_APP_OptBegin(argc, argv, g_serverOptions);
    if (opt < 0) {
        AppPrintError("Failed to initialize option parser\n");
        return HITLS_APP_ERR_PARSE_OPT;
    }
    
    while ((opt = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        switch (opt) {
            case HITLS_SERVER_OPT_ACCEPT: {
                APP_NetworkAddr addr = {0};
                if (ParseConnectString(HITLS_APP_OptGetValueStr(), &addr) == HITLS_APP_SUCCESS) {
                    params->bind_addr = addr.host;
                    params->port = addr.port;
                }
                break;
            }
            
            case HITLS_SERVER_OPT_PORT:
                HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), (uint32_t*)&params->port);
                break;
                
            case HITLS_SERVER_OPT_IPV4:
                params->ipv4 = true;
                params->ipv6 = false;
                break;
                
            case HITLS_SERVER_OPT_IPV6:
                params->ipv6 = true;
                params->ipv4 = false;
                break;
                
            case HITLS_SERVER_OPT_BIND: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->bind_addr = BSL_SAL_Malloc(len);
                if (params->bind_addr != NULL) {
                    strcpy(params->bind_addr, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_TLS12:
                params->protocol = "tls12";
                break;
                
            case HITLS_SERVER_OPT_TLS13:
                params->protocol = "tls13";
                break;
                
            case HITLS_SERVER_OPT_DTLS12:
                params->protocol = "dtls12";
                break;
                
            case HITLS_SERVER_OPT_TLCP:
                params->protocol = "tlcp";
                break;
                
            case HITLS_SERVER_OPT_CIPHER: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->cipher_suites = BSL_SAL_Malloc(len);
                if (params->cipher_suites != NULL) {
                    strcpy(params->cipher_suites, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_TLS13_CIPHER: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->tls13_cipher_suites = BSL_SAL_Malloc(len);
                if (params->tls13_cipher_suites != NULL) {
                    strcpy(params->tls13_cipher_suites, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_SIGALGS: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->sig_algs = BSL_SAL_Malloc(len);
                if (params->sig_algs != NULL) {
                    strcpy(params->sig_algs, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_CURVES: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->curves = BSL_SAL_Malloc(len);
                if (params->curves != NULL) {
                    strcpy(params->curves, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_CIPHER_SERVER_PREFERENCE:
                params->cipher_server_preference = true;
                break;
                
            case HITLS_SERVER_OPT_CERT: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->cert_file = BSL_SAL_Malloc(len);
                if (params->cert_file != NULL) {
                    strcpy(params->cert_file, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_KEY: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->key_file = BSL_SAL_Malloc(len);
                if (params->key_file != NULL) {
                    strcpy(params->key_file, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_PASS: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->key_pass = BSL_SAL_Malloc(len);
                if (params->key_pass != NULL) {
                    strcpy(params->key_pass, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_CAFILE: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->ca_file = BSL_SAL_Malloc(len);
                if (params->ca_file != NULL) {
                    strcpy(params->ca_file, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_CAPATH: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->ca_dir = BSL_SAL_Malloc(len);
                if (params->ca_dir != NULL) {
                    strcpy(params->ca_dir, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_VERIFY:
                params->verify_client = true;
                HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), &params->verify_depth);
                break;
                
            case HITLS_SERVER_OPT_VERIFY_FORCE:
                params->verify_client = true;
                params->verify_client_force = true;
                HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), &params->verify_depth);
                break;
                
            case HITLS_SERVER_OPT_VERIFY_ONCE:
                params->verify_client_once = true;
                break;
                
            case HITLS_SERVER_OPT_TLCP_ENC_CERT: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->tlcp_enc_cert = BSL_SAL_Malloc(len);
                if (params->tlcp_enc_cert != NULL) {
                    strcpy(params->tlcp_enc_cert, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_TLCP_ENC_KEY: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->tlcp_enc_key = BSL_SAL_Malloc(len);
                if (params->tlcp_enc_key != NULL) {
                    strcpy(params->tlcp_enc_key, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_TLCP_SIGN_CERT: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->tlcp_sign_cert = BSL_SAL_Malloc(len);
                if (params->tlcp_sign_cert != NULL) {
                    strcpy(params->tlcp_sign_cert, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_TLCP_SIGN_KEY: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->tlcp_sign_key = BSL_SAL_Malloc(len);
                if (params->tlcp_sign_key != NULL) {
                    strcpy(params->tlcp_sign_key, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_MTU:
                HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), &params->mtu);
                break;
                
            case HITLS_SERVER_OPT_COOKIE_EXCHANGE:
                params->cookie_exchange = true;
                break;
                
            case HITLS_SERVER_OPT_SESSION_CACHE_FILE: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->session_cache_file = BSL_SAL_Malloc(len);
                if (params->session_cache_file != NULL) {
                    strcpy(params->session_cache_file, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_NO_SESSION_CACHE:
                params->no_session_cache = true;
                break;
                
            case HITLS_SERVER_OPT_SESSION_TIMEOUT:
                HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), &params->session_timeout);
                break;
                
            case HITLS_SERVER_OPT_DAEMON:
                params->daemon = true;
                break;
                
            case HITLS_SERVER_OPT_ACCEPT_ONCE:
                params->accept_once = true;
                break;
                
            case HITLS_SERVER_OPT_NACCEPT:
                HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), &params->max_connections);
                break;
                
            case HITLS_SERVER_OPT_QUIET:
                params->quiet = true;
                break;
                
            case HITLS_SERVER_OPT_DEBUG:
                params->debug = true;
                break;
                
            case HITLS_SERVER_OPT_STATE:
                params->state = true;
                break;
                
            case HITLS_SERVER_OPT_SHOWCERTS:
                params->showcerts = true;
                break;
                
            case HITLS_SERVER_OPT_MSG: {
                const char *value = HITLS_APP_OptGetValueStr();
                size_t len = strlen(value) + 1;
                params->msg = BSL_SAL_Malloc(len);
                if (params->msg != NULL) {
                    strcpy(params->msg, value);
                }
                break;
            }
                
            case HITLS_SERVER_OPT_CERTFORM:
                HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), 
                                         HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, &params->cert_format);
                break;
                
            case HITLS_SERVER_OPT_KEYFORM:
                HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), 
                                         HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, &params->key_format);
                break;
                
            case HITLS_APP_OPT_HELP:
                HITLS_APP_OptHelpPrint(g_serverOptions);
                return HITLS_APP_HELP_PRINTED;
                
            default:
                AppPrintError("Unknown option\n");
                return HITLS_APP_ERR_PARSE_OPT;
        }
    }
    
    HITLS_APP_OptEnd();
    
    /* Validate required parameters */
    if (params->cert_file == NULL || params->key_file == NULL) {
        AppPrintError("Server certificate and key files must be specified\n");
        return HITLS_APP_INVALID_ARG;
    }
    
    return HITLS_APP_SUCCESS;
}

HITLS_Config *CreateServerConfig(HITLS_ServerParams *params)
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
    
    /* Configure server cipher preference */
    if (params->cipher_server_preference) {
        ret = HITLS_CFG_SetCipherServerPreference(config, true);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to set server cipher preference: 0x%x\n", ret);
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
    
    ret = ConfigureCertificateVerification(config, &cert_config, false, params->verify_client, params->verify_depth);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    
    /* Configure server certificate */
    if (protocol == APP_PROTOCOL_TLCP) {
        ret = ConfigureTLCPCertificates(config, &cert_config, false);
    } else {
        ret = ConfigureCertificate(config, &cert_config, false);
    }
    
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    
    /* Configure client verification options */
    if (params->verify_client_force) {
        ret = HITLS_CFG_SetNoClientCertSupport(config, false);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to set client cert requirement: 0x%x\n", ret);
        }
    }
    
    if (params->verify_client_once) {
        ret = HITLS_CFG_SetClientOnceVerifySupport(config, true);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to set verify once: 0x%x\n", ret);
        }
    }
    
    /* Configure DTLS specific options */
    if (protocol == APP_PROTOCOL_DTLS12) {
        ret = ConfigureDTLSOptions(config, params->mtu, params->cookie_exchange);
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
    } else {
        ret = HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_SERVER);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to enable session cache: 0x%x\n", ret);
        }
        
        if (params->session_timeout > 0) {
            ret = HITLS_CFG_SetSessionTimeout(config, params->session_timeout);
            if (ret != HITLS_SUCCESS) {
                AppPrintError("Failed to set session timeout: 0x%x\n", ret);
            }
        }
    }
    
    return config;
}

int CreateListenSocket(HITLS_ServerParams *params)
{
    if (params == NULL) {
        return -1;
    }
    
    APP_NetworkAddr addr = {
        .host = params->bind_addr,
        .port = params->port,
        .ipv4 = params->ipv4,
        .ipv6 = params->ipv6
    };
    
    int listen_fd = -1;
    
    /* Create listen socket based on protocol */
    APP_ProtocolType protocol = ParseProtocolType(params->protocol);
    if (protocol == APP_PROTOCOL_DTLS12) {
        listen_fd = CreateUDPListenSocket(&addr);
    } else {
        listen_fd = CreateTCPListenSocket(&addr, params->backlog);
    }
    
    if (listen_fd < 0) {
        return -1;
    }
    
    if (!params->quiet) {
        AppPrintInfo("Listening on %s:%d (%s)\n", 
                    addr.host ? addr.host : "0.0.0.0", 
                    params->port,
                    protocol == APP_PROTOCOL_DTLS12 ? "UDP" : "TCP");
    }
    
    return listen_fd;
}

static BSL_UIO *CreateServerUIO(int client_fd, HITLS_ServerParams *params)
{
    BSL_UIO *uio = NULL;
    
    APP_ProtocolType protocol = ParseProtocolType(params->protocol);
    if (protocol == APP_PROTOCOL_DTLS12) {
        uio = BSL_UIO_New(BSL_UIO_UdpMethod());
    } else {
        uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    }
    
    if (uio == NULL) {
        return NULL;
    }
    
    int ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, sizeof(client_fd), &client_fd);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Failed to set socket to UIO: 0x%x\n", ret);
        BSL_UIO_Free(uio);
        return NULL;
    }
    
    return uio;
}

int HandleClientConnection(HITLS_Ctx *ctx, HITLS_ServerParams *params)
{
    if (ctx == NULL || params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    int ret = HITLS_APP_SUCCESS;
    
    if (!params->quiet) {
        AppPrintInfo("Starting TLS handshake with client...\n");
    }
    
    /* Perform handshake */
    do {
        ret = HITLS_Accept(ctx);
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
    
    /* Handle data exchange */
    uint8_t buffer[8192];
    uint32_t read_len = 0;
    
    /* Read client data */
    ret = HITLS_Read(ctx, buffer, sizeof(buffer) - 1, &read_len);
    if (ret == HITLS_SUCCESS && read_len > 0) {
        buffer[read_len] = '\0';
        
        if (!params->quiet) {
            AppPrintInfo("Received %u bytes from client:\n%s\n", read_len, buffer);
        }
        
        /* Send response */
        const char *response = params->msg ? params->msg : "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
        uint32_t written = 0;
        
        ret = HITLS_Write(ctx, (const uint8_t *)response, strlen(response), &written);
        if (ret == HITLS_SUCCESS) {
            if (!params->quiet) {
                AppPrintInfo("Sent %u bytes response to client\n", written);
            }
        } else {
            AppPrintError("Failed to send response: 0x%x\n", ret);
        }
    } else if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to read client data: 0x%x\n", ret);
    }
    
    return HITLS_APP_SUCCESS;
}

static void CleanupConnection(HITLS_Ctx *ctx, BSL_UIO *uio, int client_fd)
{
    if (ctx) {
        HITLS_Close(ctx);
        HITLS_Free(ctx);
    }
    
    if (uio) {
        BSL_UIO_Free(uio);
    }
    
    if (client_fd >= 0) {
        BSL_SAL_SockClose(client_fd);
    }
}

int ServerMainLoop(HITLS_Config *config, int listen_fd, HITLS_ServerParams *params)
{
    if (config == NULL || listen_fd < 0 || params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    int connections = 0;
    APP_ProtocolType protocol = ParseProtocolType(params->protocol);
    
    if (!params->quiet) {
        AppPrintInfo("Server started, waiting for connections...\n");
    }
    
    while (1) {
        int client_fd = -1;
        BSL_UIO *uio = NULL;
        HITLS_Ctx *ctx = NULL;
        
        /* Accept connection */
        if (protocol == APP_PROTOCOL_DTLS12) {
            /* For DTLS, we use the same socket for communication */
            client_fd = listen_fd;
        } else {
            client_fd = AcceptTCPConnection(listen_fd);
            if (client_fd < 0) {
                continue;
            }
        }
        
        /* Create UIO and TLS context */
        uio = CreateServerUIO(client_fd, params);
        ctx = HITLS_New(config);
        
        if (uio == NULL || ctx == NULL) {
            AppPrintError("Failed to create UIO or TLS context\n");
            CleanupConnection(ctx, uio, (protocol != APP_PROTOCOL_DTLS12) ? client_fd : -1);
            continue;
        }
        
        int ret = HITLS_SetUio(ctx, uio);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to set UIO: 0x%x\n", ret);
            CleanupConnection(ctx, uio, (protocol != APP_PROTOCOL_DTLS12) ? client_fd : -1);
            continue;
        }
        
        /* Handle client connection */
        ret = HandleClientConnection(ctx, params);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("Failed to handle client connection\n");
        }
        
        CleanupConnection(ctx, uio, (protocol != APP_PROTOCOL_DTLS12) ? client_fd : -1);
        
        connections++;
        
        if (!params->quiet) {
            AppPrintInfo("Connection %d completed\n", connections);
        }
        
        /* Check if we should exit */
        if (params->accept_once || 
            (params->max_connections > 0 && connections >= params->max_connections)) {
            if (!params->quiet) {
                AppPrintInfo("Reached connection limit, exiting\n");
            }
            break;
        }
        
        /* For DTLS, we don't need to loop for more connections in this simple implementation */
        if (protocol == APP_PROTOCOL_DTLS12) {
            break;
        }
    }
    
    return HITLS_APP_SUCCESS;
}

void CleanupServerResources(HITLS_Config *config, int listen_fd, HITLS_ServerParams *params)
{
    if (config) {
        HITLS_CFG_FreeConfig(config);
    }
    
    if (listen_fd >= 0) {
        BSL_SAL_SockClose(listen_fd);
    }
    
    if (params) {
        CleanupServerParams(params);
    }
}

int HITLS_ServerMain(int argc, char *argv[])
{
    HITLS_ServerParams params = {0};
    HITLS_Config *config = NULL;
    int listen_fd = -1;
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
    ret = ParseServerOptions(argc, argv, &params);
    if (ret != HITLS_APP_SUCCESS) {
        if (ret == HITLS_APP_HELP_PRINTED) {
            ret = HITLS_APP_SUCCESS;
        }
        goto cleanup;
    }
    
    /* Run as daemon if requested */
    if (params.daemon) {
        if (daemon(0, 0) != 0) {
            AppPrintError("Failed to daemonize: %s\n", strerror(errno));
            ret = HITLS_APP_ERR_DAEMON;
            goto cleanup;
        }
    }
    
    /* Create TLS configuration */
    config = CreateServerConfig(&params);
    if (config == NULL) {
        AppPrintError("Failed to create TLS configuration\n");
        ret = HITLS_APP_ERR_CREATE_CONFIG;
        goto cleanup;
    }
    
    /* Create listening socket */
    listen_fd = CreateListenSocket(&params);
    if (listen_fd < 0) {
        AppPrintError("Failed to create listening socket\n");
        ret = HITLS_APP_ERR_LISTEN;
        goto cleanup;
    }
    
    /* Handle SIGCHLD for child processes */
    signal(SIGCHLD, SIG_IGN);
    
    /* Enter main server loop */
    ret = ServerMainLoop(config, listen_fd, &params);
    
cleanup:
    CleanupServerResources(config, listen_fd, &params);
    
    if (!params.quiet && ret == HITLS_APP_SUCCESS) {
        AppPrintInfo("Server completed successfully\n");
    }
    
    /* Cleanup print UIO */
    AppPrintInfoUioUnInit();
    AppPrintErrorUioUnInit();
    
    return ret;
}