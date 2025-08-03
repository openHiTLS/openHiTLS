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

#ifndef HITLS_APP_ERRNO_H
#define HITLS_APP_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_APP_SUCCESS 0

// The return value of HITLS APP ranges from 0, 1, 3 to 125.
// 3 to 125 are external error codes.
enum HITLS_APP_ERROR {
    HITLS_APP_HELP = 0x1,              /* *< the subcommand has the help option */
    HITLS_APP_SECUREC_FAIL,            /* *< error returned by the safe function */
    HITLS_APP_MEM_ALLOC_FAIL,          /* *< failed to apply for memory resources */
    HITLS_APP_INVALID_ARG,             /* *< invalid parameter */
    HITLS_APP_INTERNAL_EXCEPTION,
    HITLS_APP_ENCODE_FAIL,             /* *< encodeing  failure */
    HITLS_APP_CRYPTO_FAIL,
    HITLS_APP_PASSWD_FAIL,
    HITLS_APP_UIO_FAIL,
    HITLS_APP_STDIN_FAIL,              /* *< incorrect stdin input */
    HITLS_APP_INFO_CMP_FAIL,           /* *< failed to match the received information with the parameter */
    HITLS_APP_INVALID_DN_TYPE,
    HITLS_APP_INVALID_DN_VALUE,
    HITLS_APP_INVALID_GENERAL_NAME_TYPE,
    HITLS_APP_INVALID_GENERAL_NAME,
    HITLS_APP_INVALID_IP,
    HITLS_APP_ERR_CONF_GET_SECTION,
    HITLS_APP_NO_EXT,

    HITLS_APP_INIT_FAILED,
    HITLS_APP_COPY_ARGS_FAILED,

    HITLS_APP_OPT_UNKOWN,              /* *< option error */
    HITLS_APP_OPT_NAME_INVALID,        /* *< the subcommand name is invalid */
    HITLS_APP_OPT_VALUETYPE_INVALID,   /* *< the parameter type of the subcommand is invalid */
    HITLS_APP_OPT_TYPE_INVALID,        /* *< the subcommand type is invalid */
    HITLS_APP_OPT_VALUE_INVALID,       /* *< the subcommand parameter value is invalid */

    HITLS_APP_DECODE_FAIL,             /* *< decoding failure */
    HITLS_APP_CERT_VERIFY_FAIL,        /* *< certificate verification failed */
    HITLS_APP_X509_FAIL,               /* *< x509-related error. */
    HITLS_APP_SAL_FAIL,                /* *< sal-related error. */
    HITLS_APP_BSL_FAIL,                /* *< bsl-related error. */
    HITLS_APP_CONF_FAIL,               /* *< conf-related error. */

    HITLS_APP_LOAD_CERT_FAIL,          /* *< Failed to load the cert. */
    HITLS_APP_LOAD_CSR_FAIL,           /* *< Failed to load the csr. */
    HITLS_APP_LOAD_KEY_FAIL,           /* *< Failed to load the public and private keys. */
    HITLS_APP_ENCODE_KEY_FAIL,         /* *< Failed to encode the public and private keys. */

    /* TLS Client/Server specific errors */
    HITLS_APP_ERR_PARSE_OPT,           /* *< Failed to parse command line options */
    HITLS_APP_ERR_CREATE_CONFIG,       /* *< Failed to create TLS configuration */
    HITLS_APP_ERR_CREATE_CTX,          /* *< Failed to create TLS context */
    HITLS_APP_ERR_SET_UIO,             /* *< Failed to set UIO */
    HITLS_APP_ERR_CONNECT,             /* *< Failed to connect to server */
    HITLS_APP_ERR_LISTEN,              /* *< Failed to create listening socket */
    HITLS_APP_ERR_HANDSHAKE,           /* *< TLS handshake failed */
    HITLS_APP_ERR_SEND_DATA,           /* *< Failed to send data */
    HITLS_APP_ERR_RECV_DATA,           /* *< Failed to receive data */
    HITLS_APP_ERR_DAEMON,              /* *< Failed to daemonize */
    HITLS_APP_ERR_SET_CIPHER,          /* *< Failed to set cipher suites */
    HITLS_APP_ERR_SET_SIGNATURE,       /* *< Failed to set signature algorithms */
    HITLS_APP_ERR_SET_GROUPS,          /* *< Failed to set curves/groups */
    HITLS_APP_ERR_LOAD_CA,             /* *< Failed to load CA certificate */
    HITLS_APP_ERR_SET_VERIFY,          /* *< Failed to set verification options */
    HITLS_APP_ERR_LOAD_CERT,           /* *< Failed to load certificate */
    HITLS_APP_ERR_LOAD_KEY,            /* *< Failed to load private key */
    HITLS_APP_ERR_SET_CERT,            /* *< Failed to set certificate */
    HITLS_APP_ERR_SET_KEY,             /* *< Failed to set private key */
    HITLS_APP_ERR_SET_TLCP_CERT,       /* *< Failed to set TLCP certificate */
    HITLS_APP_ERR_SET_MTU,             /* *< Failed to set MTU */
    HITLS_APP_ERR_SET_COOKIE,          /* *< Failed to set cookie exchange */
    HITLS_APP_ERR_RESOLVE_HOST,        /* *< Failed to resolve hostname */
    HITLS_APP_HELP_PRINTED,            /* *< Help was printed */

    HITLS_APP_MAX = 126,               /* *< maximum of the error code */
};

#ifdef __cplusplus
}
#endif
#endif