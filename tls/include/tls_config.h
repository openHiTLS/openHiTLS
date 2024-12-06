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

#ifndef TLS_CONFIG_H
#define TLS_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include "hitls_build.h"
#include "hitls_cert_type.h"
#include "hitls_cert.h"
#include "hitls_debug.h"
#include "hitls_config.h"
#include "hitls_session.h"
#include "hitls_psk.h"
#include "hitls_security.h"
#include "hitls_sni.h"
#include "hitls_alpn.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup config
 * @brief   Certificate management context
 */
typedef struct CertMgrCtxInner CERT_MgrCtx;

typedef struct TlsSessionManager TLS_SessionMgr;

/**
* @ingroup  config
* @brief    DTLS 1.0
*/
#define HITLS_VERSION_DTLS10 0xfeffu

#define HITLS_TICKET_KEY_NAME_SIZE  16u
#define HITLS_TICKET_KEY_SIZE       32u
#define HITLS_TICKET_IV_SIZE  16u

/* the default number of tickets of TLS1.3 server is 2 */
#define HITLS_TLS13_TICKET_NUM_DEFAULT 2u
#define HITLS_MAX_EMPTY_RECORDS 32
/* max cert list is 100k */
#define HITLS_MAX_CERT_LIST_DEFAULT (1024 * 100)

/**
 * @brief   TLS Global Configuration
 */
typedef struct TlsConfig {
    BSL_SAL_RefCount references;        /* reference count */
    uint32_t version;                   /* supported proto version */
    uint32_t originVersionMask;         /* the original supported proto version mask */
    uint16_t minVersion;                /* min supported proto version */
    uint16_t maxVersion;                /* max supported proto version */

    uint16_t *tls13CipherSuites;        /* tls13 cipher suite */
    uint32_t tls13cipherSuitesSize;
    uint16_t *cipherSuites;             /* cipher suite */
    uint32_t cipherSuitesSize;
    uint8_t *pointFormats;              /* ec point format */
    uint32_t pointFormatsSize;
    /* According to RFC 8446 4.2.7, before TLS 1.3 is ec curves; TLS 1.3: supported groups for the key exchange */
    uint16_t *groups;
    uint32_t groupsSize;
    uint16_t *signAlgorithms;           /* signature algorithm */
    uint32_t signAlgorithmsSize;

    uint8_t *alpnList;                  /* application layer protocols list */
    uint32_t alpnListSize;              /* bytes of alpn, excluding the tail 0 byte */

    HITLS_SecurityCb securityCb;        /* Security callback */
    void *securityExData;               /* Security ex data */
    int32_t securityLevel;              /* Security level */

    uint8_t *serverName;                /* server name */
    uint32_t serverNameSize;            /* server name size */

    int32_t readAhead;                  /* need read more data into user buffer, nonzero indicates yes, otherwise no */
    uint32_t emptyRecordsNum;           /* the max number of empty records can be received */

    /* TLS1.2 psk */
    uint8_t *pskIdentityHint;           /* psk identity hint */
    uint32_t hintSize;
    HITLS_PskClientCb pskClientCb;      /* psk client callback */
    HITLS_PskServerCb pskServerCb;      /* psk server callback */

    /* TLS1.3 psk */
    HITLS_PskFindSessionCb pskFindSessionCb;    /* TLS1.3 PSK server callback */
    HITLS_PskUseSessionCb pskUseSessionCb;      /* TLS1.3 PSK client callback */

    HITLS_CRYPT_Key *dhTmp;             /* Temporary DH key set by the user */
    HITLS_DhTmpCb dhTmpCb;              /* Temporary ECDH key set by the user */

    HITLS_InfoCb infoCb;                /* information indicator callback */
    HITLS_MsgCb msgCb;                  /* message callback function cb for observing all SSL/TLS protocol messages */
    void *msgArg;                       /*  set argument arg to the callback function */

    HITLS_RecordPaddingCb  recordPaddingCb; /* the callback to specify the padding for TLS 1.3 records */
    void *recordPaddingArg;                 /* assign a value arg that is passed to the callback */

    uint32_t keyExchMode;               /* TLS1.3 psk exchange mode */

    uint32_t maxCertList;               /* the maximum size allowed for the peer's certificate chain */

    HITLS_TrustedCAList *caList;        /* the list of CAs sent to the peer */
    CERT_MgrCtx *certMgrCtx;            /* certificate management context */

    uint32_t sessionIdCtxSize;                            /* the size of sessionId context */
    uint8_t sessionIdCtx[HITLS_SESSION_ID_CTX_MAX_SIZE];  /* the sessionId context */

    uint32_t ticketNums;                /* TLS1.3 ticket number */
    TLS_SessionMgr *sessMgr;            /* session management */

    void *userData;                     /* user data */
    HITLS_ConfigUserDataFreeCb userDataFreeCb;

    bool needCheckKeyUsage;             /* whether to check keyusage, default on */
    bool needCheckPmsVersion;           /* whether to verify the version in premastersecret */
    bool isSupportRenegotiation;        /* support renegotiation */
    bool allowClientRenegotiate;      /* allow a renegotiation initiated by the client */
    bool allowLegacyRenegotiate;        /* whether to abort handshake when server doesn't support SecRenegotiation */
    bool isResumptionOnRenego;          /* supports session resume during renegotiation */
    bool isSupportDhAuto;               /* the DH parameter to be automatically selected */

    /* Certificate Verification Mode */
    bool isSupportClientVerify;         /* Enable dual-ended authentication. only for server */
    bool isSupportNoClientCert;         /* Authentication Passed When Client Sends Empty Certificate. only for server */
    bool isSupportPostHandshakeAuth;    /* TLS1.3 support post handshake auth. for server and client */
    bool isSupportVerifyNone;           /* The handshake will be continued regardless of the verification result.
                                           for server and client */
    bool isSupportClientOnceVerify;     /* only request a client certificate once during the connection.
                                           only for server */

    bool isQuietShutdown;               /* is support the quiet shutdown mode */
    bool isEncryptThenMac;              /* is EncryptThenMac on */
    bool isFlightTransmitEnable;        /* sending of handshake information in one flighttransmit */

    bool isSupportExtendMasterSecret;   /* is support extended master secret */
    bool isSupportSessionTicket;        /* is support session ticket */
    bool isSupportServerPreference;     /* server cipher suites can be preferentially selected */

    /* DTLS */
    bool isHelloVerifyReqEnable;    /* is HelloVerifyRequest message enabled on server */

    /**
     * Configurations in the HITLS_Ctx are classified into private configuration and global configuration.
     * The following parameters directly reference the global configuration in tls.
     * Private configuration: ctx->config.tlsConfig
     * The global configuration: ctx->globalConfig
     * Modifying the globalConfig will affects all associated HITLS_Ctx
    */
    HITLS_AlpnSelectCb alpnSelectCb;    /* alpn callback */
    void *alpnUserData;                 /* the user data for alpn callback */
    void *sniArg;			            /* the args for servername callback */
    HITLS_SniDealCb sniDealCb;          /* server name callback function */
    HITLS_ClientHelloCb clientHelloCb;          /* ClientHello callback */
    void *clientHelloCbArg;                     /* the args for ClientHello callback */
#ifdef HITLS_TLS_PROTO_DTLS12
    HITLS_CookieGenerateCb cookieGenerateCb;
    HITLS_CookieVerifyCb cookieVerifyCb;
#endif
    HITLS_NewSessionCb newSessionCb;    /* negotiates to generate a session */
    HITLS_KeyLogCb keyLogCb;            /* the key log callback */
    bool isKeepPeerCert;                /* whether to save the peer certificate */
} TLS_Config;

#ifdef __cplusplus
}
#endif

#endif // TLS_CONFIG_H
