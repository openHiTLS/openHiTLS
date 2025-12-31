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
#include "hitls_cookie.h"
#include "hitls_alpn.h"
#include "sal_atomic.h"
#ifdef HITLS_TLS_FEATURE_PROVIDER
#include "crypt_eal_provider.h"
#endif

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
#ifdef HITLS_TLS_FEATURE_MAX_SEND_FRAGMENT
#define HITLS_MAX_SEND_FRAGMENT_DEFAULT 16384
#endif
/* max cert list is 100k */
#define HITLS_MAX_CERT_LIST_DEFAULT (1024 * 100)

#define HITLS_ENDPOINT_UNDEFINED 0
#define HITLS_ENDPOINT_CLIENT 1
#define HITLS_ENDPOINT_SERVER 2

/**
 * @brief Group information
 */
typedef struct {
    char *name;                 // group name
    int32_t paraId;             // parameter id CRYPT_PKEY_ParaId
    int32_t algId;              // algorithm id CRYPT_PKEY_AlgId
    int32_t secBits;            // security bits
    uint16_t groupId;           // iana group id, HITLS_NamedGroup
    uint32_t pubkeyLen;         // public key length(CH keyshare / SH keyshare)
    uint32_t sharedkeyLen;      // shared key length
    uint32_t ciphertextLen;     // ciphertext length(SH keyshare)
    uint32_t versionBits;       // TLS_VERSION_MASK
    bool isKem;                 // true: KEM, false: KEX
} TLS_GroupInfo;

/**
 * @brief Signature scheme information
 */
typedef struct {
    char *name;
    uint16_t signatureScheme; // HITLS_SignHashAlgo, IANA specified
    int32_t keyType;          // HITLS_CERT_KeyType
    int32_t paraId;           // CRYPT_PKEY_ParaId
    int32_t signHashAlgId;    // combined sign hash algorithm id
    int32_t signAlgId;        // CRYPT_PKEY_AlgId
    int32_t hashAlgId;        // CRYPT_MD_AlgId
    int32_t secBits;          // security bits
    uint32_t certVersionBits;      // TLS_VERSION_MASK
    uint32_t chainVersionBits; // TLS_VERSION_MASK
} TLS_SigSchemeInfo;

#ifdef HITLS_TLS_FEATURE_PROVIDER
/**
 * @brief   TLS capability data
 */
typedef struct {
    HITLS_Config *config;
    CRYPT_EAL_ProvMgrCtx *provMgrCtx;
} TLS_CapabilityData;
#define TLS_CAPABILITY_LIST_MALLOC_SIZE 10
#endif

typedef struct CustomExtMethods HITLS_CustomExts;

/**
 * @brief   TLS Global Configuration
 */
typedef struct TlsConfig {
    BSL_SAL_RefCount references;        /* reference count */
    HITLS_Lib_Ctx *libCtx;          /* library context */
    const char *attrName;              /* attrName */
#ifdef HITLS_TLS_FEATURE_PROVIDER
    TLS_GroupInfo *groupInfo;
    uint32_t groupInfolen;
    uint32_t groupInfoSize;
    TLS_SigSchemeInfo *sigSchemeInfo;
    uint32_t sigSchemeInfolen;
    uint32_t sigSchemeInfoSize;
#endif
    uint32_t endpoint;                  /* client or server */
    uint32_t version;                   /* supported proto version */
    uint32_t originVersionMask;         /* the original supported proto version mask */
    uint16_t minVersion;                /* min supported proto version */
    uint16_t maxVersion;                /* max supported proto version */
    uint32_t modeSupport;               /* support mode */

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

    HITLS_DtlsTimerCb dtlsTimerCb;      /* DTLS get the timeout callback */
    uint32_t dtlsPostHsTimeoutVal;      /* DTLS over UDP completed handshake timeout */

    HITLS_CRYPT_Key *dhTmp;             /* Temporary DH key set by the user */
    HITLS_DhTmpCb dhTmpCb;              /* the callback for generating the DH key */

    HITLS_InfoCb infoCb;                /* information indicator callback */
    HITLS_MsgCb msgCb;                  /* message callback function cb for observing all SSL/TLS protocol messages */
    void *msgArg;                       /*  set argument arg to the callback function */

    HITLS_RecordPaddingCb recordPaddingCb; /* the callback to specify the padding for TLS 1.3 records */
    void *recordPaddingArg;                 /* assign a value arg that is passed to the callback */

    uint32_t keyExchMode;               /* TLS1.3 psk exchange mode */

    uint32_t maxCertList;               /* the maximum size allowed for the peer's certificate chain */

    HITLS_TrustedCAList *caList;        /* the list of CAs sent to the peer */
    CERT_MgrCtx *certMgrCtx;            /* certificate management context */

    uint32_t sessionIdCtxSize;                            /* the size of sessionId context */
    uint8_t sessionIdCtx[HITLS_SESSION_ID_CTX_MAX_SIZE];  /* the sessionId context */

    uint32_t ticketNums;                /* TLS1.3 ticket number */
    uint16_t maxSendFragment;           /* max send fragment to restrict the amount of plaintext bytes in any record */
    uint32_t recInbufferSize;           /* Rec inbuffer inital size */
    TLS_SessionMgr *sessMgr;            /* session management */

    void *userData;                     /* user data */
    HITLS_ConfigUserDataFreeCb userDataFreeCb;

    uint16_t recordSizeLimit;           /* record size limit RFC 8449 */

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
    /* DTLS */
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    bool isSupportDtlsCookieExchange;    /* is dtls support cookie exchange */
#endif
    bool isFlightTransmitEnable;        /* sending of handshake information in one flighttransmit */

    bool isSupportExtendMasterSecret;   /* is support extended master secret */
    bool isSupportSessionTicket;        /* is support session ticket */
    bool isSupportServerPreference;     /* server cipher suites can be preferentially selected */

    /*
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
    HITLS_AppVerifyCookieCb appVerifyCookieCb; /* the callback to verify the cookie */
    HITLS_AppGenCookieCb appGenCookieCb;       /* the callback to generate the cookie */
    HITLS_ClientHelloCb clientHelloCb;          /* ClientHello callback */
    void *clientHelloCbArg;                     /* the args for ClientHello callback */
    HITLS_NewSessionCb newSessionCb;    /* negotiates to generate a session */
    HITLS_SessionRemoveCb sessionRemoveCb; /* session removal callback */
    HITLS_SessionGetCb sessionGetCb;       /* obtains a session based on the session ID */
    uint8_t *sessionTicketExt;
    uint32_t sessionTicketExtSize;
    HITLS_SessionTicketExtProcessCb sessionTicketExtCb;
    void *sessionTicketExtCbArg;
    HITLS_KeyLogCb keyLogCb;            /* the key log callback */
    bool isKeepPeerCert;                /* whether to save the peer certificate */
    bool isMiddleBoxCompat;             /* whether to support middlebox compatibility */

    HITLS_CustomExts *customExts;
} TLS_Config;

#define LIBCTX_FROM_CONFIG(config) (((config) == NULL) ? NULL : (config)->libCtx)
#define ATTRIBUTE_FROM_CONFIG(config) (((config) == NULL) ? NULL : (config)->attrName)

#ifdef __cplusplus
}
#endif

#endif // TLS_CONFIG_H
