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

#ifndef TLS_H
#define TLS_H

#include <stdint.h>
#include <stdbool.h>
#include "hitls_build.h"
#include "cipher_suite.h"
#include "tls_config.h"
#include "hitls_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DIGEST_SIZE 64UL /* The longest known value is SHA512 */

#define DTLS_DEFAULT_PMTU 1500uL

/* RFC 6083 4.1. Mapping of DTLS Records:
    The supported maximum length of SCTP user messages MUST be at least
    2^14 + 2048 + 13 = 18445 bytes (2^14 + 2048 is the maximum length of
    the DTLSCiphertext.fragment, and 13 is the size of the DTLS record
    header). */
#define DTLS_SCTP_PMTU 18445uL

#define IS_DTLS_VERSION(version) (((version) & 0x8u) == 0x8u)

#define IS_SUPPORT_STREAM(versionBits) (((versionBits) & STREAM_VERSION_BITS) != 0x0u)
#define IS_SUPPORT_DATAGRAM(versionBits) (((versionBits) & DATAGRAM_VERSION_BITS) != 0x0u)
#define IS_SUPPORT_TLCP(versionBits) (((versionBits) & TLCP_VERSION_BITS) != 0x0u)
#define IS_SUPPORT_TLS(versionBits) (((versionBits) & TLS_VERSION_MASK) != 0x0u)

#define MAC_KEY_LEN 32u              /* the length of mac key */

#define UNPROCESSED_APP_MSG_COUNT_MAX 50       /* number of APP data cached */

#define RANDOM_SIZE 32u                   /* the size of random number */

typedef struct TlsCtx TLS_Ctx;
typedef struct HsCtx HS_Ctx;
typedef struct CcsCtx CCS_Ctx;
typedef struct AlertCtx ALERT_Ctx;
typedef struct RecCtx REC_Ctx;

typedef enum {
    CCS_CMD_RECV_READY,                 /* CCS allowed to be received */
    CCS_CMD_RECV_EXIT_READY,            /* CCS cannot be received */
    CCS_CMD_RECV_ACTIVE_CIPHER_SPEC,    /* CCS active change cipher spec */
} CCS_Cmd;

/* Check whether the CCS message is received */
typedef bool (*IsRecvCcsCallback)(const TLS_Ctx *ctx);
/* Send a CCS message */
typedef int32_t (*SendCcsCallback)(TLS_Ctx *ctx);
/* Control the CCS */
typedef int32_t (*CtrlCcsCallback)(TLS_Ctx *ctx, CCS_Cmd cmd);

typedef enum {
    ALERT_LEVEL_WARNING = 1,
    ALERT_LEVEL_FATAL = 2,
    ALERT_LEVEL_UNKNOWN = 255,
} ALERT_Level;

typedef enum {
    ALERT_CLOSE_NOTIFY = 0,
    ALERT_UNEXPECTED_MESSAGE = 10,
    ALERT_BAD_RECORD_MAC = 20,
    ALERT_DECRYPTION_FAILED = 21,
    ALERT_RECORD_OVERFLOW = 22,
    ALERT_DECOMPRESSION_FAILURE = 30,
    ALERT_HANDSHAKE_FAILURE = 40,
    ALERT_NO_CERTIFICATE_RESERVED = 41,
    ALERT_BAD_CERTIFICATE = 42,
    ALERT_UNSUPPORTED_CERTIFICATE = 43,
    ALERT_CERTIFICATE_REVOKED = 44,
    ALERT_CERTIFICATE_EXPIRED = 45,
    ALERT_CERTIFICATE_UNKNOWN = 46,
    ALERT_ILLEGAL_PARAMETER = 47,
    ALERT_UNKNOWN_CA = 48,
    ALERT_ACCESS_DENIED = 49,
    ALERT_DECODE_ERROR = 50,
    ALERT_DECRYPT_ERROR = 51,
    ALERT_EXPORT_RESTRICTION_RESERVED = 60,
    ALERT_PROTOCOL_VERSION = 70,
    ALERT_INSUFFICIENT_SECURITY = 71,
    ALERT_INTERNAL_ERROR = 80,
    ALERT_INAPPROPRIATE_FALLBACK = 86,
    ALERT_USER_CANCELED = 90,
    ALERT_NO_RENEGOTIATION = 100,
    ALERT_MISSING_EXTENSION = 109,
    ALERT_UNSUPPORTED_EXTENSION = 110,
    ALERT_CERTIFICATE_UNOBTAINABLE = 111,
    ALERT_UNRECOGNIZED_NAME = 112,
    ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    ALERT_BAD_CERTIFICATE_HASH_VALUE = 114,
    ALERT_UNKNOWN_PSK_IDENTITY = 115,
    ALERT_CERTIFICATE_REQUIRED = 116,
    ALERT_NO_APPLICATION_PROTOCOL = 120,
    ALERT_UNKNOWN = 255
} ALERT_Description;

/** Connection management state */
typedef enum {
    CM_STATE_IDLE,
    CM_STATE_HANDSHAKING,
    CM_STATE_TRANSPORTING,
    CM_STATE_RENEGOTIATION,
    CM_STATE_ALERTING,
    CM_STATE_ALERTED,
#ifdef HITLS_TLS_PROTO_CLOSE_STATE
    CM_STATE_CLOSED,
#endif
    CM_STATE_END
} CM_State;

/** post-handshake auth */
typedef enum {
    PHA_NONE,           /* not support pha */
    PHA_EXTENSION,      /* pha extension send or received */
    PHA_PENDING,        /* try to send certificate request */
    PHA_REQUESTED       /* certificate request has been sent or received */
} PHA_State;

/* Describes the handshake status */
typedef enum {
    TLS_IDLE,                       /* initial state */
    TLS_CONNECTED,                  /* Handshake succeeded */
    TRY_SEND_HELLO_REQUEST,         /* sends hello request message */
    TRY_SEND_CLIENT_HELLO,          /* sends client hello message */
    TRY_SEND_HELLO_VERIFY_REQUEST,  /* sends hello verify request message */
    TRY_SEND_HELLO_RETRY_REQUEST,   /* sends hello retry request message */
    TRY_SEND_SERVER_HELLO,          /* sends server hello message */
    TRY_SEND_ENCRYPTED_EXTENSIONS,  /* sends encrypted extensions message */
    TRY_SEND_CERTIFICATE,           /* sends certificate message */
    TRY_SEND_SERVER_KEY_EXCHANGE,   /* sends server key exchange message */
    TRY_SEND_CERTIFICATE_REQUEST,   /* sends certificate request message */
    TRY_SEND_SERVER_HELLO_DONE,     /* sends server hello done message */
    TRY_SEND_CLIENT_KEY_EXCHANGE,   /* sends client key exchange message */
    TRY_SEND_CERTIFICATE_VERIFY,    /* sends certificate verify message */
    TRY_SEND_NEW_SESSION_TICKET,    /* sends new session ticket message */
    TRY_SEND_CHANGE_CIPHER_SPEC,    /* sends change cipher spec message */
    TRY_SEND_END_OF_EARLY_DATA,     /* sends end of early data message */
    TRY_SEND_FINISH,                /* sends finished message */
    TRY_SEND_KEY_UPDATE,            /* sends keyupdate message */
    TRY_RECV_CLIENT_HELLO,          /* attempts to receive client hello message */
    TRY_RECV_HELLO_VERIFY_REQUEST,  /* attempts to receive hello verify request message */
    TRY_RECV_SERVER_HELLO,          /* attempts to receive server hello message */
    TRY_RECV_ENCRYPTED_EXTENSIONS,  /* attempts to receive encrypted extensions message */
    TRY_RECV_CERTIFICATE,           /* attempts to receive certificate message */
    TRY_RECV_SERVER_KEY_EXCHANGE,   /* attempts to receive server key exchange message */
    TRY_RECV_CERTIFICATE_REQUEST,   /* attempts to receive certificate request message */
    TRY_RECV_SERVER_HELLO_DONE,     /* attempts to receive server hello done message */
    TRY_RECV_CLIENT_KEY_EXCHANGE,   /* attempts to receive client key exchange message */
    TRY_RECV_CERTIFICATE_VERIFY,    /* attempts to receive certificate verify message */
    TRY_RECV_NEW_SESSION_TICKET,    /* attempts to receive new session ticket message */
    TRY_RECV_END_OF_EARLY_DATA,     /* attempts to receive end of early data message */
    TRY_RECV_FINISH,                /* attempts to receive finished message */
    TRY_RECV_KEY_UPDATE,            /* attempts to receive keyupdate message */
    TRY_RECV_HELLO_REQUEST,         /* attempts to receive hello request message */
    HS_STATE_BUTT = 255             /* enumerated Maximum Value */
} HITLS_HandshakeState;

typedef enum {
    TLS_PROCESS_STATE_A,
    TLS_PROCESS_STATE_B
} HitlsProcessState;

typedef void (*SendAlertCallback)(const TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description);

typedef void (*ClearAlertCallBack)(TLS_Ctx *ctx, uint32_t recordType);

typedef bool (*GetAlertFlagCallback)(const TLS_Ctx *ctx);

typedef int32_t (*UnexpectMsgHandleCallback)(TLS_Ctx *ctx, uint32_t msgType, const uint8_t *data, uint32_t dataLen,
    bool isPlain);

/** Connection management configure */
typedef struct TLSCtxConfig {
    void *userData;                         /* user data */
    uint16_t linkMtu;                       /* Maximum transport unit of a path (bytes),
                                               including IP header and udp/tcp header */
    uint16_t pmtu;                          /* Maximum transport unit of a path (bytes) */

    bool isSupportPto;                      /* is support process based TLS offload */
    uint8_t reserved[1];                    /* four-byte alignment */

    TLS_Config tlsConfig;                   /* tls configure context */
} TLS_CtxConfig;

typedef struct {
    uint32_t algRemainTime;            /* current key usage times */
    uint8_t preMacKey[MAC_KEY_LEN];    /* previous random key */
    uint8_t macKey[MAC_KEY_LEN];       /* random key used by the current algorithm */
} CookieInfo;

typedef struct {
    uint16_t version;                              /* negotiated version */
    uint16_t clientVersion;                        /* version field of client hello */
    uint32_t cookieSize;                           /* cookie length */
    uint8_t *cookie;                               /* cookie data */
    CookieInfo cookieInfo;                         /* cookie info with calculation and verification */
    CipherSuiteInfo cipherSuiteInfo;               /* cipher suite info */
    HITLS_SignHashAlgo signScheme;                 /* sign algorithm used by the local */
    uint8_t *alpnSelected;                         /* alpn proto */
    uint32_t alpnSelectedSize;
    uint8_t clientVerifyData[MAX_DIGEST_SIZE];     /* client verify data */
    uint8_t serverVerifyData[MAX_DIGEST_SIZE];     /* server verify data */
    uint8_t clientRandom[RANDOM_SIZE];             /* client random number */
    uint8_t serverRandom[RANDOM_SIZE];             /* server random number */
    uint32_t clientVerifyDataSize;                 /* client verify data size */
    uint32_t serverVerifyDataSize;                 /* server verify data size */
    uint32_t renegotiationNum;                     /* the number of renegotiation */
    uint32_t certReqSendTime;                      /* certificate request sending times */
    uint32_t tls13BasicKeyExMode;                   /* TLS13_KE_MODE_PSK_ONLY || TLS13_KE_MODE_PSK_WITH_DHE ||
                                                      TLS13_CERT_AUTH_WITH_DHE */

    uint16_t negotiatedGroup;                      /* negotiated group */
    uint16_t recordSizeLimit;                      /* read record size limit */
    uint16_t renegoRecordSizeLimit;
    uint16_t peerRecordSizeLimit;                  /* write record size limit */
    bool isResume;                                 /* whether to resume the session */
    bool isRenegotiation;                          /* whether to renegotiate */

    bool isSecureRenegotiation;                    /* whether security renegotiation */
    bool isExtendedMasterSecret;                   /* whether to calculate the extended master sercret */
    bool isEncryptThenMac;                         /* Whether to enable EncryptThenMac */
    bool isEncryptThenMacRead;                     /* Whether to enable EncryptThenMacRead */
    bool isEncryptThenMacWrite;                    /* Whether to enable EncryptThenMacWrite */
    bool isTicket;                                 /* whether to negotiate tickets, only below tls1.3 */
    bool isSniStateOK;                             /* Whether server successfully processes the server_name callback */
#ifdef HITLS_TLS_FEATURE_SNI
    uint8_t *serverName;
    uint32_t serverNameSize;
#endif
} TLS_NegotiatedInfo;

typedef struct {
    uint16_t *groups;                   /* all groups sent by the peer end */
    uint32_t groupsSize;                /* size of a group */
    uint16_t *cipherSuites;             /* all cipher suites sent by the peer end */
    uint16_t cipherSuitesSize;          /* size of a cipher suites */
    HITLS_SignHashAlgo peerSignHashAlg; /* peer signature algorithm */
    uint16_t *signatureAlgorithms;
    uint16_t signatureAlgorithmsSize;
    HITLS_ERROR verifyResult;           /* record the certificate verification result of the peer end */
    HITLS_TrustedCAList *caList;        /* peer trusted ca list */
} PeerInfo;

struct TlsCtx {
    bool isClient;                          /* is Client */
    bool userShutDown;                      /* record whether the local end invokes the HITLS_Close */
    bool userRenego;                        /* record whether the local end initiates renegotiation */
    uint8_t rwstate;                        /* record the current internal read and write state */
    CM_State preState;
    CM_State state;

    uint32_t shutdownState;                 /* Record the shutdown state */

    void *rUio;                             /* read uio */
    void *uio;                              /* write uio */
    void *bUio;                             /* Storing uio */
    HS_Ctx *hsCtx;                          /* handshake context */
    CCS_Ctx *ccsCtx;                        /* ChangeCipherSpec context */
    ALERT_Ctx *alertCtx;                    /* alert context */
    REC_Ctx *recCtx;                        /* record context */
    struct {
        IsRecvCcsCallback isRecvCCS;
        SendCcsCallback sendCCS;            /* send a CCS message */
        CtrlCcsCallback ctrlCCS;            /* controlling CCS */
        SendAlertCallback sendAlert;        /* set the alert message to be sent */
        ClearAlertCallBack clearAlert;      /* Clear the number of consecutive received warnings */
        GetAlertFlagCallback getAlertFlag;  /* get alert state */
        UnexpectMsgHandleCallback unexpectedMsgProcessCb;   /* the callback for unexpected messages */
    } method;

    PeerInfo peerInfo;                      /* Temporarily save the messages sent by the peer end */
    TLS_CtxConfig config;                   /* private configuration */
    TLS_Config *globalConfig;               /* global configuration */
    TLS_NegotiatedInfo negotiatedInfo;      /* TLS negotiation information */
    HITLS_Session *session;                 /* session information */

    uint8_t clientAppTrafficSecret[MAX_DIGEST_SIZE];   /* TLS1.3 client app traffic secret */
    uint8_t serverAppTrafficSecret[MAX_DIGEST_SIZE];   /* TLS1.3 server app traffic secret */
    uint8_t resumptionMasterSecret[MAX_DIGEST_SIZE];   /* TLS1.3 session resume secret */
    uint8_t exporterMasterSecret[MAX_DIGEST_SIZE];     /* TLS1.3 export the master secret */

    uint32_t bytesLeftToRead;               /* bytes left to read after hs header has parsed */
    uint32_t keyUpdateType;                 /* TLS1.3 key update type */
    bool isKeyUpdateRequest;                /* TLS1.3 Check whether there are unsent key update messages */
    bool haveClientPointFormats;            /* whether the EC point format extension in the client hello is processed */
    uint8_t peekFlag;                       /* peekFlag equals 0, read mode; otherwise, peek mode */
    bool hasParsedHsMsgHeader;              /* has parsed current hs msg header */
    int32_t errorCode;                      /* Record the tls error code */

    HITLS_HASH_Ctx *phaHash;                /* tls1.3 pha: Handshake main process hash */
    HITLS_HASH_Ctx *phaCurHash;             /* tls1.3 pha: Temporarily store the current pha hash */
    PHA_State phaState;                     /* tls1.3 pha state */
    uint8_t *certificateReqCtx;             /* tls1.3 pha certificate_request_context */
    uint32_t certificateReqCtxSize;         /* tls1.3 pha certificate_request_context */
    bool isDtlsListen;
    bool plainAlertForbid;                  /* tls1.3 forbid to receive plain alert message */
    bool allowAppOut;                       /* whether user used HITLS_read to start renegotiation */
    bool noQueryMtu;                        /* Don't query the mtu from bio */
    bool needQueryMtu;                      /* whether need query mtu from bio */
    bool mtuModified;                       /* whether mtu has been modified */
};

typedef struct {
    uint8_t **buf;       // &hsCtx->msgbuf
    uint32_t *bufLen;    // &hsCtx->bufferLen
    uint32_t *bufOffset; // &hsCtx->msgLen
} PackPacket;

#define LIBCTX_FROM_CTX(ctx) (((ctx) == NULL) ? NULL : (ctx)->config.tlsConfig.libCtx)
#define ATTRIBUTE_FROM_CTX(ctx) (((ctx) == NULL) ? NULL : (ctx)->config.tlsConfig.attrName)

#define CUSTOM_EXT_FROM_CTX(ctx) (((ctx) == NULL) ? NULL : (ctx)->config.tlsConfig.customExts)

#define GET_VERSION_FROM_CTX(ctx) \
    ((ctx)->negotiatedInfo.version > 0 ? (ctx)->negotiatedInfo.version : (ctx)->config.tlsConfig.maxVersion)

#ifdef __cplusplus
}
#endif

#endif /* TLS_H */
