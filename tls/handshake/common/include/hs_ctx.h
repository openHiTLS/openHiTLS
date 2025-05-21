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

#ifndef HS_CTX_H
#define HS_CTX_H

#include <stdint.h>
#include "hitls_build.h"
#include "sal_time.h"
#include "hitls_cert_type.h"
#include "hitls_crypt_type.h"
#include "cert.h"
#include "crypt.h"
#include "rec.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MASTER_SECRET_LEN 48u
#define HS_PSK_IDENTITY_MAX_LEN 128u /* Maximum length of PSK-negotiated identity information */
#define HS_PSK_MAX_LEN 256u
#define COOKIE_SECRET_LIFETIME 5u /* the number of times the cookie's secret is used */

/* Transmits ECDH key exchange data */
typedef struct {
    HITLS_ECParameters curveParams; /* Elliptic curve parameter */
} EcdhParam;

/* Transmits DH key exchange data */
typedef struct {
    uint8_t *p;    /* prime */
    uint8_t *g;    /* generator */
    uint16_t plen; /* prime length */
    uint16_t glen; /* generator length */
} DhParam;

/* Used to transfer RSA key exchange data */
typedef struct {
    uint8_t preMasterSecret[MASTER_SECRET_LEN];
} RsaParam;

/* Used to transfer Ecc key exchange data */
typedef struct {
    uint8_t preMasterSecret[MASTER_SECRET_LEN];
} EccParam;

typedef struct {
    /* For TLS1.3 multi-key share, we try to send two key shares:
     * - One for key encapsulation mechanism (KEM)
     * - One for key exchange (KEX) */
    HITLS_NamedGroup group;        /* First group for key share */
    HITLS_NamedGroup secondGroup;  /* Second group for key share */
} KeyShareParam;

/**
 * @ingroup hitls
 *
 * @brief   PskInfo is used for PSK negotiation and stores identity and psk during negotiation
 */
#ifdef HITLS_TLS_FEATURE_PSK
typedef struct {
    uint8_t *identity;
    uint32_t identityLen;
    uint8_t *psk;
    uint32_t pskLen;
} PskInfo;
#endif /* HITLS_TLS_FEATURE_PSK */
#ifdef HITLS_TLS_PROTO_TLS13
typedef struct {
    uint8_t *identity;
    uint32_t identityLen;
    HITLS_Session *pskSession;
    uint8_t num;
} UserPskList;

typedef struct {
    UserPskList *userPskSess;     /* tls 1.3 user psk session */
    HITLS_Session *resumeSession; /* tls 1.3 psk resume */
    int32_t selectIndex;          /* selected index */
    uint8_t *psk;                 /* selected psk */
    uint32_t pskLen;
} PskInfo13;
#endif /* HITLS_TLS_PROTO_TLS13 */

/* Used to transfer the key exchange context */
typedef struct {
    HITLS_KeyExchAlgo keyExchAlgo;
    union {
        EcdhParam ecdh;
        DhParam dh;
        RsaParam rsa;
        EccParam ecc; /* Sm2 parameter */
        KeyShareParam share;
    } keyExchParam;
    HITLS_CRYPT_Key *key; /* Local key pair */
    HITLS_CRYPT_Key *secondKey; /* second key pair for tls1.3 multi-key share */
    uint8_t *peerPubkey; /* peer public key or peer ciphertext */
    uint32_t pubKeyLen; /* peer public key length */
#ifdef HITLS_TLS_FEATURE_PSK
    PskInfo *pskInfo;     /* PSK data tls 1.2 */
#endif /* HITLS_TLS_FEATURE_PSK */
#ifdef HITLS_TLS_PROTO_TLS13
    PskInfo13 pskInfo13; /* tls 1.3 psk */
    uint8_t *ciphertext; /* local ciphertext */
    uint32_t ciphertextLen; /* ciphertext length */
#endif /* HITLS_TLS_PROTO_TLS13 */
} KeyExchCtx;

/* Buffer for transmitting handshake data. */
typedef struct HsMsgCache {
    uint8_t *data;
    uint32_t dataSize;
    struct HsMsgCache *next;
} HsMsgCache;

/* Used to transfer the handshake data verification context. */
typedef struct {
    HITLS_HashAlgo hashAlgo;
    HITLS_HASH_Ctx *hashCtx;
    uint8_t verifyData[MAX_SIGN_SIZE];
    uint32_t verifyDataSize;
    HsMsgCache *dataBuf; /* handshake data buffer */
} VerifyCtx;

/* Used to pass the handshake context */
struct HsCtx {
    HITLS_HandshakeState state;
    ExtensionFlag extFlag;
#ifdef HITLS_TLS_PROTO_TLS13
    HITLS_HandshakeState ccsNextState;
    bool haveHrr; /* Whether the hello retry request has been processed */
#endif
    bool isNeedClientCert;
#if defined(HITLS_TLS_FEATURE_SESSION) || defined(HITLS_TLS_PROTO_TLS13)
    uint32_t sessionIdSize;
    uint8_t *sessionId;
#endif
    uint8_t *clientRandom;
    uint8_t *serverRandom;
#ifdef HITLS_TLS_PROTO_TLS13
    uint8_t earlySecret[MAX_DIGEST_SIZE];
    uint8_t handshakeSecret[MAX_DIGEST_SIZE];
#endif
    uint8_t masterKey[MAX_DIGEST_SIZE];
    CERT_Pair *peerCert;
#ifdef HITLS_TLS_FEATURE_ALPN
    uint8_t *clientAlpnList;
    uint32_t clientAlpnListSize;
#endif
#ifdef HITLS_TLS_FEATURE_SNI
    uint8_t *serverName;
    uint32_t serverNameSize;
#endif
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    uint32_t ticketSize;
    uint8_t *ticket;
    uint32_t ticketLifetimeHint; /* ticket timeout interval, in seconds */
#ifdef HITLS_TLS_PROTO_TLS13
    uint32_t ticketAgeAdd; /* Used to obfuscate ticket age */

    uint64_t nextTicketNonce; /* TLS1.3 connection, starting from 0 and increasing in ascending order */
    uint32_t sentTickets;     /* TLS1.3 Number of tickets sent */
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
    KeyExchCtx *kxCtx;    /* Key Exchange Context */
    VerifyCtx *verifyCtx; /* Verify the context of handshake data. */
    uint8_t *msgBuf;      /* Buffer for receiving and sending messages */
    uint32_t msgOffset;   /* messages offset */
    uint32_t bufferLen;   /* messages buffer size */
    uint32_t msgLen;      /* Total length of buffered messages */
#ifdef HITLS_TLS_PROTO_TLS13
    uint8_t clientHsTrafficSecret[MAX_DIGEST_SIZE]; /* Handshake secret used to encrypt the message sent by the TLS1.3
                                                       client */
    uint8_t serverHsTrafficSecret[MAX_DIGEST_SIZE]; /* Handshake secret used to encrypt the message sent by the TLS1.3
                                                       server */
    ClientHelloMsg *firstClientHello;               /* TLS1.3 server records the first received ClientHello message */
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_PROTO_DTLS12
    uint16_t nextSendSeq;    /* message sending sequence number */
    uint16_t expectRecvSeq;  /* message receiving sequence number */
    HS_ReassQueue *reassMsg; /* reassembly message queue, used for reassembly of fragmented messages */

    /* To reduce the calculation amount for determining timeout, use the end time instead of the start time. If the end
     * time is exceeded, the receiving times out. */
    BSL_TIME deadline;     /* End time */
    uint32_t timeoutValue; /* Timeout interval, in us. */
    uint32_t timeoutNum;   /* Timeout count */
#endif /* HITLS_TLS_PROTO_DTLS12 */

#if defined(HITLS_TLS_PKEY_SPAKE2P)
    CRYPT_EAL_PkeyCtx *pake_ctx; /* Context for PAKE operations (e.g., SPAKE2+) */
    uint8_t pake_client_confirmation_mac[MAX_DIGEST_SIZE]; /* Stores client's computed PAKE MAC */
    uint32_t pake_client_confirmation_mac_len;
    uint8_t pake_server_confirmation_mac[MAX_DIGEST_SIZE]; /* Stores server's computed PAKE MAC */
    uint32_t pake_server_confirmation_mac_len;
    uint32_t pake_ke_len; /* Stores the actual length of the derived PAKE shared secret Ke */
#endif
};

#ifdef __cplusplus
}
#endif /* end __cplusplus */
#endif /* end HS_CTX_H */