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

#ifndef HS_MSG_H
#define HS_MSG_H

#include <stdint.h>
#include <stdbool.h>
#include "hitls_build.h"
#include "bsl_module_list.h"
#include "cert.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HS_MSG_HEADER_SIZE 4u
#define DTLS_HS_MSG_HEADER_SIZE 12u
#define HS_RANDOM_SIZE 32u
#define HS_RANDOM_DOWNGRADE_SIZE 8u
#define TLS_HS_MAX_SESSION_ID_SIZE 32u
#define TLS_HS_MIN_SESSION_ID_SIZE 24u
#define TLS_HS_MIN_COOKIE_SIZE 1u
#define TLS_HS_MAX_COOKIE_SIZE 255u

#define DTLS_HS_MSGLEN_ADDR 1u /* DTLS message length address, which is used when parsing the DTLS message header. */
/* DTLS message sequence number address, which is used for parsing the DTLS message header. */
#define DTLS_HS_MSGSEQ_ADDR 4u
/* DTLS message fragment offset address, which is used when the DTLS message header is parsed. */
#define DTLS_HS_FRAGMENT_OFFSET_ADDR 6u
/* DTLS message fragment length address, which is used when parsing the DTLS message header. */
#define DTLS_HS_FRAGMENT_LEN_ADDR 9u

/* Handshake message type */
typedef enum {
    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    HELLO_VERIFY_REQUEST = 3,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA = 5,
    HELLO_RETRY_REQUEST = 6,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20,
    CERTIFICATE_URL = 21,
    CERTIFICATION_STATUS = 22,
    SUPPLEMENTAL_DATA = 23,
    KEY_UPDATE = 24,
    /* PAKE specific messages, if they are new top-level handshake messages */
    /* Values chosen to be distinct from existing standard messages. */
    PAKE_CLIENT_MESSAGE = 60, /* draft-bmw-tls-pake13 ClientPakeMessage */
    PAKE_SERVER_MESSAGE = 61, /* draft-bmw-tls-pake13 ServerPakeMessage */
    MESSAGE_HASH = 254,
    HS_MSG_TYPE_END = 255
} HS_MsgType;

typedef enum {
    PSK_KE = 0,
    PSK_DHE_KE = 1,
    PSK_KEY_EXCHANGEMODE_END = 255
} HS_PskKeyExchMode;

typedef struct {
    HITLS_KeyUpdateRequest requestUpdate;
} KeyUpdateMsg;

typedef struct {
    ListHead head;
    uint16_t group; /* Naming group of keys to be exchanged */
    uint16_t keyExchangeSize;
    uint8_t *keyExchange; /* Key exchange information */
} KeyShare;

typedef struct OfferedPsks {
    ListHead pskNode;  /* Multiple PSK linked lists are formed through pskNode. The actual data of this node is the
                          following fields */
    uint8_t *identity; /* pskid and binder are in one-to-one mapping. */
    uint8_t *binder;   /* HMAC value */
    uint32_t obfuscatedTicketAge; /* An obfuscated version of the age of the key */
    uint16_t identitySize;        /* bytes of identity */
    uint8_t binderSize;           /* bytes of binder */
    bool isValid;                 /* is binder valid */
} PreSharedKey;

typedef struct {
    uint16_t *supportedGroups;
    uint16_t *signatureAlgorithms;
    uint16_t *signatureAlgorithmsCert;
    uint8_t *pointFormats;
    uint8_t *alpnList;      /* application-layer protocol negotiation list */
    uint8_t *serverName;    /* serverName after parsing */
    uint8_t *secRenegoInfo; /* renegotiation extension information */
    uint8_t *ticket;        /* ticket information */

    uint32_t ticketSize;
    uint16_t supportedGroupsSize;
    uint16_t signatureAlgorithmsSize;
    uint16_t signatureAlgorithmsCertSize;
    uint16_t alpnListSize; /* application-layer protocol negotiation list len */
    uint16_t serverNameSize;
    uint8_t pointFormatsSize;
    uint8_t serverNameType;    /* Type of the parsed serverName. */
    uint8_t secRenegoInfoSize; /* Length of the security renegotiation information */
    uint8_t reserved[1];       /* Four-byte alignment */

    /* TLS1.3 */
    uint16_t *supportedVersions;
    uint8_t *cookie;
    uint8_t *keModes;
    uint8_t keModesSize;
    uint8_t supportedVersionsCount; /* Number of supported version */
    uint16_t cookieLen;

    HITLS_TrustedCAList *caList;
    PreSharedKey *preSharedKey;
    KeyShare *keyShare; /* In the ClientHello message, this extension provides a set of KeyShares */
} ExtensionContent;

typedef struct {
    bool haveSupportedGroups;
    bool haveSignatureAlgorithms;
    bool haveSignatureAlgorithmsCert;
    bool havePointFormats;
    bool haveExtendedMasterSecret;
    bool haveSupportedVers;
    bool haveCookie;        /* Whether there is a cookie (involved in TLS1.3 ClientHello) */
    bool haveCA;            /* Whether the CA exists (involved in TLS1.3 ClientHello) */
    bool havePostHsAuth;    /* Indicates whether the Client (TLS1.3) is willing to receive the Certificate Request
                               message. */
    bool haveKeyShare;
    bool haveEarlyData;
    bool havePskExMode;      /* Indicates whether the TLS1.3 key exchange mode exists. */
    bool havePreShareKey;    /* Indicates whether the pre-shared key exists. */
    bool haveAlpn;           /* Whether there is Alpn */
    bool haveServerName;     /* Whether the ServerName extension exists. */
    bool haveSecRenego;      /* Whether security renegotiation exists. */
    bool haveTicket;         /* Indicates whether a ticket is available. */
    bool haveEncryptThenMac; /* Indicates whether EncryptThenMac is supported. */
} ExtensionFlag;

typedef struct {
    ExtensionFlag flag;
    ExtensionContent content;
} ClientHelloExt;

/* It is used to transmit client hello message */
typedef struct {
    uint8_t randomValue[HS_RANDOM_SIZE]; /* random number group */
    uint8_t *sessionId;
    uint8_t *cookie; /* Cookie (for DTLS only) */
    uint16_t *cipherSuites;
    uint16_t version;
    uint16_t cipherSuitesSize;
    uint8_t sessionIdSize;
    uint8_t compressionMethodsSize;
    uint8_t *compressionMethods;
    uint8_t cookieLen;
    bool haveScsvCipher; /* According to RFC 5746, a special signaling cipher suite value (SCSV) can be used to indicate
                            that security renegotiation is supported. */
    uint8_t refCnt;      /* Do not involve multiple threads. Process the hrr check clientHello. */
    uint32_t truncateHelloLen; /* is used for binder calculation. */
    ClientHelloExt extension;
    uint64_t extensionTypeMask;
} ClientHelloMsg;

/* It is used to transmit server hello message */
typedef struct {
    uint16_t version;
    uint16_t cipherSuite;
    uint8_t randomValue[HS_RANDOM_SIZE]; /* random number group */
    uint8_t *sessionId;
    uint8_t *pointFormats;
    uint8_t *alpnSelected; /* selected alpn protocol */
    uint8_t *cookie;
    uint8_t *secRenegoInfo;
    KeyShare keyShare;
    uint16_t alpnSelectedSize; /* selected alpn protocol length */
    uint16_t supportedVersion;
    uint16_t cookieLen;
    uint16_t selectedIdentity; /* TLS 1.3 psk required */
    uint8_t sessionIdSize;
    uint8_t pointFormatsSize;
    uint8_t secRenegoInfoSize; /* Length of the security renegotiation information */
    uint64_t extensionTypeMask;
    bool havePointFormats;
    bool haveExtendedMasterSecret;
    bool haveSupportedVersion;
    bool haveCookie;           /* Indicates whether the cookie length is involved in TLS1.3 HelloRetryRequest. */
    bool haveKeyShare;         /* Whether KeyShare is extended. */
    bool haveSelectedIdentity; /* Indicates whether the Pre_PSK is selected. */
    bool haveSelectedAlpn;     /* Whether the application layer protocol is selected. */
    bool haveServerName;
    bool haveSecRenego;
    bool haveTicket;
    bool haveEncryptThenMac;
    bool reserved[2]; /* Four-byte alignment */
} ServerHelloMsg;

/* It is used to transmit hello verify request message */
typedef struct {
    uint16_t version;
    uint8_t cookieLen;
    uint8_t reserved[1]; /* fill with 1 byte for 4-byte alignment */
    uint8_t *cookie;
} HelloVerifyRequestMsg;

/* Transmits certificate message */
typedef struct {
    CERT_Item *cert;                /* Certificate message content */
    uint32_t certCount;             /* Number of certificates */
    uint8_t *certificateReqCtx;     /* Used by the TLS 1.3 */
    uint32_t certificateReqCtxSize; /* Used by the TLS 1.3 */
    uint64_t extensionTypeMask;     /* Used by the TLS 1.3 */
} CertificateMsg;

typedef struct {
    HITLS_ECParameters ecPara; /* Elliptic curve field parameter of the ECDH public key */
    uint32_t pubKeySize;       /* Length of the ecdh public key */
    uint8_t *pubKey;           /* ecdh public key content */
    uint16_t signAlgorithm;
    uint16_t signSize;
    uint8_t *signData;
} ServerEcdh;
typedef struct {
    uint8_t *p;
    uint8_t *g;
    uint16_t plen;
    uint16_t glen;
    uint8_t *pubkey;
    uint16_t pubKeyLen;
    uint16_t signAlgorithm;
    uint16_t signSize;
    uint8_t *signData;
} ServerDh;

/* Used to transfer the key exchange content of the server */
typedef struct {
    uint8_t *pskIdentityHint; /* psk identity negotiation prompt message */
    uint32_t hintSize;
    HITLS_KeyExchAlgo keyExType; /* key exchange mode */
    union {
        ServerEcdh ecdh;
        ServerDh dh;
    } keyEx;
} ServerKeyExchangeMsg;

/* Used to transfer the client key exchange content */
typedef struct {
    uint8_t *pskIdentity;
    uint32_t pskIdentitySize;
    uint32_t dataSize; /* Key exchange data length */
    uint8_t *data;     /* Key exchange data. */
} ClientKeyExchangeMsg;

/* Transmits certificate request message */
typedef struct {
    uint8_t *certTypes;
    uint16_t *signatureAlgorithms;
    uint8_t reserved;               /* Four-byte alignment */
    uint8_t certTypesSize;
    uint16_t signatureAlgorithmsSize;
    HITLS_TrustedCAList *caList;
#ifdef HITLS_TLS_PROTO_TLS13
    uint16_t *signatureAlgorithmsCert;
    uint16_t signatureAlgorithmsCertSize;
    uint8_t *certificateReqCtx;     /* Used by the TLS 1.3 */
    uint32_t certificateReqCtxSize; /* This field is used by the TLS 1.3. The value is not 0 only for the
                                       authentication after the handshake */
    uint64_t extensionTypeMask;
    bool haveSignatureAndHashAlgoCert;
#endif /* HITLS_TLS_PROTO_TLS13 */
    bool haveSignatureAndHashAlgo;
    bool haveDistinguishedName;
} CertificateRequestMsg;

/* Transmits certificate verification message */
typedef struct {
    uint16_t signHashAlg; /* Signature hash algorithm, which is available only for TLS1.2 and DTLS1.2 */
    uint16_t signSize;    /* Length of the signature data. */
    uint8_t *sign;        /* Signature data */
} CertificateVerifyMsg;

/* It is used to transmit Ticket message
    RFC5077 3.3 NewSessionTicket Handshake Message
      struct {
          uint32 ticket_lifetime_hint;
          opaque ticket<0..2^16-1>;
      } NewSessionTicket;

    TLS1.3:
    struct {
        uint32 ticket_lifetime;
        uint32 ticket_age_add;
        opaque ticket_nonce<0..255>;
        opaque ticket<1..2^16-1>;
        Extension extensions<0..2^16-2>;
    } NewSessionTicket;
*/
typedef struct {
    uint32_t ticketLifetimeHint; /* ticket timeout interval, in seconds */
    uint32_t ticketAgeAdd;       /* ticket_age_add: a random number generated each time a ticket is issued. */
    uint32_t ticketNonceSize;    /* ticket_nonce length */
    uint8_t *ticketNonce;        /* ticketNonce: Unique ID of the ticket issued on the connection, starting from 0 and
                                    increasing in ascending order. */
    uint32_t ticketSize;
    uint8_t *ticket; /* ticket */
    uint64_t extensionTypeMask;
} NewSessionTicketMsg;

/* It is used to transmit finish message */
typedef struct {
    uint32_t verifyDataSize;
    uint8_t *verifyData;
} FinishedMsg;

typedef struct {
    uint16_t *supportedGroups;
    uint16_t supportedGroupsSize;
    uint16_t alpnSelectedSize; /* selected alpn protocol length */
    uint8_t *alpnSelected; /* selected alpn protocol */
    uint64_t extensionTypeMask;

    bool haveSupportedGroups;
    bool haveEarlyData;
    bool haveServerName;
    bool haveSelectedAlpn;
} EncryptedExtensions;

/* Used to parse the handshake message header. */
typedef struct {
    HS_MsgType type;
    uint32_t length;    /* handshake msg body length */
    uint16_t sequence; /* DTLS Indicates the number of the handshake message. Each time a new handshake message is
                          sent, one is added. Retransmission does not add up */
    uint32_t fragmentOffset; /* Fragment offset of DTLS handshake message */
    uint32_t fragmentLength; /* Fragment length of the DTLS handshake message */
    const uint8_t *rawMsg;   /* Complete handshake information */
    uint32_t headerAndBodyLen;
} HS_MsgInfo;

/* It is used to transmit handshake message */
typedef struct {
    HS_MsgType type;
    uint32_t length;
    uint16_t sequence;       /* DTLS Indicates the number of the handshake message. Each time a new handshake message is
                          sent, one is added. Retransmission does not add up */
    uint8_t reserved[2];     /* fill 2 bytes for 4-byte alignment. */
    uint32_t fragmentOffset; /* Fragment offset of DTLS handshake message. */
    uint32_t fragmentLength; /* Fragment length of the DTLS handshake message */
    union {
        ClientHelloMsg clientHello;
        ServerHelloMsg serverHello;
        HelloVerifyRequestMsg helloVerifyReq;
        EncryptedExtensions encryptedExtensions;
        CertificateMsg certificate;
        ClientKeyExchangeMsg clientKeyExchange;
        ServerKeyExchangeMsg serverKeyExchange;
        CertificateRequestMsg certificateReq;
        CertificateVerifyMsg certificateVerify;
        NewSessionTicketMsg newSessionTicket;
        FinishedMsg finished;
        KeyUpdateMsg keyUpdate;
#if defined(HITLS_TLS_PKEY_SPAKE2P)
        PakeClientMessage pakeClientMsg;
        PakeServerMessage pakeServerMsg;
#endif
    } body;
} HS_Msg;

#ifdef HITLS_TLS_PROTO_DTLS12
/* Reassembles fragmented messages */
typedef struct {
    ListHead head;
    HS_MsgType type;
    uint16_t sequence;    /* DTLS Indicates the number of the handshake message. Each time a new handshake message is
                    sent, one is added. Retransmission does not add up */
    bool isReassComplete; /* Indicates whether the message is reassembled. */
    uint8_t reserved;     /* Padded with 1 byte for 4-byte alignment. */
    uint8_t *reassBitMap; /* bitmap, used for processing duplicate fragmented message and calculating whether the
                             fragmented message are completely reassembled. */
    uint8_t *msg;         /* Used to store the handshake messages during the reassembly. */
    uint32_t msgLen;      /* Total length of a message, including the message header. */
} HS_ReassQueue;
#endif

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end HS_MSG_H */
