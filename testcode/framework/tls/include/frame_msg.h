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

#ifndef FRAME_MSG_H
#define FRAME_MSG_H

#include <stdint.h>
#include "hs_msg.h"
#include "rec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Used to determine the field status during packing */
typedef enum {
    /* field is missing. If this state is set, the field will not be packed into the buffer during packing */
    MISSING_FIELD = 0,
    /* field initial status. The field status in the parsed msg structure is filled with the value. */
    INITIAL_FIELD,
    /* Specifies the value of the field. If the field content is modified, set the status to the value. */
    ASSIGNED_FIELD,
    /* Repeat the field. During the packing, the field will be packed again */
    DUPLICATE_FIELD,
    /* Only one byte length is packed and used to construct abnormal messages.
    It is used for two or more bytes of fields (such as the cipher suite length). */
    SET_LEN_TO_ONE_BYTE,
} FieldState;

// uint64_t data with status
typedef struct {
    FieldState state; /* Field state */
    uint64_t data;    /* Content */
} FRAME_Integer;

// uint8_t data with status
typedef struct {
    FieldState state; /* Field state */
    uint32_t size;    /* Number of data records */
    uint8_t *data;    /* Content */
} FRAME_Array8;

// uint16_t data with status
typedef struct {
    FieldState state; /* Field state */
    uint32_t size;    /* Number of data records */
    uint16_t *data;   /* Content */
} FRAME_Array16;

typedef struct {
    FieldState exState;        /* extension Field state */
    FRAME_Integer exType;      /* extension type */
    FRAME_Integer exLen;       /* Full length of extension */
    FRAME_Integer exDataLen;   /* Length of extension content */
    FRAME_Array8 exData;       /* extension content */
} FRAME_HsExtArray8;

// The handshake extension with state carries a variable-length array with uint16_t
// such as the signature algorithm extension
typedef struct {
    FieldState exState;         /* extension Field state */
    FRAME_Integer exType;       /* extension type */
    FRAME_Integer exLen;        /* Full length of extension */
    FRAME_Integer exDataLen;    /* Length of extension content */
    FRAME_Array16 exData;       /* extension content */
} FRAME_HsExtArray16;

typedef struct {
    FieldState state;             /* Field state */
    FRAME_Integer group;          /* group */
    FRAME_Integer keyExchangeLen; /* key exchange size */
    FRAME_Array8 keyExchange;
} FRAME_HsKeyShareEntry;

typedef struct {
    FieldState state;            /* Field state */
    uint32_t size;               /* Number of entries */
    FRAME_HsKeyShareEntry *data; /* key shareContent */
} FRAME_HsArrayKeyShare;

typedef struct {
    FieldState exState;                /* extension Field state */
    FRAME_Integer exType;              /* extension type */
    FRAME_Integer exLen;               /* Full length of extension */
    FRAME_Integer exKeyShareLen;       /* keyshare Array length */
    FRAME_HsArrayKeyShare exKeyShares; /* keyshare array content */
} FRAME_HsExtKeyShare;

typedef struct {
    FieldState state; /* Field state */
    FRAME_Integer identityLen;
    FRAME_Array8 identity;
    FRAME_Integer obfuscatedTicketAge;
} FRAME_HsPskIdentity;

typedef struct {
    FieldState state;          /* Field state */
    uint32_t size;             /* Number of identities */
    FRAME_HsPskIdentity *data; /* identity Content */
} FRAME_HsArrayPskIdentity;

typedef struct {
    FieldState state; /* Field state */
    FRAME_Integer binderLen;
    FRAME_Array8 binder;
} FRAME_HsPskBinder;

typedef struct {
    FieldState state;          /* Field state */
    uint32_t size;             /* Number of identities */
    FRAME_HsPskBinder *data; /* identity Content */
} FRAME_HsArrayPskBinder;

typedef struct {
    FieldState exState;   /* extension Field state */
    FRAME_Integer exType; /* extension type */
    FRAME_Integer exLen;  /* Full length of extension */
    FRAME_Integer identitySize;
    FRAME_HsArrayPskIdentity identities;
    FRAME_Integer binderSize;
    FRAME_HsArrayPskBinder binders;
} FRAME_HsExtOfferedPsks;

typedef struct {
    FieldState exState;         /* extension Field state */
    FRAME_Integer exType;       /* extension type */
    FRAME_Integer exLen;        /* Full length of extension */
    FRAME_Integer data;         /* extension content */
} FRAME_HsExtUint16;

typedef struct {
    FieldState exState;   /* extension Field state */
    FRAME_Integer exType; /* extension type */
    FRAME_Integer exLen;  /* Full length of extension */
    FRAME_Array8 list;  /* CA list */
    FRAME_Integer listSize; /* CA list length */
} FRAME_HsExtCaList;

typedef struct {
    FRAME_Integer version;               /* Version number */
    FRAME_Array8 randomValue;            /* Random number */
    FRAME_Integer sessionIdSize;         /* session ID length */
    FRAME_Array8 sessionId;              /* session ID */
    FRAME_Integer cookiedLen;            /* Cookie length (for DTLS) */
    FRAME_Array8 cookie;                 /* cookie(for DTLS) */
    FRAME_Integer cipherSuitesSize;      /* cipher suite length */
    FRAME_Array16 cipherSuites;          /* cipher suite */
    FRAME_Integer compressionMethodsLen; /* compression method length */
    FRAME_Array8 compressionMethods;     /* compression method */

    FieldState extensionState;              /* Indicates whether the extension is packed */
    FRAME_Integer extensionLen;             /* Total length of the extension */
    FRAME_HsExtArray8 pointFormats;
    FRAME_HsExtArray16 supportedGroups;
    FRAME_HsExtArray16 signatureAlgorithms;
    FRAME_HsExtArray8 encryptThenMac;
    FRAME_HsExtArray8 extendedMasterSecret;
    FRAME_HsExtArray8 secRenego;            /* security renegotiation */
    FRAME_HsExtArray8 sessionTicket;
    FRAME_HsExtArray8 serverName;           /* sni */
    FRAME_HsExtUint16 recordSizeLimit;
    FRAME_HsExtArray8 alpn;                 /* alpn */
    FRAME_HsExtArray8 tls13Cookie;           /* tls1.3 cookie */
    FRAME_HsExtKeyShare keyshares;          /* tls1.3 key share */
    FRAME_HsExtArray8 pskModes;             /* tls1.3 psk exchange mode */
    FRAME_HsExtArray16 supportedVersion;     /* tls1.3 support version */
    FRAME_HsExtOfferedPsks psks;            /* tls1.3 psk */
    FRAME_HsExtCaList caList;
} FRAME_ClientHelloMsg;

typedef struct {
    FieldState exState;         /* extension Field state */
    FRAME_Integer exType;       /* extension type */
    FRAME_Integer exLen;        /* Full length of extension */
    FRAME_HsKeyShareEntry data; /* extension content */
} FRAME_HsExtServerKeyShare;

typedef struct {
    FRAME_Integer version;                  /* Version number */
    FRAME_Array8 randomValue;               /* Random number */
    FRAME_Integer sessionIdSize;            /* session ID length */
    FRAME_Array8 sessionId;                 /* session ID */
    FRAME_Integer cipherSuite;
    FRAME_Integer compressionMethod;
    FRAME_Integer extensionLen;             /* Full length of the extended field */
    FRAME_HsExtArray8 pointFormats;
    FRAME_HsExtArray8 extendedMasterSecret;
    FRAME_HsExtArray8 secRenego;            /* security renegotiation */
    FRAME_HsExtArray8 sessionTicket;        /* sessionTicket */
    FRAME_HsExtArray8 serverName;           /* sni */
    FRAME_HsExtUint16 recordSizeLimit;
    FRAME_HsExtArray8 alpn;                 /* alpn */
    FRAME_HsExtUint16 supportedVersion;     /* tls1.3 supported version */
    FRAME_HsExtServerKeyShare keyShare;     /* tls1.3 key share */
    FRAME_HsExtUint16 pskSelectedIdentity;  /* tls1.3 psk extension */
    FRAME_HsExtArray8 tls13Cookie;          /* tls1.3 cookie */
    FRAME_HsExtArray8 encryptThenMac;
} FRAME_ServerHelloMsg;

typedef struct {
    FRAME_Array8 extra; /* server hello done is a null message. This field is used to construct abnormal messages */
} FRAME_ServerHelloDoneMsg;

typedef struct FrameCertItem_ {
    FieldState state;        /* Certificate Field state */
    FRAME_Integer certLen;   /* Certificate length */
    FRAME_Array8 cert;       /* Certificate Content */
    FRAME_Integer extensionLen;   /* Certificate extension length. only for tls1.3 */
    FRAME_Array8 extension;       /* Certificate extension Content. only for tls1.3 */
    struct FrameCertItem_ *next;
} FrameCertItem;

typedef struct {
    FRAME_Integer certsLen;   /* Certificate total length */
    FrameCertItem *certItem;  /* Certificate */
    FRAME_Array8 certificateReqCtx;        /* For TLS 1.3 */
    FRAME_Integer certificateReqCtxSize;   /* For TLS 1.3 */
} FRAME_CertificateMsg;

typedef struct {
    FRAME_Integer curveType;     /* Curve type */
    FRAME_Integer namedcurve;    /* Named curve */
    FRAME_Integer pubKeySize;    /* ecdh public key size */
    FRAME_Array8 pubKey;         /* ecdh public key content */
    FRAME_Integer signAlgorithm; /* Signature hash algorithm, for TLS1.2 and DTLS1.2 */
    FRAME_Integer signSize;      /* Signature length */
    FRAME_Array8 signData;       /* Signature Content */
} FRAME_ServerEcdh;

typedef struct {
    FRAME_Integer plen;
    FRAME_Array8 p;
    FRAME_Integer glen;
    FRAME_Array8 g;
    FRAME_Integer pubKeyLen;     /* dh public key */
    FRAME_Array8 pubKey;         /* dH public key content */
    FRAME_Integer signAlgorithm; /* Signature hash algorithm, for TLS1.2 and DTLS1.2 */
    FRAME_Integer signSize;      /* Signature length */
    FRAME_Array8 signData;       /* Signature content */
} FRAME_ServerDh;

typedef struct {
    union {
        FRAME_ServerEcdh ecdh;
        FRAME_ServerDh dh;
    } keyEx;
} FRAME_ServerKeyExchangeMsg;

typedef struct {
    FRAME_Integer pubKeySize;     /* Key exchange data length */
    FRAME_Array8 pubKey;          /* Key exchange data */
} FRAME_ClientKeyExchangeMsg;

typedef struct {
    FieldState state;                        /* Field state */
    FRAME_Integer certTypesSize;             /* certificate type length */
    FRAME_Array8 certTypes;                  /* Certificate type list */
    FRAME_Integer signatureAlgorithmsSize;   /* signature algorithm length */
    FRAME_Array16 signatureAlgorithms;       /* signature algorithm list */
    FRAME_Integer reserved;                  /* Four-byte alignment */
    FRAME_Integer distinguishedNamesSize;    /* DN length */
    FRAME_Array8 distinguishedNames;         /* DN */
    FRAME_Array8 certificateReqCtx;         /* For TLS 1.3 */
    FRAME_Integer certificateReqCtxSize;    /* For TLS 1.3 */
    FRAME_Integer exMsgLen;
} FRAME_CertificateRequestMsg;

/* Used to transmit certificate verification packets. */
typedef struct {
    FRAME_Integer signHashAlg; /* Signature hash algorithm, used for TLS1.2 and DTLS1.2 */
    FRAME_Integer signSize;    /* Length of the signature data */
    FRAME_Array8 sign;         /* Signature data */
} FRAME_CertificateVerifyMsg;

typedef struct {
    FRAME_Integer ticketLifetime;
    FRAME_Integer ticketAgeAdd;
    FRAME_Integer ticketNonceSize;
    FRAME_Array8 ticketNonce;
    FRAME_Integer ticketSize;
    FRAME_Array8 ticket;
    FRAME_Integer extensionLen;             /* Total length of the extension */
} FRAME_NewSessionTicketMsg;

/* Transmit the Finish message */
typedef struct {
    FRAME_Array8 verifyData;       /* verify data Content */
} FRAME_FinishedMsg;

typedef struct {
    FRAME_Integer type;             /* Handshake type */
    FRAME_Integer length;           /* Length of the handshake message */
    /* Sequence number of DTLS handshake messages. Increases by 1 each time a new handshake message is sent.
     *Does not increase for retransmission */
    FRAME_Integer sequence;
    FRAME_Integer fragmentOffset;   /* Fragment offset of DTLS handshake message */
    FRAME_Integer fragmentLength;   /* DTLS Handshake message Fragment Length */
    union {
        FRAME_ClientHelloMsg clientHello;
        FRAME_ServerHelloMsg serverHello;
        FRAME_CertificateMsg certificate;
        FRAME_ServerKeyExchangeMsg serverKeyExchange;
        FRAME_CertificateRequestMsg certificateReq;
        FRAME_ServerHelloDoneMsg serverHelloDone;
        FRAME_ClientKeyExchangeMsg clientKeyExchange;
        FRAME_CertificateVerifyMsg certificateVerify;
        FRAME_NewSessionTicketMsg newSessionTicket;
        FRAME_FinishedMsg finished;
    } body;
} FRAME_HsMsg;

typedef struct {
    uint8_t level;                   /* To be deleted. The member is not processed because some code uses it */
    uint8_t description;             /* To be deleted. The member is not processed because some code uses it */
    FRAME_Integer alertLevel;        /* Alert level: See ALERT_Level */
    FRAME_Integer alertDescription;  /* Alert description: See ALERT_Description */
    FRAME_Array8 extra;              /* This field is used to construct abnormal messages */
} FRAME_AlertMsg;

typedef struct {
    uint8_t type;            /* To be deleted. The member is not processed because some code uses it */
    FRAME_Integer ccsType;   /* ccs type */
    FRAME_Array8 extra;      /* This field is used to construct abnormal messages */
} FRAME_CcsMsg;

typedef struct {
    char *buffer;           /* To be deleted. The member is not processed because some code uses it */
    uint32_t len;           /* To be deleted. The member is not processed because some code uses it */
    FRAME_Array8 appData;   /* app data */
} FRAME_AppMsg;

typedef struct {
    uint8_t type;       /* To be deleted. The member is not processed because some code uses it */
    uint8_t reverse;    /* To be deleted. The member is not processed because some code uses it */
    uint16_t version;   /* To be deleted. The member is not processed because some code uses it */
    uint16_t bodyLen;   /* To be deleted. The member is not processed because some code uses it */
    BSL_UIO_TransportType transportType;
    uint64_t epochSeq;  /* To be deleted. The member is not processed because some code uses it */

    FRAME_Integer recType;        /* record the message type */
    FRAME_Integer recVersion;     /* record version */
    FRAME_Integer epoch;          /* Counter value that increases each time the password status changes.
                                    This counter is used by DTLS */
    FRAME_Integer sequence;       /* Record message sequence number, for DTLS */
    FRAME_Integer length;         /* Length of the record message */
    union {
        HS_Msg handshakeMsg; /* To be deleted. The member is not processed because some code uses it */
        FRAME_HsMsg hsMsg;
        FRAME_AlertMsg alertMsg;
        FRAME_CcsMsg ccsMsg;
        FRAME_AppMsg appMsg;
    } body;

    uint8_t *buffer; /* To be deleted. The member is not processed because some code uses it */
    uint32_t len;    /* To be deleted. The member is not processed because some code uses it */
} FRAME_Msg;

/* Used to transfer the message type. The framework packs and parses the corresponding message based on the field value
 * of this structure */
typedef struct {
    uint16_t versionType;
    /* To ensure that the memory can be released normally, a value is assigned to the member during parsing */
    REC_Type recordType;
    /* To ensure that the memory can be released normally, a value is assigned to the member during parsing */
    HS_MsgType handshakeType;
    HITLS_KeyExchAlgo keyExType;
    BSL_UIO_TransportType transportType;
} FRAME_Type;

/**
 * @brief    Generate a TLS record byte stream based on the specified parameter of frameType
 * and the field content of the msg structure and save the stream to the buffer

 * @param   frameType [IN] Specified packing parameters
 * @param   msg [IN] Message structure
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Input buffer size
 * @param   usedLen [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_PackMsg(FRAME_Type *frameType, const FRAME_Msg *msg, uint8_t *buffer, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief    Generate tls13 handshake message according to type

 * @param   type [IN] Specified packing parameters
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Input buffer size
 * @param   usedLen [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_GetTls13DisorderHsMsg(HS_MsgType type, uint8_t *buffer, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Generate a TLS record body byte stream based on the specified parameter of frameType
 * and the field content of the msg structure and save the byte stream to the buffer.
 *
 * @param   frameType [IN] Specified packing parameters
 * @param   msg [IN] Message structure
 * @param   buffer [OUT] Returned handshake message
 * @param   bufLen [IN] Input buffer size
 * @param   usedLen [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_PackRecordBody(FRAME_Type *frameType, const FRAME_Msg *msg,
    uint8_t *buffer, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Parse the MSG structure based on the specified parameter of frameType and the TLS record byte stream.
 *          Only the record message header is parsed
 *
 * @param   frameType [IN] Specified parsing parameter, mainly versionType
 * @param   buffer [IN] TLS record byte stream
 * @param   bufLen [IN] Input buffer size
 * @param   msg [OUT] Parsed Message structure
 * @param   parseLen [OUT] Length of the parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_ParseMsgHeader(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
    FRAME_Msg *msg, uint32_t *parseLen);

/**
 * @brief   parse TLS record header
 *
 * @param   buffer [IN] TLS record byte stream
 * @param   bufferLen [IN] Input buffer size
 * @param   msg [OUT] Parsed Message structure
 * @param   headerLen [OUT] Length of the parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_ParseTLSRecordHeader(const uint8_t *buffer, uint32_t bufferLen,
    FRAME_Msg *msg, uint32_t *parseLen);

/**
 * @brief   Parse the body of the TLS non-handshake record
 *
 * @param   buffer [IN] TLS record byte stream
 * @param   bufferLen [IN] Input buffer size
 * @param   msg [OUT] Parsed Message structure
 * @param   headerLen [OUT] Length of the parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_ParseTLSNonHsRecordBody(const uint8_t *buffer, uint32_t bufferLen,
    FRAME_Msg *msg, uint32_t *parseLen);

/**
 * @brief   Parse the TLS non-handshake record
 *
 * @param   buffer [IN] TLS record byte stream
 * @param   bufferLen [IN] Input buffer size
 * @param   msg [OUT] Parsed Message structure
 * @param   headerLen [OUT] Length of the parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_ParseTLSNonHsRecord(const uint8_t *buffer, uint32_t bufferLen,
    FRAME_Msg *msg, uint32_t *parseLen);

/**
 * @brief   Parse the record of the handshake type
 *
 * @param   buffer [IN] TLS record byte stream
 * @param   bufferLen [IN] Input buffer size
 * @param   msg [OUT] Parsed Message structure
 * @param   headerLen [OUT] Length of the parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_ParseHsRecord(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufferLen,
    FRAME_Msg *msg, uint32_t *parseLen);

/**
 * @brief    Parse the MSG structure based on the specified parameter of frameType and the TLS record byte stream.
 *           Only the record message body is parsed
 *
 * @attention Invoke the Frame_ParseMsgHeader interface to parse the message header
 *
 * @param   frameType [IN] Specified parsing parameters, mainly versionType and keyExType
 * @param   buffer [IN] TLS record byte stream
 * @param   bufLen [IN] Input buffer size
 * @param   msg [OUT] Parsed Message structure
 * @param   parseLen [OUT] Length of the parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_ParseMsgBody(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
    FRAME_Msg *msg, uint32_t *parseLen);

/**
 * @brief   Parse the message into the msg structure based on the specified parameter of frameType and
 * the TLS record byte stream
 *
 * @param   frameType [IN] Specified parsing parameters, mainly versionType and keyExType
 * @param   buffer [IN] TLS record byte stream
 * @param   bufLen [IN] Input buffer size
 * @param   msg [OUT] Parsed Message structure
 * @param   parseLen [OUT] Length of the parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_ParseMsg(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
    FRAME_Msg *msg, uint32_t *parseLen);

/**
 * @brief   Clear the memory allocated during parsing
 *
 * @param   frameType [IN] Specified parsing parameters, mainly versionType and keyExType
 * @param   msg [IN] Message structure
 */
void FRAME_CleanMsg(FRAME_Type *frameType, FRAME_Msg *msg);

/**
 * @brief   Clear the memory allocated during parsing
 *
 * @param   recType [IN] Specified record type
 * @param   msg [IN] Message structure
 */
void FRAME_CleanNonHsRecord(REC_Type recType, FRAME_Msg *msg);

/**
 * @brief  Obtain a structure of a specified message type
 *
 * @attention This interface does not set the callback function. User need to set the callback interface first
 *            This interface obtains only the HANDSHAKE,Change_CIPHER_SPEC, and ALERT messages
 *            The existing framework does not support parsing of encrypted finished messages.
 *            Therefore, the finished messages cannot be obtained.
 *
 * @param   frameType [IN] Specified message parameters
 * @param   msg [OUT] Returned Message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_GetDefaultMsg(FRAME_Type *frameType, FRAME_Msg *msg);

/**
 * @brief   Modify a message field
 *          This method is used to modify the contents of integer fields in a message, such as the message type,
 *          version number, and field length
 *
 * @param   data [IN] Data content
 * @param   frameInteger [IN/OUT] IN original field; OUT New field
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_ModifyMsgInteger(const uint64_t data, FRAME_Integer *frameInteger);

/**
 * @brief   Modify the message field content. User can increase or decrease the length of the message field and modify
 *          the field content.
 *          (This implementation performs deep copy of the data content.)
 *          This method is used to modify the content of the uint8_t array field in a message, such as the session ID,
 *          cookie, and signature data
 *
 * @param   data [IN] Data content
 * @param   dataLen [IN] Number of data records
 * @param   frameArray [IN/OUT] IN original field; OUT New field
 * @param   frameArrayLen [IN/OUT] IN Original field length; Length of the new field in the OUT field. This parameter
 *          can be none
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_ModifyMsgArray8(const uint8_t *data, uint32_t dataLen,
    FRAME_Array8 *frameArray, FRAME_Integer *frameArrayLen);

/**
 * @brief   Retain the original handshake message field content and add a string of data data to the end of the data.
 *          (This implementation performs deep copy of the data content.)
 *          This method is used to modify the content of the uint8_t array field in a message, such as the session ID,
 *          cookie, and signature data.
 *
 * @param   data [IN] Data content
 * @param   dataLen [IN] Number of data records
 * @param   frameArray [IN/OUT] IN original field; OUT New field
 * @param   frameArrayLen [IN/OUT] IN Original field length; Length of the new field in the OUT field. This parameter
 *          can be none
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_AppendMsgArray8(const uint8_t *data, uint32_t dataLen,
    FRAME_Array8 *frameArray, FRAME_Integer *frameArrayLen);

/**
 * @brief   Modify the message field content. User can increase or decrease the length of the message field and modify
 *          the field content.
 *          (This implementation performs deep copy of the data content.)
 *          This method is used to modify the uint16_t array field in a message, for example, cipher suite and support
 *          group extension
 *
 * @param   data [IN] Data content
 * @param   dataLen [IN] Number of data records
 * @param   frameArray [IN/OUT] IN original field; OUT New field
 * @param   frameArrayLen [IN/OUT] IN Original field length; Length of the new field in the OUT field. This parameter
 *          can be none
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_ModifyMsgArray16(const uint16_t *data, uint32_t dataLen,
    FRAME_Array16 *frameArray, FRAME_Integer *frameArrayLen);

/**
 * @brief   Retain the original handshake message field content and add a string of data data to the end of the data.
 *          (This implementation performs deep copy of the data content.)
 *          This method is used to modify the uint16_t array field in a message, for example, the cipher suite and
 *          support group extension
 *
 * @param   data [IN] Data content
 * @param   dataLen [IN] Number of data records
 * @param   frameArray [IN/OUT] IN original field; OUT New field
 * @param   frameArrayLen [IN/OUT] IN Original field length; Length of the new field in the OUT field. This parameter
 *          can be none
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t FRAME_AppendMsgArray16(const uint16_t *data, uint32_t dataLen,
    FRAME_Array16 *frameArray, FRAME_Integer *frameArrayLen);

#ifdef __cplusplus
}
#endif

#endif // FRAME_MSG_H