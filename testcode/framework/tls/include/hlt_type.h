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

#ifndef HLT_TYPE_H
#define HLT_TYPE_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>
#include "uio_base.h"
#include "bsl_uio.h"
#include "hitls_type.h"
#include "tls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IP_LEN (32)
#define MAX_CIPHERSUITES_LEN (512)
#define MAX_POINTFORMATS_LEN (512)
#define MAX_GROUPS_LEN (512)
#define MAX_SIGNALGORITHMS_LEN (512)
#define MAX_CERT_LEN (512)
#define PSK_MAX_LEN (256)
#define TICKET_KEY_CB_NAME_LEN (50)
#define MAX_SERVER_NAME_LEN (256)
#define SERVER_NAME_CB_NAME_LEN (50)
#define SERVER_NAME_ARG_NAME_LEN (50)
#define MAX_ALPN_LEN (256)
#define ALPN_CB_NAME_LEN (50)
#define ALPN_DATA_NAME_LEN (50)
#define MAX_NO_RENEGOTIATIONCB_LEN (1024)
#define MAX_PROVIDER_NAME_LEN (256)
#define MAX_ATTR_NAME_LEN (256)
#define MAX_PROVIDER_PATH_LEN (256)
#define MAX_PROVIDER_COUNT (10)
#define KEY_LOG_CB_LEN (1024)
#define MAX_EXPORT_MATERIAL_BUF (1024)

#define DEFAULT_CERT_PATH       "../../testcode/testdata/tls/certificate/der/"

#define RSAPSS_SHA256_CA_PATH      "rsa_pss_sha256/rsa_pss_root.der:rsa_pss_sha256/rsa_pss_intCa.der"
#define RSAPSS_SHA256_CHAIN_PATH   "rsa_pss_sha256/rsa_pss_intCa.der"
#define RSAPSS_SHA256_EE_PATH      "rsa_pss_sha256/rsa_pss_dev.der"
#define RSAPSS_SHA256_PRIV_PATH    "rsa_pss_sha256/rsa_pss_dev.key.der"
#define RSAPSS_RSAE_CA_PATH        "rsa_pss_rsae/rsa_root.der:rsa_pss_rsae/rsa_intCa.der"
#define RSAPSS_RSAE_CHAIN_PATH     "rsa_pss_rsae/rsa_intCa.der"
#define RSAPSS_RSAE_EE_PATH        "rsa_pss_rsae/rsa_dev.der"
#define RSAPSS_RSAE_PRIV_PATH      "rsa_pss_rsae/rsa_dev.key.der"

#define RSA_SHA_CA_PATH         "rsa_sha/ca-3072.der:rsa_sha/inter-3072.der"
#define RSA_SHA_CHAIN_PATH      "rsa_sha/inter-3072.der"
#define RSA_SHA1_EE_PATH        "rsa_sha/end-sha1.der"
#define RSA_SHA1_PRIV_PATH      "rsa_sha/end-sha1.key.der"
#define RSA_SHA384_EE_PATH      "rsa_sha/end-sha384.der"
#define RSA_SHA384_PRIV_PATH    "rsa_sha/end-sha384.key.der"
#define RSA_SHA512_EE_PATH      "rsa_sha/end-sha512.der"
#define RSA_SHA512_PRIV_PATH    "rsa_sha/end-sha512.key.der"

#define ED25519_SHA512_CA_PATH        "ed25519/ed25519.ca.der:ed25519/ed25519.intca.der"
#define ED25519_SHA512_CHAIN_PATH     "ed25519/ed25519.intca.der"
#define ED25519_SHA512_EE_PATH        "ed25519/ed25519.end.der"
#define ED25519_SHA512_PRIV_PATH      "ed25519/ed25519.end.key.der"

#define ECDSA_SHA_CA_PATH       "ecdsa/ca-nist521.der:ecdsa/inter-nist521.der"
#define ECDSA_SHA_CHAIN_PATH    "ecdsa/inter-nist521.der"
#define ECDSA_SHA256_EE_PATH    "ecdsa/end256-sha256.der"
#define ECDSA_SHA256_PRIV_PATH  "ecdsa/end256-sha256.key.der"
#define ECDSA_SHA384_EE_PATH    "ecdsa/end384-sha384.der"
#define ECDSA_SHA384_PRIV_PATH  "ecdsa/end384-sha384.key.der"
#define ECDSA_SHA512_EE_PATH    "ecdsa/end521-sha512.der"
#define ECDSA_SHA512_PRIV_PATH  "ecdsa/end521-sha512.key.der"

#define ECDSA_SHA1_CA_PATH      "ecdsa_sha1/ca-nist521.der:ecdsa_sha1/inter-nist521.der"
#define ECDSA_SHA1_CHAIN_PATH   "ecdsa_sha1/inter-nist521.der"
#define ECDSA_SHA1_EE_PATH      "ecdsa_sha1/end384-sha1.der"
#define ECDSA_SHA1_PRIV_PATH    "ecdsa_sha1/end384-sha1.key.der"
#define RSA_SHA256_CA_PATH      "rsa_sha256/ca.der:rsa_sha256/inter.der"
#define RSA_SHA256_CHAIN_PATH   "rsa_sha256/inter.der"
#define RSA_SHA256_EE_PATH1     "rsa_sha256/server.der"
#define RSA_SHA256_PRIV_PATH1   "rsa_sha256/server.key.der"
#define RSA_SHA256_EE_PATH2     "rsa_sha256/client.der"
#define RSA_SHA256_PRIV_PATH2   "rsa_sha256/client.key.der"
#define RSA_SHA256_EE_PATH3     "rsa_sha/end-sha256.der"
#define RSA_SHA256_PRIV_PATH3   "rsa_sha/end-sha256.key.der"

#define ECDSA_SHA256_CA_PATH    "ecdsa_sha256/ca.der:ecdsa_sha256/inter.der"
#define ECDSA_SHA256_CHAIN_PATH "ecdsa_sha256/inter.der"
#define ECDSA_SHA256_EE_PATH1   "ecdsa_sha256/server.der"
#define ECDSA_SHA256_PRIV_PATH1 "ecdsa_sha256/server.key.der"
#define ECDSA_SHA256_EE_PATH2   "ecdsa_sha256/client.der"
#define ECDSA_SHA256_PRIV_PATH2 "ecdsa_sha256/client.key.der"

#define SM2_VERIFY_PATH "sm2_with_userid/ca.der:sm2_with_userid/inter.der"
#define SM2_CHAIN_PATH "sm2_with_userid/inter.der"
#define SM2_SERVER_ENC_CERT_PATH "sm2_with_userid/enc.der"
#define SM2_SERVER_ENC_KEY_PATH "sm2_with_userid/enc.key.der"
#define SM2_SERVER_SIGN_CERT_PATH "sm2_with_userid/sign.der"
#define SM2_SERVER_SIGN_KEY_PATH "sm2_with_userid/sign.key.der"
#define SM2_CLIENT_ENC_CERT_PATH "sm2_with_userid/enc22.der"
#define SM2_CLIENT_ENC_KEY_PATH "sm2_with_userid/enc22.key.der"
#define SM2_CLIENT_SIGN_CERT_PATH "sm2_with_userid/sign22.der"
#define SM2_CLIENT_SIGN_KEY_PATH "sm2_with_userid/sign22.key.der"

typedef struct ProcessSt HLT_Process;

typedef enum {
    HITLS,
    HITLS_PROVIDER,
} TLS_TYPE;

typedef enum {
    CLIENT,
    SERVER
} TLS_ROLE;

typedef enum {
    DTLS_ALL,
    DTLS1_0,
    DTLS1_2,
    TLS_ALL,
    SSL3_0,
    TLS1_0,
    TLS1_1,
    TLS1_2,
    TLS1_3,
    TLCP1_1,
    DTLCP1_1,
} TLS_VERSION;

typedef enum {
    TCP = 0,    /**< TCP protocol */
    SCTP = 1,   /**< SCTP protocol */
    UDP = 2,    /**< UDP protocol */
    NONE_TYPE = 10,
} HILT_TransportType;

typedef enum {
    CERT_CALLBACK_DEFAULT,
} CertCallbackType;

typedef enum {
    MEM_CALLBACK_DEFAULT,
} MemCallbackType;

typedef enum {
    HITLS_CALLBACK_DEFAULT,
} TlsCallbackType;

typedef enum {
    COOKIE_CB_DEFAULT, // Normal cookie callback
    COOKIE_CB_LEN_0,   // The length of the generated cookie is 0
} CookieCallbackType;

typedef struct {
    struct sockaddr_in sockAddr;
    HILT_TransportType type;
    char ip[IP_LEN];
    int port;
    int bindFd;
    bool isBlock;
} DataChannelParam;

typedef struct {
    struct sockaddr_in sockAddr;
    int connPort;
    int srcFd;
    int peerFd;
} HLT_FD;

typedef enum {
    SERVER_CTX_SET_TRUE = 1,
    SERVER_CTX_SET_FALSE = 2,
    SERVER_CFG_SET_TRUE = 3,
    SERVER_CFG_SET_FALSE = 4,
} HILT_SupportType;

typedef struct {
    uint16_t mtu;        // Set the MTU in the dtls.
    // The maximum version number and minimum version number must be both TLS and DTLS.
    // Currently, only DTLS 1.2 is supported
    uint32_t minVersion;
    uint32_t maxVersion;

    char cipherSuites[MAX_CIPHERSUITES_LEN]; // cipher suite
    char tls13CipherSuites[MAX_CIPHERSUITES_LEN]; // TLS13 cipher suite
    char pointFormats[MAX_POINTFORMATS_LEN]; // ec Point Format
    // According to RFC 8446 4.2.7, before TLS 1.3: ec curves; TLS 1.3: group supported by the key exchange.
    char groups[MAX_GROUPS_LEN];
    char signAlgorithms[MAX_SIGNALGORITHMS_LEN]; // signature algorithm

    char serverName[MAX_SERVER_NAME_LEN];      // Client server_name
    //  Name of the server_name callback function for processing the first handshake on the server
    char sniDealCb[SERVER_NAME_CB_NAME_LEN];
    // name of the value function related to the server_name registered by the product
    char sniArg[SERVER_NAME_ARG_NAME_LEN];

    char alpnList[MAX_ALPN_LEN];               // alpn
    char alpnUserData[ALPN_CB_NAME_LEN];
    char alpnSelectCb[ALPN_DATA_NAME_LEN];     // Application Layer Protocol Select Callback
    char keyLogCb[KEY_LOG_CB_LEN];

    // Indicates whether renegotiation is supported. The default value is False, indicating that renegotiation is not
    // supported
    bool isSupportRenegotiation;
    bool allowClientRenegotiate;        /* allow a renegotiation initiated by the client */
    bool allowLegacyRenegotiate;        /* whether to abort handshake when server doesn't support SecRenegotiation */
    int  SupportType;                   // 1:The server algorithm is preferred
    bool needCheckKeyUsage;             // Client verification is supported. The default value is False
    // Indicates whether to allow the empty certificate list on the client. The default value is False
    bool isSupportClientVerify;
    bool isSupportNoClientCert;         // supports extended master keys. The default value is True
    // The handshake will be continued regardless of the verification result. for server and client
    bool isSupportVerifyNone;
    bool isSupportPostHandshakeAuth;    // Indicates whether to support post handshake auth. The default value is false.
    bool isSupportExtendMasterSecret;   // supports extended master keys. The default value is True
    bool isSupportSessionTicket;        // Support session ticket
    bool isEncryptThenMac;              // Encrypt-then-mac is supported
    // Users can set the DH parameter to be automatically selected. If the switch is enabled,
    // the DH parameter is automatically selected based on the length of the certificate private key
    bool isSupportDhAuto;
    int32_t setSessionCache;            // Setting the Session Storage Mode
    uint32_t keyExchMode;               // TLS1.3 key exchange mode
    void *infoCb;                       // connection establishment callback function
    void *msgCb;                        // Message callback function
    void *msgArg;                       // Message callback parameter function
    void *certCb;
    void *certArg;
    void *clientHelloCb;
    void *clientHelloArg;
    // Indicates whether to enable the function of sending handshake information by flight
    bool isFlightTransmitEnable;
    bool isNoSetCert;                   // Indicates whether the certificate does not need to be set
	int32_t securitylevel;                  // Security level
    int32_t readAhead;
    void *caList;
    char psk[PSK_MAX_LEN];              // psk password
    char ticketKeyCb[TICKET_KEY_CB_NAME_LEN]; // ticket key Callback Function Name

    char eeCert[MAX_CERT_LEN];
    char privKey[MAX_CERT_LEN];
    char signCert[MAX_CERT_LEN];
    char signPrivKey[MAX_CERT_LEN];
    char password[MAX_CERT_LEN];
    char caCert[MAX_CERT_LEN];
    char chainCert[MAX_CERT_LEN];

    bool isClient;
    uint32_t emptyRecordsNum;
    char providerPath[MAX_PROVIDER_PATH_LEN];
    char providerNames[MAX_PROVIDER_COUNT][MAX_PROVIDER_NAME_LEN];
    int32_t providerLibFmts[MAX_PROVIDER_COUNT];
    int32_t providerCnt;
    char attrName[MAX_ATTR_NAME_LEN];
    uint32_t modeSupport;       // support features, such as HITLS_MODE_SEND_FALLBACK_SCSV. All mode at hitls_type.h
    bool isMiddleBoxCompat;     // Indicates whether to enable the middle box compatibility mode.
    bool isSupportDtlsCookieExchange;
    uint16_t recordSizeLimit;
} HLT_Ctx_Config;

typedef struct {
    struct sockaddr_in sockAddr;
    int connPort;
    int sockFd;
    HILT_TransportType connType;
    int SupportType;                   // 3:The server algorithm is preferred
    int sctpCtrlCmd;
} HLT_Ssl_Config;

typedef struct {
    void *ctx; // hitls config
    void *ssl; // hitls ctx
    int ctxId;
    int sslId;
    pthread_t acceptId;
} HLT_Tls_Res;

typedef enum {
    EXP_NONE,
    EXP_IO_BUSY,
    EXP_RECV_BUF_EMPTY,
} HLT_ExpectIoState;

typedef enum {
    POINT_NONE,
    POINT_RECV,
    POINT_SEND,
} HLT_PointType;

/**
 * @brief   msg processing callback
 */
typedef void (*HLT_FrameCallBack)(void *msg, void *userData);

typedef struct {
    BSL_UIO_Method method;         /**< User-defined message sending and receiving control function */
    HLT_FrameCallBack frameCallBack; /**< msg processing callback */
    void *ctx;                       /**< TLS context */
    int32_t expectReType;            /**< Corresponding enumeration REC_Type */
    int32_t expectHsType;            /**< Corresponding enumerated value HS_MsgType */
    HLT_ExpectIoState ioState;       /**< customized I/O status */
    HLT_PointType pointType;         /**< Callback function for recording keys */
    void *userData;                  /**< Customized data, which will be transferred to the msg processing callback */
} HLT_FrameHandle;

#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define TIME_OUT_SEC 50
#else
#define TIME_OUT_SEC 8
#endif

#ifdef __cplusplus
}
#endif

#endif // HLT_TYPE_H
