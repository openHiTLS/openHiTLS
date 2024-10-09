/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/**
 * @defgroup hitls_type
 * @ingroup hitls
 * @brief TLS type definition, provides the TLS type required by the user
 */

#ifndef HITLS_TYPE_H
#define HITLS_TYPE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_type
 * @brief   HITLS context
 */
typedef struct TlsCtx HITLS_Ctx;

/**
 * @ingroup hitls_type
 * @brief   config context
 */
typedef struct TlsConfig HITLS_Config;

/**
 * @ingroup hitls_type
 * @brief   cipherSuite information
 */
typedef struct TlsCipherSuiteInfo HITLS_Cipher;

typedef struct TlsSessCtx HITLS_Session;

/**
* @ingroup hitls_type
* @brief   DTLS SCTP authkey length, which is specified in the protocol and can be used to determine the length
* when the auth key is set.
*/
#define DTLS_SCTP_SHARED_AUTHKEY_LEN 64

/**
* @ingroup hitls_type
* @brief   TLS1.3 key exchange mode: Only PSKs are used for key negotiation.
*/
#define TLS13_KE_MODE_PSK_ONLY 1u

/**
* @ingroup hitls_type
* @brief   TLS1.3 key exchange mode: Both PSK and (EC)DHE are used for key negotiation.
*/
#define TLS13_KE_MODE_PSK_WITH_DHE 2u
/**
* @ingroup hitls_type
* @brief   TLS1.3 certificate authentication: The certificate authentication is used and
* the (EC)DHE negotiation key is required.
*/
#define TLS13_CERT_AUTH_WITH_DHE 4u

/* Sets the number of digits in the version number. */
#define SSLV2_VERSION_BIT 0x00000001U
#define SSLV3_VERSION_BIT 0x00000002U
#define TLS10_VERSION_BIT 0x00000004U
#define TLS11_VERSION_BIT 0x00000008U
#define TLS12_VERSION_BIT 0x00000010U
#define TLS13_VERSION_BIT 0x00000020U
#define DTLS10_VERSION_BIT 0x80000000U
#define DTLS12_VERSION_BIT 0x40000000U
#define TLS_VERSION_MASK (TLS12_VERSION_BIT | TLS13_VERSION_BIT)

/* Currently, only DTLS12 is supported. DTLS10 is not supported */
#define DTLS_VERSION_MASK DTLS12_VERSION_BIT

/**
 * @ingroup hitls_type
 * @brief   HITLS_SESS_CACHE_MODE: mode for storing hitls sessions.
 */
typedef enum {
    HITLS_SESS_CACHE_NO,
    HITLS_SESS_CACHE_CLIENT,
    HITLS_SESS_CACHE_SERVER,
    HITLS_SESS_CACHE_BOTH,
} HITLS_SESS_CACHE_MODE;

/**
 * @ingroup hitls_type
 * @brief   key update message type
 */
typedef enum {
    HITLS_UPDATE_NOT_REQUESTED = 0,
    HITLS_UPDATE_REQUESTED = 1,
    HITLS_KEY_UPDATE_REQ_END = 255
} HITLS_KeyUpdateRequest;

#define HITLS_MODE_ENABLE_PARTIAL_WRITE       0x00000001U
#define HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002U
#define HITLS_MODE_AUTO_RETRY                 0x00000004U
#define HITLS_MODE_NO_AUTO_CHAIN              0x00000008U
#define HITLS_MODE_RELEASE_BUFFERS            0x00000010U
#define HITLS_MODE_SEND_CLIENTHELLO_TIME      0x00000020U
#define HITLS_MODE_SEND_SERVERHELLO_TIME      0x00000040U
#define HITLS_MODE_SEND_FALLBACK_SCSV         0x00000080U
#define HITLS_MODE_ASYNC                      0x00000100U
#define HITLS_MODE_DTLS_SCTP_LABEL_LENGTH_BUG 0x00000400U

/* close_notify message has been sent to the peer end, turn off the alarm, and the connection is considered closed. */
# define HITLS_SENT_SHUTDOWN       1u
# define HITLS_RECEIVED_SHUTDOWN   2u        /* Received peer shutdown alert, normal close_notify or fatal error */

// Used to mark the current internal status
#define HITLS_NOTHING              1u
#define HITLS_WRITING              2u
#define HITLS_READING              3u
#define HITLS_ASYNC_PAUSED         4u
#define HITLS_ASYNC_NO_JOBS        5u

#define HITLS_CC_READ  0x001u       /* Read state */
#define HITLS_CC_WRITE 0x002u       /* Write status */

/* Describes the handshake status */
typedef enum {
    TLS_IDLE,                       /**< initial state */
    TLS_CONNECTED,                  /**< Handshake succeeded */
    TRY_SEND_HELLO_REQUEST,         /**< sends hello request message */
    TRY_SEND_CLIENT_HELLO,          /**< sends client hello message */
    TRY_SEND_HELLO_VERIFY_REQUEST,  /**< sends hello verify request message */
    TRY_SEND_HELLO_RETRY_REQUEST,   /**< sends hello retry request message */
    TRY_SEND_SERVER_HELLO,          /**< sends server hello message */
    TRY_SEND_ENCRYPTED_EXTENSIONS,  /**< sends encrypted extensions message */
    TRY_SEND_CERTIFICATE,           /**< sends certificate message */
    TRY_SEND_SERVER_KEY_EXCHANGE,   /**< sends server key exchange message */
    TRY_SEND_CERTIFICATE_REQUEST,   /**< sends certificate request message */
    TRY_SEND_SERVER_HELLO_DONE,     /**< sends server hello done message */
    TRY_SEND_CLIENT_KEY_EXCHANGE,   /**< sends client key exchange message */
    TRY_SEND_CERTIFICATE_VERIFY,    /**< sends certificate verify message */
    TRY_SEND_NEW_SESSION_TICKET,    /**< sends new session ticket message */
    TRY_SEND_CHANGE_CIPHER_SPEC,    /**< sends change cipher spec message */
    TRY_SEND_END_OF_EARLY_DATA,     /**< sends end of early data message */
    TRY_SEND_FINISH,                /**< sends finished message */
    TRY_RECV_CLIENT_HELLO,          /**< attempts to receive client hello message */
    TRY_RECV_HELLO_VERIFY_REQUEST,  /**< attempts to receive hello verify request message */
    TRY_RECV_SERVER_HELLO,          /**< attempts to receive server hello message */
    TRY_RECV_ENCRYPTED_EXTENSIONS,  /**< attempts to receive encrypted extensions message */
    TRY_RECV_CERTIFICATE,           /**< attempts to receive certificate message */
    TRY_RECV_SERVER_KEY_EXCHANGE,   /**< attempts to receive server key exchange message */
    TRY_RECV_CERTIFICATE_REQUEST,   /**< attempts to receive certificate request message */
    TRY_RECV_SERVER_HELLO_DONE,     /**< attempts to receive server hello done message */
    TRY_RECV_CLIENT_KEY_EXCHANGE,   /**< attempts to receive client key exchange message */
    TRY_RECV_CERTIFICATE_VERIFY,    /**< attempts to receive certificate verify message */
    TRY_RECV_NEW_SESSION_TICKET,    /**< attempts to receive new session ticket message */
    TRY_RECV_END_OF_EARLY_DATA,     /**< attempts to receive end of early data message */
    TRY_RECV_FINISH,                /**< attempts to receive finished message */
    HS_STATE_BUTT = 255             /**< enumerated Maximum Value */
} HITLS_HandshakeState;

#ifdef __cplusplus
}
#endif

#endif
