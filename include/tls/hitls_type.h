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
*
* @brief   DTLS SCTP authkey length, which is specified in the protocol and can be used to determine the length
* when the auth key is set.
*/
#define DTLS_SCTP_SHARED_AUTHKEY_LEN 64

/**
* @ingroup hitls_type
*
* @brief   TLS1.3 key exchange mode: Only PSKs are used for key negotiation.
*/
#define TLS13_KE_MODE_PSK_ONLY 1u

/**
* @ingroup hitls_type
*
* @brief   TLS1.3 key exchange mode: Both PSK and (EC)DHE are used for key negotiation.
*/
#define TLS13_KE_MODE_PSK_WITH_DHE 2u
/**
* @ingroup hitls_type
*
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
#define TLCP11_VERSION_BIT  0x00000080U
#define DTLS10_VERSION_BIT  0x80000000U
#define DTLS12_VERSION_BIT  0x40000000U
#define DTLCP11_VERSION_BIT 0x00000100U
#define TLS_VERSION_MASK (TLS12_VERSION_BIT | TLS13_VERSION_BIT)

/* Currently, only DTLS12 is supported. DTLS10 is not supported */
#define DTLS_VERSION_MASK DTLS12_VERSION_BIT

#define STREAM_VERSION_BITS                                                                              \
    (SSLV2_VERSION_BIT | SSLV3_VERSION_BIT | TLS10_VERSION_BIT | TLS11_VERSION_BIT | TLS12_VERSION_BIT | \
     TLS13_VERSION_BIT | TLCP11_VERSION_BIT)
#define DATAGRAM_VERSION_BITS (DTLS10_VERSION_BIT | DTLS12_VERSION_BIT | DTLCP11_VERSION_BIT)

#define TLCP_VERSION_BITS (TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT)
#define ALL_VERSION       (STREAM_VERSION_BITS | DATAGRAM_VERSION_BITS)

/**
 * @ingroup hitls_type
 *
 * @brief   HITLS_SESS_CACHE_MODE: mode for storing hitls sessions.
 */
typedef enum {
    HITLS_SESS_CACHE_NO = 0x00000000U,
    HITLS_SESS_CACHE_CLIENT = 0x00000001U,
    HITLS_SESS_CACHE_SERVER = 0x00000002U,
    HITLS_SESS_CACHE_BOTH = 0x00000003U,
    HITLS_SESS_DISABLE_INTERNAL_STORE = 0x00000004U,
    HITLS_SESS_DISABLE_INTERNAL_LOOKUP = 0x00000008U,
    HITLS_SESS_DISABLE_AUTO_CLEANUP = 0x00000010U,
    HITLS_SESS_ENABLE_TIME_UPDATE = 0x00000020U,
} HITLS_SESS_CACHE_MODE;

/**
 * @ingroup hitls_type
 *
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
#define HITLS_CLIENT_HELLO_CB      6u
#define HITLS_X509_LOOKUP          7u
#define HITLS_CC_READ  0x001u       /* Read state */
#define HITLS_CC_WRITE 0x002u       /* Write status */

#ifdef __cplusplus
}
#endif

#endif
