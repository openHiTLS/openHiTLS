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
 * @defgroup hitls_errno
 * @ingroup hitls
 * @brief error module
 */

#ifndef HITLS_ERROR_H
#define HITLS_ERROR_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup tls_error
 * @brief   Return success
 */
#define HITLS_SUCCESS 0
#define HITLS_X509_V_OK 0

/**
 * @ingroup tls_error
 * @brief   Indicates that the connection is blocked. You can call HITLS_Connect to continue the connection.
 * This problem is usually caused by read and write operations.
 */
#define HITLS_WANT_CONNECT 1

/**
 * @ingroup tls_error
 * @brief   Indicates that the connection is blocked and the HITLS_Accept can be called to continue the connection.
 * This problem is usually caused by read and write operations.
 */
#define HITLS_WANT_ACCEPT 2

/**
 * @ingroup tls_error
 * @brief   indicates that the receiving buffer is empty and the interface can be
 * called to continue receiving data.
 */
#define HITLS_WANT_READ 3

/**
 * @ingroup tls_error
 * @brief   The sending buffer is full and the interface can be called to continue sending data.
 */
#define HITLS_WANT_WRITE 4

/**
 * @ingroup tls_error
 * @brief   An unrecoverable fatal error occurs in the TLS protocol, usually a protocol error.
 */
#define HITLS_ERR_TLS 5

/**
 * @ingroup tls_error
 * @brief   An unrecoverable I/O error occurs,
 * which is usually a low level receiving and receiving exception or an unknown error occurs.
 */
#define HITLS_ERR_SYSCALL  6

#define HITLS_WANT_BACKUP 7

/**
 * @ingroup tls_error
 * @brief   The operation did not complete because an application callback set by
 * HITLS_CFG_SetClientHelloCb() has asked to be called again.
 */
#define HITLS_WANT_CLIENT_HELLO_CB 8

/**
 * @ingroup tls_error
 * @brief   The operation did not complete because an application callback set by
 * HITLS_CFG_SetCertCb() has asked to be called again.
 */
#define HITLS_WANT_X509_LOOKUP 9

/**
 * @ingroup tls_error
 *
 * Error code returned by the TLS module
 */
typedef enum {
    HITLS_NULL_INPUT = 0x02010001,                 /**< Incorrect null pointer input. */
    HITLS_INVALID_INPUT,                           /**< Invalid input, the parameter value is out of the valid range.*/
    HITLS_INTERNAL_EXCEPTION,                      /**< Unexpected internal error, which is unlikely. */
    HITLS_MEMALLOC_FAIL,                           /**< Failed to apply for memory. */
    HITLS_MEMCPY_FAIL,                             /**< Memory Copy Failure. */
    HITLS_UNREGISTERED_CALLBACK,                   /**< Use unregistered callback. */
    HITLS_UNSUPPORT_TLS_VERSION,                   /**< Does not support the protocol. */

    HITLS_CONFIG_FAIL_START = 0x02020001,          /**< config module error code start bit. */
    HITLS_CONFIG_NO_SUITABLE_CIPHER_SUITE,         /**< Unfind a proper cipher suite. */
    HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE,           /**< Unsupported cipher suites. */
    HITLS_CONFIG_INVALID_SET,                      /**< Invalid setting. */
    HITLS_CONFIG_NO_SUITABLE_SIGNATURE_ALGORITHM,  /**< The signature algorithm and the cipher suite are nonmatching. */
    HITLS_CONFIG_NO_GROUPS,                        /**< The group is not set. */
    HITLS_CONFIG_UNSUPPORT_SIGNATURE_ALGORITHM,    /**< Unsupported signature algorithm. */
    HITLS_CONFIG_UNSUPPORT_POINT_FORMATS,          /**< Unsupported the dot format. */
    HITLS_CONFIG_INVALID_VERSION,                  /**< Unsupported the protocol version. */
    HITLS_CONFIG_INVALID_LENGTH,                   /**< Invalid length. */
    HITLS_CONFIG_NO_CERT,                          /**< Unset the certificate. */
    HITLS_CONFIG_NO_PRIVATE_KEY,                   /**< Unset the certificate private key. */
    HITLS_CONFIG_DUP_DH_KEY_FAIL,                  /**< Duplicate DH key failure. */
    HITLS_CFG_ERR_LOAD_CERT_FILE,                  /**< Failed to load the certificate file. */
    HITLS_CFG_ERR_LOAD_CERT_BUFFER,                /**< Failed to load the certificate buffer. */
    HITLS_CFG_ERR_LOAD_KEY_FILE,                   /**< Failed to load the key file. */
    HITLS_CFG_ERR_LOAD_KEY_BUFFER,                 /**< Failed to load the key buffer. */
    HITLS_CONFIG_UNSUPPORT_GROUP,                  /**< Unsupported group. */
    HITLS_CONFIG_UNSUPPORT,                        /**< Unsupported interface */
    HITLS_CONFIG_ERR_LOAD_GROUP_INFO,              /**< Failed to load the group info. */
    HITLS_CONFIG_ERR_LOAD_SIGN_SCHEME_INFO,        /**< Failed to load the signature scheme info. */
    HITLS_CONFIG_DUP_CUSTOM_EXT,                   /**< Duplicate custom extension type detected. */
    HITLS_CONFIG_ERR_MAX_LIMIT_CUSTOM_EXT,         /**< Exceed the max limit of custom extensions. */
    HITLS_CFG_ERR_LOAD_CRL_FILE,                   /**< Failed to load the CRL file. */
    HITLS_CFG_ERR_LOAD_CRL_BUFFER,                 /**< Failed to load the CRL buffer. */

    HITLS_CM_FAIL_START = 0x02030001,              /**< Error start bit of the conn module. */
    HITLS_CM_LINK_FATAL_ALERTED,                   /**< link sent fatal alert. */
    HITLS_CM_LINK_CLOSED,                          /**< Link has been closed. */
    HITLS_CM_LINK_UNESTABLISHED,                   /**< The current link is not established.
                                                        Do not perform other operations, such as read and write. */
    HITLS_CM_LINK_UNSUPPORT_SECURE_RENEGOTIATION,  /**< The current link Unsupported security renegotiation. */
    HITLS_CM_LINK_HANDSHAKING,                     /**< Link is handshaking, can not set config */

    HITLS_MSG_HANDLE_FAIL_START = 0x02040001,      /**< Start bit of the error code processed by the state machine. */
    HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE,           /**< receives unexpected handshake messages. */
    HITLS_MSG_HANDLE_RANDOM_SIZE_ERR,              /**< Incorrect random number length. */
    HITLS_MSG_HANDLE_UNSUPPORT_POINT_FORMAT,       /**< Unsupported the point format. */
    HITLS_MSG_HANDLE_CIPHER_SUITE_ERR,             /**< cannot find the supported cipher suite. */
    HITLS_MSG_HANDLE_UNSUPPORT_VERSION,            /**< Unsupported version. */
    HITLS_MSG_HANDLE_STATE_ILLEGAL,                /**< Handshake status error. */
    HITLS_MSG_HANDLE_UNSUPPORT_KX_ALG,             /**< Unsupported key exchange algorithm. */
    HITLS_MSG_HANDLE_UNSUPPORT_CERT,               /**< Unsupported certificate. */
    HITLS_MSG_HANDLE_UNKNOWN_CURVE_TYPE,           /**< Unsupported elliptic curve type. */
    HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL,         /**< Failed to verify the finished message. */
    HITLS_MSG_HANDLE_VERIFY_SIGN_FAIL,             /**< Failed to verify the finished message. */
    HITLS_MSG_HANDLE_INCORRECT_DIGEST_LEN,         /**< Incorrect length of the digest. */
    HITLS_MSG_HANDLE_UNSUPPORT_NAMED_CURVE,        /**< Unsupported ECDH elliptic curves. */
    HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE,     /**< Unsupported the extended type. */
    HITLS_MSG_HANDLE_UNSUPPORT_CIPHER_SUITE,       /**< Unsupported cipher suites. */
    HITLS_MSG_HANDLE_COOKIE_ERR,                   /**< Incorrect cookie. */
    HITLS_MSG_VERIFY_COOKIE_ERR,                   /**< Failed to verify the cookie. */
    HITLS_MSG_HANDLE_ERR_ENCODE_ECDH_KEY,          /**< Failed to obtain the ECDH public key. */
    HITLS_MSG_HANDLE_ERR_ENCODE_DH_KEY,            /**< Failed to obtain the DH public key. */
    HITLS_MSG_HANDLE_ERR_GET_DH_PARAMETERS,        /**< Failed to obtain the DH parameter. */
    HITLS_MSG_HANDLE_ERR_GET_DH_KEY,               /**< Failed to generate the DH key. */
    HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE,         /**< Not receive the peer certificate. */
    HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE,    /**< Server has no certificate to send. */
    HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE,           /**< Handshake sequence number nonmatch */
    HITLS_MSG_HANDLE_ILLEGAL_VERSION,              /**< Incorrect version. */
    HITLS_MSG_HANDLE_ILLEGAL_CIPHER_SUITE,         /**< Incorrect cipher suite. */
    HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP,       /**< Incorrect selectedGroup. */
    HITLS_MSG_HANDLE_ILLEGAL_EXTRENED_MASTER_SECRET, /**< Incorrect extended master key. */
    HITLS_MSG_HANDLE_MISSING_EXTENSION,             /**< Message missing the extended field that must be sent */
    HITLS_MSG_HANDLE_DUPLICATE_HELLO_RETYR_REQUEST, /**< Duplicate Hello Retry Request messages */
    HITLS_MSG_HANDLE_ALPN_PROTOCOL_NO_MATCH,        /**< No matching alpn */
    HITLS_MSG_HANDLE_ILLEGAL_PSK_LEN,               /**< Invalid PSK length */
    HITLS_MSG_HANDLE_ILLEGAL_IDENTITY_LEN,          /**< Invalid identity length */
    HITLS_MSG_HANDLE_GET_UNSIGN_DATA_FAIL,          /**< Failed to obtain the unsigned data
                                                         during signature calculation */
    HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID,            /**< Receives an incorrect session ID */
    HITLS_MSG_HANDLE_SNI_UNRECOGNIZED_NAME,         /**< Not accept the extended value of server_name */
    HITLS_MSG_HANDLE_ALPN_UNRECOGNIZED,             /**< Not accept the extended ALPN value */
    HITLS_MSG_HANDLE_ILLEGAL_KEY_UPDATE_TYPE,       /**< Receives an incorrect key update type */
    HITLS_MSG_HANDLE_SYS_TIME_FAIL,                 /**< System time function returns a failure */
    HITLS_MSG_HANDLE_DTLS_CONNECT_TIMEOUT,           /**< DTLS connection timeout */
    HITLS_MSG_HANDLE_UNSECURE_VERSION,              /**< Insecure version. */
    HITLS_MSG_HANDLE_UNSECURE_CIPHER_SUITE,         /**< Insecure cipher suites. */
    HITLS_MSG_HANDLE_RENEGOTIATION_FAIL,            /**< Renegotiation failure */
    HITLS_MSG_HANDLE_SESSION_ID_CTX_ILLEGAL,        /**< Session ID ctx mismatch */
    HITLS_MSG_HANDLE_ENCRYPT_THEN_MAC_ERR,          /**< Failed to change the EncryptThenMac status */
    HITLS_MSG_HANDLE_ILLEGAL_PSK_IDENTITY,          /**< psk identity error */
    HITLS_MSG_HANDLE_PSK_USE_SESSION_FAIL,          /**< The TLS1.3 client fails to process the PSK callback. */
    HITLS_MSG_HANDLE_PSK_FIND_SESSION_FAIL,         /**< The TLS1.3 server fails to process the PSK callback. */
    HITLS_MSG_HANDLE_PSK_SESSION_INVALID_CIPHER_SUITE, /**< TLS1.3 psk session algorithm suite is incorrect. */
    HITLS_MSG_HANDLE_PSK_INVALID,                   /**< TLS1.3 psk check failed. */
    HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX,          /**< TLS1.3 invalid certificateReqCtx. */
    HITLS_MSG_HANDLE_HANDSHAKE_FAILURE,             /**< TLS1.3 handshake parameters cannot be negotiated. */
    HITLS_MSG_HANDLE_INVALID_COMPRESSION_METHOD,    /**< Receives an incorrect compression algorithm. */
    HITLS_MSG_HANDLE_INVALID_EXTENDED_MASTER_SECRET, /**< The peer Unsupported the extended master key. */
    HITLS_MSG_HANDLE_ERR_CLIENT_HELLO_FRAGMENT,
    HITLS_MSG_HANDLE_INVALID_RECORD_SIZE_LIMIT,      /**< The value of record size limit is invalid. */
    HITLS_MSG_HANDLE_ERR_INAPPROPRIATE_FALLBACK,    /**< The downgrade negotiation failed, and the client supports
                                                        a higher version. */
    HITLS_MSG_HANDLE_DTLS_RETRANSMIT_NOT_TIMEOUT,
    HITLS_MSG_HANDLE_ERR_WITHOUT_TIMEOUT_ACTION,
    HITLS_MSG_HANDLE_ERR_TIMEOUT_REWIND,

    HITLS_PACK_FAIL_START = 0x02050001,             /**< Start bit of the pack error code. */
    HITLS_PACK_UNSUPPORT_VERSION,                   /**< Unsupported version. */
    HITLS_PACK_UNSECURE_VERSION,                    /**< Insecure version. */
    HITLS_PACK_UNSUPPORT_HANDSHAKE_MSG,             /**< Unsupported handshake messages. */
    HITLS_PACK_NOT_ENOUGH_BUF_LENGTH,               /**< Insufficient buffer length. */
    HITLS_PACK_SESSIONID_ERR,                       /**< Failed to assemble the sessionId. */
    HITLS_PACK_COOKIE_ERR,                          /**< Failed to assemble the cookie. */
    HITLS_PACK_CLIENT_CIPHER_SUITE_ERR,             /**< Failed to assemble client_cipher_suite. */
    HITLS_PACK_UNSUPPORT_KX_ALG,                    /**< Unsupported the key negotiation algorithm. */
    HITLS_PACK_UNSUPPORT_KX_CURVE_TYPE,             /**< Unsupported ECDH key negotiation algorithm curve. */
    HITLS_PACK_INVALID_KX_PUBKEY_LENGTH,            /**< Invalid length of the public key for key negotiation */
    HITLS_PACK_SIGNATURE_ERR,                       /**< Failed to assemble the server_kx message signature data. */
    HITLS_PACK_PRE_SHARED_KEY_ERR,                  /**< Failed to assemble the PSK. */

    HITLS_PARSE_FAIL_START = 0x02060001,            /**< Start bit of the parse error code. */
    HITLS_PARSE_UNSUPPORT_VERSION,                  /**< Unsupported Version. */
    HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG,            /**< Unsupported handshake messages. */
    HITLS_PARSE_INVALID_MSG_LEN,                    /**< Message length error. */
    HITLS_PARSE_DUPLICATE_EXTENDED_MSG,             /**< Duplicate extended messages. */
    HITLS_PARSE_COMPRESSION_METHOD_ERR,             /**< Incorrect compression type. */
    HITLS_PARSE_SERVER_NAME_ERR,                    /**< Failed to parse server_name. */
    HITLS_PARSE_CERT_ERR,                           /**< Failed to parse the certificate. */
    HITLS_PARSE_ECDH_PUBKEY_ERR,                    /**< Failed to parse the ecdh public key. */
    HITLS_PARSE_ECDH_SIGN_ERR,                      /**< Failed to parse the ecdh signature. */
    HITLS_PARSE_UNSUPPORT_KX_ALG,                   /**< Unsupported the key exchange algorithm. */
    HITLS_PARSE_UNSUPPORT_KX_CURVE_TYPE,            /**< Unsupported ECC curve type. */
    HITLS_PARSE_GET_SIGN_PARA_ERR,                  /**< Failed to obtain the signature algorithm and hash algorithm */
    HITLS_PARSE_UNSUPPORT_SIGN_ALG,                 /**< Unsupported the signature algorithm. */
    HITLS_PARSE_VERIFY_SIGN_FAIL,                   /**< Failed to verify the signature. */
    HITLS_PARSE_DH_P_ERR,                           /**< Failed to parse the dh_p. */
    HITLS_PARSE_DH_G_ERR,                           /**< Failed to parse the dh_g. */
    HITLS_PARSE_DH_PUBKEY_ERR,                      /**< Failed to parse the DHE public key. */
    HITLS_PARSE_DH_SIGN_ERR,                        /**< Failed to parse the DHE signature. */
    HITLS_PARSE_UNSUPPORTED_EXTENSION,              /**< Unsupported extended fields. */
    HITLS_PARSE_CA_LIST_ERR,                        /**< Failed to parse the CA name list. */
    HITLS_PARSE_EXCESSIVE_MESSAGE_SIZE,             /**< The length of the parsing exceeds the maximum. */
    HITLS_PARSE_PRE_SHARED_KEY_FAILED,              /**< Failed to parse the PSK extension. */
    HITLS_PARSE_DUPLICATED_KEY_SHARE,               /**< duplicated key share entry. */
    HITLS_PARSE_SESSION_TICKET_FAIL,                /**< parse session ticket fail */

    HITLS_REASS_FAIL_START = 0x02070001,            /**< Reassembly module error code start bit. */
    HITLS_REASS_INVALID_FRAGMENT,                   /**< Receives invalid fragmented messages. */

    HITLS_CCS_FAIL_START = 0x02080001,              /**< ccs module error code start bit. */
    HITLS_CCS_INVALID_CMD,                          /**< Invalid command. */

    HITLS_ALERT_FAIL_START = 0x02090001,            /**< alert module error code start bit. */
    HITLS_ALERT_NO_WANT_SEND,                       /**< No alert messages to be sent. */

    HITLS_REC_FAIL_START = 0x020A0001,              /**< record module error start bit. */
    HITLS_REC_PMTU_TOO_SMALL,                       /**< pmtu is too small to meet the record packet length. */
    HITLS_REC_ERR_BUFFER_NOT_ENOUGH,                /**< Insufficient buffer. */
    HITLS_REC_ERR_TOO_BIG_LENGTH,                   /**< The length of the plaintext data to be written
                                                         exceeds the maximum length of a single record. */
    HITLS_REC_ERR_NOT_SUPPORT_CIPHER,              /**< Unsupported the cipher suites. */
    HITLS_REC_ERR_ENCRYPT,                         /**< Encryption failed. */
    HITLS_REC_ERR_AEAD_NONCE_PARAM,                /**< AEAD nonce input parameter is incorrect. */
    HITLS_REC_ERR_SN_WRAPPING,                     /**< Sequence number Rewind. */
    HITLS_REC_ERR_IO_EXCEPTION,                    /**< The low level I/O is abnormal. */
    HITLS_REC_NORMAL_IO_BUSY,                      /**< Low level I/O is busy, need wait for the next sending. */
    HITLS_REC_NORMAL_RECV_BUF_EMPTY,               /**< The receiving buffer is empty. */
    HITLS_REC_NORMAL_RECV_UNEXPECT_MSG,            /**< If REC receives unexpected messages and the receiver is user,
                                                        needs to recall the previous function. */
    HITLS_REC_NORMAL_RECV_DISORDER_MSG,            /**< The REC receives disordered records,
                                                        to receive disordered finished records. */
    HITLS_REC_INVLAID_RECORD,                      /**< record: invalid record message. */
    HITLS_REC_INVALID_PROTOCOL_VERSION,            /**< record: Incorrect version. */
    HITLS_REC_BAD_RECORD_MAC,                      /**< record: Invalid MAC. */
    HITLS_REC_DECODE_ERROR,                        /**< Decoding failed. */
    HITLS_REC_RECORD_OVERFLOW,                     /**< Record is too long. */
    HITLS_REC_ERR_RECV_UNEXPECTED_MSG,             /**< Record: unexpected message */
    HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY,          /**< TLS1.3: read key change not on record boundary */
    HITLS_REC_ERR_GENERATE_MAC,                    /**< Failed to generate the MAC address. */
    HITLS_REC_NORMAL_IO_EOF,                       /**< IO object has reached EOF. */
    HITLS_REC_ENCRYPTED_NUMBER_OVERFLOW,           /**< The number of AES-GCM encryption times cannot exceed 2^24.5. */
    HITLS_REC_ERR_DATA_BETWEEN_CCS_AND_FINISHED,   /**< When version is below TLS13,
                                                        must not have data between ccs and finished. */

    HITLS_UIO_FAIL_START = 0x020B0001,             /**< uio module error code start bit. */
    HITLS_UIO_FAIL,                                /**< UIO internal failure. */
    HITLS_UIO_IO_EXCEPTION,                        /**< Low level I/O exception. */
    HITLS_UIO_SCTP_IS_SND_BUF_EMPTY_FAIL,          /**< Failed to obtain whether the sending buffer
                                                        of the UIO object is empty. */
    HITLS_UIO_SCTP_ADD_AUTH_KEY_FAIL,              /**< Failed to add the auth key for the sctp UIO object. */
    HITLS_UIO_SCTP_ACTIVE_AUTH_KEY_FAIL,           /**< Failed to activate the auth key for the sctp UIO object. */
    HITLS_UIO_SCTP_DEL_AUTH_KEY_FAIL,              /**< Failed to delete the auth key for the sctp UIO object. */
    HITLS_UIO_NOT_SET,                             /**< Does not set the UIO object. */
    HITLS_UIO_IO_TYPE_ERROR,                       /**< The type of UIO is wrong. */

    HITLS_CERT_FAIL_START = 0x020C0001,            /**< Certificate module error code start bit. */
    HITLS_CERT_STORE_CTRL_ERR_SET_VERIFY_DEPTH,
    HITLS_CERT_STORE_CTRL_ERR_ADD_CERT_LIST,
    HITLS_CERT_ERR_X509_DUP,                       /**< Failed to duplicate the certificate. */
    HITLS_CERT_ERR_KEY_DUP,                        /**< Failed to duplicate the key. */
    HITLS_CERT_ERR_STORE_DUP,                      /**< Failed to duplicate the store. */
    HITLS_CERT_ERR_CHAIN_DUP,                      /**< Failed to duplicate the certificate chain. */
    HITLS_CERT_CTRL_ERR_GET_ENCODE_LEN,            /**< Failed to obtain the certificate encoding length. */
    HITLS_CERT_CTRL_ERR_GET_PUB_KEY,               /**< Failed to obtain the certificate public key. */
    HITLS_CERT_CTRL_ERR_GET_SIGN_ALGO,             /**< Failed to obtain the signature algorithm. */
    HITLS_CERT_KEY_CTRL_ERR_GET_SIGN_LEN,          /**< Failed to obtain the signature length. */
    HITLS_CERT_KEY_CTRL_ERR_GET_TYPE,              /**< Failed to obtain the key type. */
    HITLS_CERT_KEY_CTRL_ERR_GET_CURVE_NAME,        /**< Failed to obtain the elliptic curve ID. */
    HITLS_CERT_KEY_CTRL_ERR_GET_POINT_FORMAT,      /**< Failed to obtain the point format. */
    HITLS_CERT_KEY_CTRL_ERR_GET_SECBITS,           /**< Failed to obtain security bits. */
    HITLS_CERT_KEY_CTRL_ERR_IS_ENC_USAGE,          /**< Determine whether the certificate fails to be encrypted,
                                                        Applicable to TLCP scenarios. */
    HITLS_CERT_KEY_CTRL_ERR_IS_DIGITAL_SIGN_USAGE,  /**< Determine whether the certificate fails to be digital sign. */
    HITLS_CERT_KEY_CTRL_ERR_IS_KEY_CERT_SIGN_USAGE, /**< Determine whether the certificate fails to be cert sign. */
    HITLS_CERT_KEY_CTRL_ERR_IS_KEY_AGREEMENT_USAGE, /**< Determine whether the certificate fails to be agreement. */
	HITLS_CERT_STORE_CTRL_ERR_SET_VERIFY_FLAGS,     /**< Failed to set the certificate verification flags. */
    HITLS_CERT_KEY_CTRL_ERR_GET_PARAM_ID,           /**< Failed to obtain the parameter ID. */

    HITLS_CERT_ERR_INVALID_KEY_TYPE,                /**< Invalid key type */
    HITLS_CERT_ERR_CHECK_CERT_AND_KEY,              /**< Certificate and private key nonmatch. */
    HITLS_CERT_ERR_NO_CURVE_MATCH,                  /**< Certificate and elliptic curve ID nonmatch. */
    HITLS_CERT_ERR_NO_POINT_FORMAT_MATCH,           /**< Certificate and dot format nonmatch. */
    HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH,            /**< Certificate and signature algorithm nonmatch. */
    HITLS_CERT_ERR_SELECT_CERTIFICATE,              /**< Failed to select the certificate. */
    HITLS_CERT_ERR_BUILD_CHAIN,                     /**< Failed to construct the certificate chain. */
    HITLS_CERT_ERR_ENCODE_CERT,                     /**< Certificate encoding failure. */
    HITLS_CERT_ERR_PARSE_MSG,                       /**< Certificate decoding failure. */
    HITLS_CERT_ERR_VERIFY_CERT_CHAIN,               /**< Certificate chain verification failure. */
    HITLS_CERT_ERR_CREATE_SIGN,                     /**< Failed to sign using the certificate private key. */
    HITLS_CERT_ERR_VERIFY_SIGN,                     /**< Failed to use the certificate public key
                                                         to verify the signature. */
    HITLS_CERT_ERR_ENCRYPT,                         /**< Failed to encrypt the RSA certificate public key. */
    HITLS_CERT_ERR_DECRYPT,                         /**< Failed to decrypt using the RSA Certificate Private Key */
    HITLS_CERT_ERR_ADD_CHAIN_CERT,                  /**< Failed to add the certificate chain. */
    HITLS_CERT_ERR_MGR_DUP,                         /**< Failed to duplicate the certificate management structure. */
    HITLS_CERT_ERR_INSECURE_SIG_ALG,                /**< Insecure signature algorithm strength. */
    HITLS_CERT_ERR_CA_KEY_WITH_INSECURE_SECBITS,    /**< Insecure CA certificate key security bits. */
    HITLS_CERT_ERR_EE_KEY_WITH_INSECURE_SECBITS,    /**< Insecure EE certificate key security bits. */
    HITLS_CERT_ERR_EXP_CERT,                        /**< No expected certificate included. */
    HITLS_CERT_ERR_ENCODE,                          /**< Failed to encode the certificate. */
    HITLS_CERT_ERR_SET_CERT,                        /**< Failed to set the certificate. */
    HITLS_CERT_ERR_KEYUSAGE,                        /**< Failed to verify the certificate keyusage. */
    HITLS_CERT_ERR_INVALID_STORE_TYPE,              /**< Invalid store type */
    HITLS_CERT_ERR_X509_REF,                        /**< Certificate reference counting error. */
    HITLS_CERT_ERR_NO_KEYUSAGE,                     /**< No keyusage. */
    HITLS_CERT_KEY_CTRL_ERR_IS_DATA_ENC_USAGE,      /**< Determine whether the certificate fails to be data enc. */
    HITLS_CERT_KEY_CTRL_ERR_IS_NON_REPUDIATION_USAGE, /**< Determine whether the certificate fails to be
                                                           non-repudiation. */
    HITLS_CERT_CTRL_ERR_GET_SUBJECT_DN,             /**< Failed to obtain the subject DN of the certificate. */
    HITLS_CERT_STORE_CTRL_ERR_GET_VERIFY_DEPTH,     /**< Get the certificate verification depth error. */
	HITLS_CERT_STORE_CTRL_ERR_GET_VERIFY_FLAGS,    /**< Get the certificate verification flags error. */
    HITLS_CERT_CTRL_ERR_IS_SELF_SIGNED,             /** Determine whether the certificate is a self-signed
                                                        certificate */
    HITLS_CERT_ERR_INSERT_CERTPAIR,                 /**< Certificate insert certPair error. */
    HITLS_CERT_CTRL_ERR_INVALID_CMD,               /**< certificate ctrl invalid command */
	HITLS_CERT_STORE_CTRL_ERR_ADD_CRL_LIST,        /**< Failed to add CRL list to verify store. */
    HITLS_CERT_STORE_CTRL_ERR_CLEAR_CRL_LIST,      /**< Failed to clear CRL list from verify store. */

    HITLS_CRYPT_FAIL_START = 0x020D0001,           /**< Crypt adaptation module error code start bit. */
    HITLS_CRYPT_ERR_GENERATE_RANDOM,               /**< Failed to generate a random number. */
    HITLS_CRYPT_ERR_HMAC,                          /**< HMAC operation failure. */
    HITLS_CRYPT_ERR_DIGEST,                        /**< Hash operation failure. */
    HITLS_CRYPT_ERR_ENCRYPT,                       /**< Encryption failure. */
    HITLS_CRYPT_ERR_DECRYPT,                       /**< Decryption failure. */
    HITLS_CRYPT_ERR_ENCODE_ECDH_KEY,               /**< Failed to obtain the ECDH public key. */
    HITLS_CRYPT_ERR_CALC_SHARED_KEY,               /**< Failed to calculate the ECDH shared key. */
    HITLS_CRYPT_ERR_ENCODE_DH_KEY,                 /**< Failed to obtain the DH public key. */
    HITLS_CRYPT_ERR_HKDF_EXTRACT,                  /**< HKDF-Extract calculation error. */
    HITLS_CRYPT_ERR_HKDF_EXPAND,                   /**< HKDF-Expand calculation error. */
    HITLS_CRYPT_ERR_KEM_ENCAPSULATE,               /**< KEM-Encapsulate calculation error. */
    HITLS_CRYPT_ERR_KEM_DECAPSULATE,               /**< KEM-Decapsulate calculation error. */
    HITLS_CRYPT_ERR_DH,                            /**< DH failure. */
    HITLS_CRYPT_ERR_KDF,                           /**< KDF failure. */
    HITLS_CRYPT_ERR_GEN_KEY_PAIR,                  /**< Failed to generate key pair */

    HITLS_APP_FAIL_START = 0x020E0001,             /**< APP module error code start bit. */
    HITLS_APP_ERR_TOO_LONG_TO_WRITE,               /**< APP Data written is too long. */
    HITLS_APP_ERR_ZERO_READ_BUF_LEN,               /**< The buffer size read by the APP cannot be 0. */
    HITLS_APP_ERR_WRITE_BAD_RETRY,                 /**< The addresses of the buffers sent twice are inconsistent. */

    HITLS_SESS_FAIL_START = 0x02100001,            /**< Session feature error code start bit. */
    HITLS_SESS_ERR_SESSION_ID_GENRATE,             /**< Session id output error. */
    HITLS_SESS_ERR_DECODE_TICKET,                  /**< Error decoding session ticket object. */
    HITLS_SESS_ERR_SESSION_TICKET_SIZE_INCORRECT,  /**< Session ticket length is incorrect. */
    HITLS_SESS_ERR_SESSION_TICKET_HMAC_FAIL,       /**< Failed to calculate the session ticket hmac. */
    HITLS_SESS_ERR_SESSION_TICKET_KEY_FAIL,        /**< Failed to obtain the ticket key, and then link
                                                        establishment failed, so needs to sent alert. */
    HITLS_SESS_ERR_ENC_VERIFY_RESULT_FAIL,         /**< Failed to verify the encoding result. */
    HITLS_SESS_ERR_ENC_MASTER_SECRET_FAIL,         /**< Failed to encode the master secret. */
    HITLS_SESS_ERR_ENC_EXT_MASTER_SECRET_FAIL,     /**< Failed to encode the extend master secret. */
    HITLS_SESS_ERR_ENC_SESSION_ID_FAIL,            /**< Failed to encode the session ID. */
    HITLS_SESS_ERR_ENC_SESSION_ID_CTX_FAIL,        /**< Failed to encode the session ID context. */
    HITLS_SESS_ERR_ENC_HOST_NAME_FAIL,             /**< Failed to encode the host name. */
    HITLS_SESS_ERR_ENC_TIME_OUT_FAIL,              /**< Failed to encode the time out. */
    HITLS_SESS_ERR_ENC_VERSION_FAIL,               /**< Failed to encode the version. */
    HITLS_SESS_ERR_ENC_CIPHER_SUITE_FAIL,          /**< Failed to encode the ciphersuite. */
    HITLS_SESS_ERR_ENC_START_TIME_FAIL,            /**< Failed to encode the start time. */
    HITLS_SESS_ERR_ENC_PSK_IDENTITY_FAIL,          /**< Failed to encode the PSK identity. */
    HITLS_SESS_ERR_DEC_VERIFY_RESULT_FAIL,         /**< Failed to decode the verify result. */
    HITLS_SESS_ERR_DEC_VERSION_FAIL,               /**< Failed to decode the version. */
    HITLS_SESS_ERR_DEC_CIPHER_SUITE_FAIL,          /**< Fails to decode the cipher suite. */
    HITLS_SESS_ERR_DEC_MASTER_SECRET_FAIL,         /**< Failed to decode the master secret. */
    HITLS_SESS_ERR_DEC_PSK_IDENTITY_FAIL,          /**< Failed to decode the PSK identity. */
    HITLS_SESS_ERR_DEC_START_TIME_FAIL,            /**< Failed to decode the start time. */
    HITLS_SESS_ERR_DEC_TIME_OUT_FAIL,              /**< Failed to decode the time out. */
    HITLS_SESS_ERR_DEC_HOST_NAME_FAIL,             /**< Failed to decode the host name. */
    HITLS_SESS_ERR_DEC_SESSION_ID_CTX_FAIL,        /**< Failed to decode the session ID context. */
    HITLS_SESS_ERR_DEC_SESSION_ID_FAIL,            /**< Failed to decode the session ID. */
    HITLS_SESS_ERR_DEC_EXT_MASTER_SECRET_FAIL,     /**< Failed to decode the extended master secret. */
    HITLS_SESS_ERR_BAD_SESSION,                    /**< Invalid session in the unclosed state. */
    HITLS_SESS_ERR_ENC_PEER_CERT_FAIL,             /**< Failed to encode the peercert. */
    HITLS_SESS_ERR_DEC_PEER_CERT_FAIL,             /**< Failed to decode the peercert. */
    HITLS_SESS_ERR_FLUSH_FAIL,                     /**< Session flush failure. */
    HITLS_SESS_ERR_NOT_FOUND,                      /**< Session not found. */

    HITLS_X509_FAIL_START = 0x02120001,            /**< The X509 feature error code start bit of. */

    HITLS_CERT_SELF_ADAPT_ERR = 0x02130001,
    HITLS_CERT_SELF_ADAPT_INVALID_TIME,
    HITLS_CERT_SELF_ADAPT_UNSUPPORT_FORMAT,
    HITLS_CERT_SELF_ADAPT_BUILD_CERT_CHAIN_ERR,

    HITLS_CALLBACK_CERT_RETRY = 0x02140001,            /**< Certificate callback retry. */
    HITLS_CALLBACK_CERT_ERROR,                         /**< Certificate callback failure. */
    HITLS_CALLBACK_CLIENT_HELLO_ERROR,                 /**< ClientHello callback failure. */
    HITLS_CALLBACK_CLIENT_HELLO_RETRY,                 /**< ClientHello callback retry. */
    HITLS_CALLBACK_CLIENT_HELLO_INVALID_CALL,          /**< Invalid use of HITLS_ClientHelloGet* function. */
    HITLS_CALLBACK_CLIENT_HELLO_EXTENSION_NOT_FOUND,   /**< Extension not found. */
} HITLS_ERROR;

/**
 * @ingroup hitls_error
 * @brief   Obtain the TLS operation error code.
 *
 * @param   ctx [IN] TLS context
 * @param   ret [IN] Return value of the TLS interface called
 * @retval  HITLS_SUCCESS, No error.
 * @retval  HITLS_WANT_CONNECT, indicates that the connection is blocked.
 * You can call HITLS_Connect to continue the connection, This problem is usually caused
 * by the read and write operation failure.
 * @retval  HITLS_WANT_ACCEPT, indicates that the connection is blocked and the HITLS_Accept
 * can be called to continue the connection. This problem is usually caused by the read and write operation failure.
 * @retval  HITLS_WANT_READ, indicates that the receiving buffer is empty and the interface
 * can be called to continue receiving data.
 * @retval  HITLS_WANT_WRITE, indicates that the sending buffer is full and the interface
 * can be called to continue sending data.
 * @retval  HITLS_ERR_TLS, An unrecoverable fatal error occurs in the TLS protocol, usually a protocol error.
 * @retval  HITLS_ERR_SYSCALL, An unrecoverable I/O error occurs. Generally, the I/O error is caused
 * by the Low level receiving and receiving exception and an unknown error occurs.
 * @retval  HITLS_WANT_BACKUP, in the scenario where the bearer and control are separated,
 * the user needs to perform backup and restoration.
 */
int32_t HITLS_GetError(const HITLS_Ctx *ctx, int32_t ret);

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end HITLS_ERROR_H */
