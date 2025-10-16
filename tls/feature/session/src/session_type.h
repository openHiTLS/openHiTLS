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

#ifndef SESSION_TYPE_H
#define SESSION_TYPE_H

#include <stdbool.h>
#include <stdint.h>
#include "hitls_type.h"
#include "hitls_session.h"
#include "tls_config.h"
#include "cert.h"
#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif

struct TlsSessionManager {
    void *lock;                                            /* Thread lock */
    int32_t references;                                    /* Reference times */

    void *hash;                                            /* hash table */

    uint64_t sessTimeout;                                  /* Session timeout interval, in seconds */
#ifdef HITLS_TLS_FEATURE_SESSION
    uint32_t sessCacheSize;                                /* session cache size: maximum number of sessions */
    uint32_t sessCacheMode;                   /* session cache mode */

    /* TLS1.2 session ticket */
    HITLS_TicketKeyCb ticketKeyCb;                         /* allows users to customize ticket keys through callback */
#endif
    /* key_name: is used to identify a specific set of keys used to protect tickets */
    uint8_t ticketKeyName[HITLS_TICKET_KEY_NAME_SIZE];
    uint8_t ticketAesKey[HITLS_TICKET_KEY_SIZE];           /* aes key */
    uint8_t ticketHmacKey[HITLS_TICKET_KEY_SIZE];          /* hmac key */
};

struct TlsSessCtx {
    void *lock;                                         /* Thread lock */
    /* certificate management context. The certificate interface depends on this field */
    CERT_MgrCtx *certMgrCtx;

    int32_t references;                                 /* Reference times */

    bool enable;                                        /* Whether to enable the session */
    bool haveExtMasterSecret;                           /* Whether an extended master key exists */
    bool reserved[2];                                   /* Four-byte alignment */

    uint64_t startTime;                                 /* Start time */
    uint64_t timeout;                                   /* Timeout interval */
#ifdef HITLS_TLS_FEATURE_SNI
    uint32_t hostNameSize;                              /* Length of the host name */
    uint8_t *hostName;                                  /* Host name */
#endif

    uint32_t sessionIdCtxSize;                                  /* Session ID Context Length */
    uint8_t sessionIdCtx[HITLS_SESSION_ID_CTX_MAX_SIZE];        /* Session ID Context */

    uint32_t sessionIdSize;                             /* Session ID length */
    uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE];       /* session ID */
    int32_t verifyResult;                               /* Authentication result */

    CERT_Pair *peerCert;                                /* Peer certificate */

    uint16_t version;                                   /* Version */
    uint16_t cipherSuite;                               /* Cipher suite */
    uint32_t masterKeySize;                             /* length of the master key */
    uint8_t masterKey[MAX_MASTER_KEY_SIZE];             /* Master Key */

    uint32_t ticketSize;                                /* Session ticket length */
    uint8_t *ticket;                                    /* Session ticket */
    uint32_t ticketLifetime;                            /* Timeout interval of the ticket */
    uint32_t ticketAgeAdd;                              /* A random number generated each time a ticket is issued */
    void *userData;
};

#define LIBCTX_FROM_SESSION_CTX(sessCtx) (sessCtx == NULL) ? NULL : ((sessCtx)->certMgrCtx == NULL ? NULL : (sessCtx)->certMgrCtx->libCtx)
#define ATTRIBUTE_FROM_SESSION_CTX(sessCtx) (sessCtx == NULL) ? NULL : ((sessCtx)->certMgrCtx == NULL ? NULL : (sessCtx)->certMgrCtx->attrName)

#ifdef __cplusplus
}
#endif

#endif
