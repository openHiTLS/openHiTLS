/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
    uint32_t sessCacheSize;                                /* session cache size: maximum number of sessions */
    HITLS_SESS_CACHE_MODE sessCacheMode;                   /* session cache mode */

    /* TLS1.2 session ticket */
    HITLS_TicketKeyCb ticketKeyCb;                         /* allows users to customize ticket keys through callback */
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

    uint32_t hostNameSize;                              /* Length of the host name */
    uint8_t *hostName;                                  /* Host name */

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
    uint32_t pskIdentitySize;                           /* pskIdentity length */
    uint8_t *pskIdentity;                               /* pskIdentity */

    uint32_t ticketSize;                                /* Session ticket length */
    uint8_t *ticket;                                    /* Session ticket */
    uint32_t ticketLifetime;                            /* Timeout interval of the ticket */
    uint32_t ticketAgeAdd;                              /* A random number generated each time a ticket is issued */
};

#ifdef __cplusplus
}
#endif

#endif
