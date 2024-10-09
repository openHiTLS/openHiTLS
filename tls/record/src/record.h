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

#ifndef RECORD_H
#define RECORD_H

#include "tls.h"
#include "rec.h"
#include "rec_header.h"
#include "rec_unprocessed_msg.h"
#include "rec_buf.h"
#include "rec_conn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define REC_MAX_PLAIN_TEXT_LENGTH 16384     /* Plain content length */

#define REC_MAX_ENCRYPTED_OVERHEAD 2048u                                              /* Maximum Encryption Overhead */
#define REC_MAX_CIPHER_TEXT_LEN (REC_MAX_PLAIN_LENGTH + REC_MAX_ENCRYPTED_OVERHEAD)   /* Maximum ciphertext length */

#define REC_MAX_AES_GCM_ENCRYPTION_LIMIT 23726566u   /* RFC 8446 5.5 Limits on Key Usage AES-GCM SHOULD under 2^24.5 */

typedef struct {
    RecConnState *outdatedState;
    RecConnState *currentState;
    RecConnState *pendingState;
} RecConnStates;

typedef struct {
    ListHead head;          /* Linked list header */
    bool isExistCcsMsg;     /* Check whether CCS messages exist in the retransmission message queue */
    REC_Type type;          /* message type */
    uint8_t *msg;           /* message data */
    uint32_t len;           /* message length */
} RecRetransmitList;

typedef struct RecCtx {
    RecBuf *inBuf;                  /* Buffer for reading data */
    RecBuf *outBuf;                 /* Buffer for writing data */
    bool hasReadBufDecrypted;
    RecConnStates readStates;
    RecConnStates writeStates;

#ifndef HITLS_NO_DTLS12
    uint16_t writeEpoch;
    uint16_t readEpoch;

    RecRetransmitList retransmitList; /* Cache the messages that may be retransmitted during the handshake */

    /* Process out-of-order messages */
    UnprocessedHsMsg unprocessedHsMsg;          /* used to cache out-of-order finished messages */
    /* unprocessed app message: app messages received in the CCS and finished receiving phases */
    UnprocessedAppMsg unprocessedAppMsgList;
#endif
} RecCtx;


/**
 * @brief   Obtain the size of the buffer for read and write operations
 *
 * @param   ctx [IN] TLS_Ctx context
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Access a null pointer
 */
uint32_t RecGetInitBufferSize(const TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* RECORD_H */
