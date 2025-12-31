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

#define REC_MAX_ENCRYPTED_OVERHEAD 2048u                  /* Maximum Encryption Overhead rfc5246 */
#ifdef HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT
#define REC_MAX_READ_ENCRYPTED_OVERHEAD (256u + 64u)        /* Maximum Encryption Overhead maxPadding + max(iv + mac) */
#define REC_MAX_WRITE_ENCRYPTED_OVERHEAD (16u + 64u)        /* Maximum Encryption Overhead minPadding + max(iv + mac) */
#else
#define REC_MAX_READ_ENCRYPTED_OVERHEAD REC_MAX_ENCRYPTED_OVERHEAD
#define REC_MAX_WRITE_ENCRYPTED_OVERHEAD REC_MAX_ENCRYPTED_OVERHEAD
#endif /* HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT */
#define REC_MAX_CIPHER_TEXT_LEN (REC_MAX_PLAIN_LENGTH + REC_MAX_ENCRYPTED_OVERHEAD)   /* Maximum ciphertext length */

#define REC_MAX_AES_GCM_ENCRYPTION_LIMIT 23726566u   /* RFC 8446 5.5 Limits on Key Usage AES-GCM SHOULD under 2^24.5 */

typedef struct {
    RecConnState *outdatedState;
    RecConnState *currentState;
    RecConnState *pendingState;
} RecConnStates;

typedef int32_t (*REC_ReadFunc)(TLS_Ctx *, REC_Type, uint8_t *, uint32_t *, uint32_t);
typedef int32_t (*REC_WriteFunc)(TLS_Ctx *, REC_Type, const uint8_t *, uint32_t);
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
    RecConnStates readStates;
    RecConnStates writeStates;
    RecBufList *hsRecList;      /* hs plaintext data cache */
    RecBufList *appRecList;     /* app plaintext data cache */
    uint32_t emptyRecordCnt;        /* Count of empty records */
#ifdef HITLS_TLS_PROTO_DTLS12
    uint16_t writeEpoch;
    uint16_t readEpoch;

    RecRetransmitList retransmitList; /* Cache the messages that may be retransmitted during the handshake */

    /* Process out-of-order messages */
    UnprocessedHsMsg unprocessedHsMsg;          /* used to cache out-of-order finished messages */
    /* unprocessed app message: app messages received in the CCS and finished receiving phases */
    UnprocessedAppMsg unprocessedAppMsgList;
#endif
    REC_ReadFunc recRead;
    void *rUserData;
    REC_WriteFunc recWrite;
    void *wUserData;
    REC_Type unexpectedMsgType;
    uint32_t pendingDataSize;               /* Data length */
    const uint8_t *pendingData;             /* Plain Data content */
} RecCtx;


/**
 * @brief   Obtain the size of the buffer for read and write operations
 *
 * @param   ctx [IN] TLS_Ctx context
 * @param   isRead [IN] is read buffer
 *
 * @retval  the size of the buffer for read and write operations
 */
uint32_t RecGetInitBufferSize(const TLS_Ctx *ctx, bool isRead);

int32_t RecDerefBufList(TLS_Ctx *ctx);

/**
 * @brief   free the record buffer
 *
 * @param   ctx [IN] TLS_Ctx context
 * @param   isOut [IN] is out buffer or not
 */
void RecTryFreeRecBuf(TLS_Ctx *ctx, bool isOut);

/**
 * @brief   Init the record io buffer
 *
 * @param   ctx [IN] TLS_Ctx context
 * @param   recordCtx [IN] record context
 * @param   isRead [IN] Init in buffer or not
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL malloc fail
 */
int32_t RecIoBufInit(TLS_Ctx *ctx, RecCtx *recordCtx, bool isRead);
#ifdef __cplusplus
}
#endif

#endif /* RECORD_H */
