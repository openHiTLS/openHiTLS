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

#define REC_MAX_PLAIN_TEXT_LENGTH 16384 /* Plain content length */

#define REC_MAX_ENCRYPTED_OVERHEAD 2048u /* Maximum Encryption Overhead rfc5246 */
#ifdef HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT
#define REC_MAX_READ_ENCRYPTED_OVERHEAD  (256u + 64u) /* Maximum Encryption Overhead maxPadding + max(iv + mac) */
#define REC_MAX_WRITE_ENCRYPTED_OVERHEAD (16u + 64u) /* Maximum Encryption Overhead minPadding + max(iv + mac) */
#else
#define REC_MAX_READ_ENCRYPTED_OVERHEAD  REC_MAX_ENCRYPTED_OVERHEAD
#define REC_MAX_WRITE_ENCRYPTED_OVERHEAD REC_MAX_ENCRYPTED_OVERHEAD
#endif /* HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT */
#define REC_MAX_CIPHER_TEXT_LEN (REC_MAX_PLAIN_LENGTH + REC_MAX_ENCRYPTED_OVERHEAD) /* Maximum ciphertext length */

#define REC_MAX_AES_GCM_ENCRYPTION_LIMIT 23726566u   /* RFC 8446 5.5 Limits on Key Usage AES-GCM SHOULD under 2^24.5 */
#define REC_MAX_AES_CCM_ENCRYPTION_LIMIT 8388608u   /* 2^23 */
#define REC_MAX_SM4_GCM_ENCRYPTION_LIMIT 4194303u  /* 2^22 - 1 */
#define REC_MAX_SM4_CCM_ENCRYPTION_LIMIT 1023u   /* 2^10 - 1 */

/* Decryption (integrity) limits per RFC 9147 §4.5.3 */
#define REC_MAX_AES_GCM_DECRYPTION_LIMIT        68719476736u             /* 2^36 */
#define REC_MAX_CHACHA20_DECRYPTION_LIMIT       68719476736u             /* 2^36 */
#define REC_MAX_AES_CCM_DECRYPTION_LIMIT        11863283u                /* 2^23.5 ≈ 11863283 */
#define REC_MAX_AES_CCM8_DECRYPTION_LIMIT       128u                     /* 2^7 */

#define REC_DTLS13_ACK_ITEM_LEN (sizeof(uint64_t) * 2u)
#define REC_DTLS13_ACK_LIST_MAX_COUNT 128u

/* Maximum number of rejected early data bytes the server discards while skipping 0-RTT records
 * (RFC 8446 section 4.2.10). Exceeding the budget terminates the connection with a fatal
 * unexpected_message alert. Records are counted by ciphertext body; empty records count the
 * 5-byte record header so that they cannot spin the discard path forever. */
#define REC_MAX_EARLY_DATA_DISCARD_SIZE 16384u

typedef struct {
    RecConnState *outdatedState;
    RecConnState *currentState;
    RecConnState *pendingState;
} RecConnStates;

typedef int32_t (*REC_ReadFunc)(TLS_Ctx *, REC_Type, uint8_t *, uint32_t *, uint32_t);
typedef int32_t (*REC_WriteFunc)(TLS_Ctx *, REC_Type, const uint8_t *, uint32_t);

typedef struct Dtls13SeqMapEntry {
    RecordNumber recordNumber;
    Dtls13FragmentRange frag;
    bool valid;
} Dtls13SeqMapEntry;

typedef struct Dtls13GapNode {
    ListHead head;
    uint32_t start;
    uint32_t end;
} Dtls13GapNode;

typedef struct {
    ListHead gaps;
    uint32_t totalLen;
    uint32_t unackedBytes;
    Dtls13SeqMapEntry *seqMap;
    uint32_t seqMapSize;
    uint32_t seqMapCap;
} Dtls13AckState;

struct RecRetransmitList {
    ListHead head; /* Linked list header */
    bool isExistCcsMsg; /* Check whether CCS messages exist in the retransmission message queue */
    REC_Type type; /* message type */
    uint8_t *msg; /* message data */
    uint32_t len; /* message length */
#ifdef HITLS_TLS_PROTO_DTLS13
    uint8_t hsType;         /* DTLS1.3 handshake message type */
    uint16_t epoch; /* DTLS1.3 message epoch */
    uint64_t nextRecordSeq; /* DTLS1.3 next record sequence used when the original write state is gone */
    uint32_t bodyLen; /* DTLS1.3 handshake body length */
    Dtls13AckState ackState;
    REC_Dtls13RetransmitAckCb ackCb; /* DTLS1.3 callback after this node is fully ACKed */
#endif
};

typedef struct RecCtx {
    RecBuf *inBuf; /* Buffer for reading data */
    RecBuf *outBuf; /* Buffer for writing data */
    RecConnStates readStates;
    RecConnStates writeStates;
    RecBufList *hsRecList; /* hs plaintext data cache */
    RecBufList *appRecList; /* app plaintext data cache */
    uint32_t emptyRecordCnt; /* Count of empty records */
    /* 0-RTT discard mode state (RFC 8446 section 4.2.10), owned by the record layer: the
     * handshake layer arms it through REC_SetEarlyDataDiscard() once a rejected ClientHello
     * carrying early_data is processed; the record layer disarms it on the first record that
     * deprotects successfully. */
    bool discardEarlyData;
    uint32_t earlyDataDiscardBytes; /* Accumulated size of dropped rejected 0-RTT records */
#if defined(HITLS_TLS_PROTO_DATAGRAM)
    uint16_t writeEpoch;
    uint16_t readEpoch;
    uint64_t lastWriteEpochSeq;
    bool hasLastWriteEpochSeq;
#endif
#ifdef HITLS_TLS_PROTO_DTLS13
    Dtls13AckList ackList;
    Dtls13AckList retransAckList;
    bool needSendRetransAck;
#endif
#if defined(HITLS_TLS_PROTO_DATAGRAM)
    RecRetransmitList retransmitList; /* Cache the messages that may be retransmitted during the handshake */
#endif

#if defined(HITLS_TLS_PROTO_DATAGRAM)
    /* unprocessed app message: app messages received in the CCS and finished receiving phases */
    UnprocessedMsg UnprocessedMsgList;
#endif
    REC_ReadFunc recRead;
    void *rUserData;
    REC_WriteFunc recWrite;
    void *wUserData;
    REC_Type unexpectedMsgType;
    uint32_t pendingDataSize; /* Data length */
    const uint8_t *pendingData; /* Plain Data content */
    uint8_t pendingRecordType; /* pending record type */
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
