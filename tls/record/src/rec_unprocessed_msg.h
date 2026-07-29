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

#ifndef REC_UNPROCESSED_MSG_H
#define REC_UNPROCESSED_MSG_H

#include <stdint.h>
#include "bsl_module_list.h"
#include "rec_header.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(HITLS_TLS_PROTO_DATAGRAM)

/*  rfc6083 4.7 Handshake
    User messages that arrive between ChangeCipherSpec and Finished
    messages and use the new epoch have probably passed the Finished
    message and MUST be buffered by DTLS until the Finished message is
    read.
*/
/**
 * @brief A cached DTLS record waiting for a matching epoch and record type.
 *
 * This structure is used as both the list head and a record node.
 * The list head uses head and count.
 * A record node uses head, hdr, and recordBody.
 */
typedef struct {
    ListHead head;  /* List head or links of a cached record node. */
    uint32_t count; /* Number of record nodes. Valid only in the list head. */
    RecHdr hdr;     /* Parsed record header. Valid only in a record node. */
    /* Wire-format body copied before record decryption.
     * Plaintext if unprotected; ciphertext plus protection fields if protected.
     * Protection fields can include an IV, explicit nonce, or authentication tag.
     */
    uint8_t *recordBody;
} UnprocessedMsg;

UnprocessedMsg *UnprocessedMsgNew(void);

void UnprocessedMsgFree(UnprocessedMsg *msg);

void UnprocessedMsgListInit(UnprocessedMsg *appMsgList);

void UnprocessedMsgListDeinit(UnprocessedMsg *appMsgList);

int32_t UnprocessedMsgListAppend(UnprocessedMsg *appMsgList, const RecHdr *hdr, const uint8_t *recordBody);

UnprocessedMsg *UnprocessedMsgGet(UnprocessedMsg *appMsgList, uint16_t curEpoch, uint8_t recordType);

#endif /* HITLS_TLS_PROTO_DATAGRAM */

#ifdef __cplusplus
}
#endif

#endif
