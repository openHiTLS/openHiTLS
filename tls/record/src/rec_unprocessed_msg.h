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

#if defined(HITLS_TLS_PROTO_DTLS12) || defined(HITLS_TLS_PROTO_DTLS13)

/*  rfc6083 4.7 Handshake
    User messages that arrive between ChangeCipherSpec and Finished
    messages and use the new epoch have probably passed the Finished
    message and MUST be buffered by DTLS until the Finished message is
    read.
*/
typedef struct {
    ListHead head;
    uint32_t count; /* Number of cached record messages */
    RecHdr hdr; /* record header */
    uint8_t *recordBody; /* record body */
} UnprocessedMsg; /* Unprocessed App messages: App messages that are out of order with finished */

UnprocessedMsg *UnprocessedMsgNew(void);

void UnprocessedMsgFree(UnprocessedMsg *msg);

void UnprocessedMsgListInit(UnprocessedMsg *appMsgList);

void UnprocessedMsgListDeinit(UnprocessedMsg *appMsgList);

int32_t UnprocessedMsgListAppend(UnprocessedMsg *appMsgList, const RecHdr *hdr, const uint8_t *recordBody);

UnprocessedMsg *UnprocessedMsgGet(UnprocessedMsg *appMsgList, uint16_t curEpoch);

#endif /* HITLS_TLS_PROTO_DTLS12 || HITLS_TLS_PROTO_DTLS13 */

#ifdef __cplusplus
}
#endif

#endif
