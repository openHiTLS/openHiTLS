/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef REC_UNPROCESSED_MSG_H
#define REC_UNPROCESSED_MSG_H

#include <stdint.h>
#include "bsl_module_list.h"
#include "rec_header.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HITLS_NO_DTLS12

typedef struct {
    RecHdr hdr;                     /* record header */
    uint8_t *recordBody;            /* record body */
} UnprocessedHsMsg;                 /* Unprocessed handshake messages */

/*  rfc6083 4.7 Handshake
    User messages that arrive between ChangeCipherSpec and Finished
    messages and use the new epoch have probably passed the Finished
    message and MUST be buffered by DTLS until the Finished message is
    read.
*/
typedef struct {
    ListHead head;
    uint32_t count;                 /* Number of cached record messages */
    RecHdr hdr;                     /* record header */
    uint8_t *recordBody;            /* record body */
} UnprocessedAppMsg;                /* Unprocessed App messages: App messages that are out of order with finished */

void CacheNextEpochHsMsg(UnprocessedHsMsg *unprocessedHsMsg, const RecHdr *hdr, const uint8_t *recordBody);

UnprocessedAppMsg *UnprocessedAppMsgNew(void);

void UnprocessedAppMsgFree(UnprocessedAppMsg *msg);

void UnprocessedAppMsgListInit(UnprocessedAppMsg *appMsgList);

void UnprocessedAppMsgListDeinit(UnprocessedAppMsg *appMsgList);

int32_t UnprocessedAppMsgListAppend(UnprocessedAppMsg *appMsgList, const RecHdr *hdr, const uint8_t *recordBody);

UnprocessedAppMsg *UnprocessedAppMsgGet(UnprocessedAppMsg *appMsgList);

#endif // HITLS_NO_DTLS12

#ifdef __cplusplus
}
#endif

#endif