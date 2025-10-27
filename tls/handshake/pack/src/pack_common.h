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

#ifndef PACK_COMMON_H
#define PACK_COMMON_H

#include <stdint.h>
#include "tls.h"
#include "pack.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Pack session ID
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   id [IN] Session ID
 * @param   idSize [IN] Session ID length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PACK_SESSIONID_ERR Failed to pack sessionId
 * @retval  HITLS_MEMALLOC_FAIL Grow buffer failed
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Buffer is not enough
 */
int32_t PackSessionId(PackPacket *pkt, const uint8_t *id, uint32_t idSize);

/**
 * @brief   Pack DTLS message header
 *
 * @param   type [IN] Message type
 * @param   sequence [IN] Sequence number (only in DTLS)
 * @param   length [IN] Length of message body
 * @param   buf [OUT] Message header
 */
void PackDtlsMsgHeader(HS_MsgType type, uint16_t sequence, uint32_t length, uint8_t *buf);

int32_t PackTrustedCAList(HITLS_TrustedCAList *caList, PackPacket *pkt);

int32_t PackCertificateReqCtx(const TLS_Ctx *ctx, PackPacket *pkt);

int32_t PackHelloCommonField(const TLS_Ctx *ctx, PackPacket *pkt, uint16_t version, bool isClient);
#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end PACK_COMMON_H */