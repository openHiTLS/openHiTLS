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
 
#ifndef PARSE_EXTENSIONS_H
#define PARSE_EXTENSIONS_H

#include <stdint.h>
#include "tls.h"
#include "hs_msg.h"
#include "parse_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Parse Client Hello extension
 *
 * @attention The input parameter pointer can't be NULL
 *            If parsing fails, the invoker releases the allocated memory
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer, starting from the extension type
 * @param   bufLen [IN] Message length
 * @param   msg [OUT] Parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG Extension duplicated
 */
int32_t ParseClientExtension(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg);

/**
 * @brief   Release the buffer in the Client Hello extension structure
 *
 * @param   msg [IN] Message structure
 */
void CleanClientHelloExtension(ClientHelloMsg *msg);

/**
 * @brief   Parse server hello extension
 *
 * @attention The input parameter pointer can't be NULL
 *            If the parsing fails, the invoker releases the allocated memory
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer, starting from the extension type
 * @param   bufLen [IN] Message length
 * @param   msg [OUT] Parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG Extension duplicated
 * @retval  HITLS_PARSE_UNSUPPORTED_EXTENSION Unsupported extension
 */
int32_t ParseServerExtension(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg);
/**
 * @brief   Parse extension type and length
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer, starting from the extension type
 * @param   bufLen [IN] Message length
 * @param   extMsgType [OUT] Extension type
 * @param   extMsgLen [OUT] Extension length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG Extension duplicated
 */
int32_t ParseExHeader(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint16_t *extMsgType, uint32_t *extMsgLen);
/**
 * @brief   Release the buffer in the Server Hello extension structure
 *
 * @param   msg [IN] Message structure
 */
void CleanServerHelloExtension(ServerHelloMsg *msg);
/**
 * @brief   Parse empty extension
 *
 * @param   ctx [IN] TLS context
 * @param   extMsgType [IN] Extension type
 * @param   extMsgLen [IN] Extension length
 * @param   haveExtension [OUT] Indicates whether there are extensions
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG Extension duplicated
 */
int32_t ParseEmptyExtension(TLS_Ctx *ctx, uint16_t extMsgType, uint32_t extMsgLen, bool *haveExtension);

int32_t ParseExCookie(const uint8_t *buf, uint32_t bufLen, uint8_t **cookie, uint16_t *cookieLen);

int32_t ParseSecRenegoInfo(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint8_t **secRenegoInfo,
    uint8_t *secRenegoInfoSize);

int32_t ParseRecordSizeLimit(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
                             bool *haveRecordSizeLimit, uint16_t *recordSizeLimit);

int32_t ParseServerSelectedAlpnProtocol(
    ParsePacket *pkt, bool *haveSelectedAlpn, uint8_t **alpnSelected, uint16_t *alpnSelectedSize);

/**
 * @brief   error procrss in duplicated extension
 *
 * @param   ctx [IN] TLS context
 * @param   logId [IN] binlogid
 * @param   format [IN] Message for log function

 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG
 */
int32_t ParseDupExtProcess(TLS_Ctx *ctx, uint32_t logId, const void *format);

/**
 * @brief   parse extension length error
 *
 * @param   ctx [IN] TLS context
 * @param   logId [IN] binlogid
 * @param   format [IN] Message for log function

 * @retval  HITLS_PARSE_INVALID_MSG_LEN
 */
int32_t ParseErrorExtLengthProcess(TLS_Ctx *ctx, uint32_t logId, const void *format);

bool GetExtensionFlagValue(TLS_Ctx *ctx, uint32_t hsExTypeId);

int32_t CheckForDuplicateExtension(ParsePacket *pkt, uint16_t *extMsgType, uint32_t *extMsgLen,
    uint32_t *extensionId, uint64_t extensionTypeMask);
#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end PARSE_EXTENSIONS_H */
