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

#ifndef PARSER_COMMON_H
#define PARSER_COMMON_H

#include <stdint.h>
#include "tls.h"
#include "hs_msg.h"
#include "cert_method.h"
#include "security.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    TLS_Ctx *ctx;
    const uint8_t *buf;
    uint32_t bufLen;
    uint32_t *bufOffset;
} ParsePacket;

/**
 * @brief   Parse the version of the message
 *
 * @param   pkt [IN] Context for parsing
 * @param   version [OUT] Parsed version
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseVersion(ParsePacket *pkt, uint16_t *version);

/**
 * @brief   Parse random number in message
 *
 * @param   pkt [IN] Context for parsing
 * @param   random [OUT]  Parsed random number
 * @param   randomSize [IN] Random number length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMCPY_FAIL Memory Copy Failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseRandom(ParsePacket *pkt, uint8_t *random, uint32_t randomSize);

/**
 * @brief   Parse SessionId in message
 *
 * @param   pkt [IN] Context for parsing
 * @param   id [OUT] Parsed session ID
 * @param   idSize [OUT] Parsed session ID length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @retval  HITLS_MEMCPY_FAIL Memory Copy Failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseSessionId(ParsePacket *pkt, uint8_t *idSize, uint8_t **id);

/**
 * @brief   Parse Cookie in message
 *
 * @param   pkt [IN] Context for parsing
 * @param   cookie [OUT] Parsed cookie
 * @param   cookieLen [OUT] Parsed cookie length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @retval  HITLS_MEMCPY_FAIL Memory Copy Failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseCookie(ParsePacket *pkt, uint8_t *cookieLen, uint8_t **cookie);

/**
 * @brief   Parse TrustCA list in message
 *
 * @param   data [IN] TrustCAList message buffer
 * @param   buf [IN]  TrustCAList message buffer length
 *
 * @retval  HITLS_TrustedCAList * Pointer to the CAList header
 */
HITLS_TrustedCAList *ParseDNList(const uint8_t *data, uint32_t len);

/**
 * @brief   Free the buffer of TrustCAList
 *
 * @param   listHead [IN] Pointer to the CAList header
 *
 * @retval  void
 */
void FreeDNList(HITLS_TrustedCAList *caList);

/**
 * @brief   Parse uint8_t data
 *
 * @param   pkt [IN] Context for parsing
 * @param   object [OUT] Parsed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_PARSE_INVALID_MSG_LEN bufLen is not enough
 */
int32_t ParseBytesToUint8(ParsePacket *pkt, uint8_t *object);

/**
 * @brief   Parse uint16_t data
 *
 * @param   pkt [IN] Context for parsing
 * @param   object [OUT] Parsed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_PARSE_INVALID_MSG_LEN bufLen is not enough
 */
int32_t ParseBytesToUint16(ParsePacket *pkt, uint16_t *object);

/**
 * @brief   Parse 3 bytes data
 *
 * @param   pkt [IN] Context for parsing
 * @param   object [OUT] Parsed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_PARSE_INVALID_MSG_LEN bufLen is not enough
 */
int32_t ParseBytesToUint24(ParsePacket *pkt, uint32_t *object);

/**
 * @brief   Parse uint32_t data
 *
 * @param   pkt [IN] Context for parsing
 * @param   object [OUT] Parsed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_PARSE_INVALID_MSG_LEN bufLen is not enough
 */
int32_t ParseBytesToUint32(ParsePacket *pkt, uint32_t *object);

/**
 * @brief   Parse one byte length field, then parse the following content
 *
 * @param   pkt [IN] Context for parsing
 * @param   objectSize [OUT] Parsed one byte data length
 * @param   object [OUT] Parsed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_PARSE_INVALID_MSG_LEN bufLen is not enough
 */
int32_t ParseOneByteLengthField(ParsePacket *pkt, uint8_t *objectSize, uint8_t **object);

/**
 * @brief   Parse two byte length field, then parse the following content
 *
 * @param   pkt [IN] Context for parsing
 * @param   objectSize [OUT] Parsed one byte data length
 * @param   object [OUT] Parsed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_PARSE_INVALID_MSG_LEN bufLen is not enough
 */
int32_t ParseTwoByteLengthField(ParsePacket *pkt, uint16_t *objectSize, uint8_t **object);

/**
 * @brief   Parse data by length
 *
 * @param   pkt [IN] Context for parsing
 * @param   object [OUT] Parsed data, need memory allocation
 * @param   length [IN] Length of data need be parsed
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_PARSE_INVALID_MSG_LEN bufLen is not enough
 */
int32_t ParseBytesToArray(ParsePacket *pkt, uint8_t **object, uint32_t length);

/**
 * @brief   Parse data by length
 *
 * @param   pkt [IN] Context for parsing
 * @param   object [OUT] Parsed data, do not need memory allocation
 * @param   length [IN] Length of data need be parsed
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_PARSE_INVALID_MSG_LEN bufLen is not enough
 */
int32_t ParseCopyBytesToArray(ParsePacket *pkt, uint8_t *object, uint32_t length);

/**
 * @brief   Error processing function in parse module
 *
 * @param   ctx [IN] TLS context
 * @param   err [IN] Error code need to be pushed and returned
 * @param   logId [IN] binlogid
 * @param   format [IN] Message for log function
 * @param   description [IN] Alert description

 * @retval  error code
 */
int32_t ParseErrorProcess(TLS_Ctx *ctx, int32_t err, uint32_t logId, const void *format, ALERT_Description description);

/**
 * @brief   Check whether the peer certificate matches the peer signature algorithm.
 *
 * @param   ctx [IN] TLS context
 * @param   peerCert [IN] peerCert
 * @param   signScheme [IN] peer signScheme

 * @retval  error code
 */
int32_t CheckPeerSignScheme(HITLS_Ctx *ctx, CERT_Pair *peerCert, uint16_t signScheme);

int32_t ParseExtensionCommon(ParsePacket *pkt, uint16_t *exMsgLen);
#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end PARSER_COMMON_H */
