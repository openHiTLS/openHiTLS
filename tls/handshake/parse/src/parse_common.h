/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef PARSER_COMMON_H
#define PARSER_COMMON_H

#include <stdint.h>
#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Parse the version of the message
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN]  Message buffer, starting from version
 * @param   bufLen [IN]  Maximum message length
 * @param   version [OUT] Parsed version
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseVersion(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint16_t *version);

/**
 * @brief   Parse random number in message
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN]  Message buffer, starting from random number
 * @param   bufLen [IN]  Maximum message length
 * @param   random [OUT]  Parsed random number
 * @param   randomSize [IN] Random number length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMCPY_FAIL Memory Copy Failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseRandom(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint8_t *random, uint32_t randomSize);

/**
 * @brief   Parse SessionId in message
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN]  Message buffer. The first byte is the length of the session ID
 * @param   bufLen [IN]  Maximum message length
 * @param   id [OUT] Parsed session ID
 * @param   idSize [OUT] Parsed session ID length
 * @param   readLen [OUT] Length of parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @retval  HITLS_MEMCPY_FAIL Memory Copy Failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseSessionId(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
                       uint8_t **id, uint8_t *idSize, uint32_t *readLen);

/**
 * @brief   Parse Cookie in message
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN]  Message buffer. The first byte is the cookie length.
 * @param   bufLen [IN]  Maximum message length
 * @param   cookie [OUT] Parsed cookie
 * @param   cookieLen [OUT] Parsed cookie length
 * @param   readLen [OUT] Length of parsed messag
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @retval  HITLS_MEMCPY_FAIL Memory Copy Failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseCookie(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
                    uint8_t **cookie, uint8_t *cookieLen, uint32_t *readLen);

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end PARSER_COMMON_H */
