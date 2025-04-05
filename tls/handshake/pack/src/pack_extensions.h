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

#ifndef PACK_EXTENSIONS_H
#define PACK_EXTENSIONS_H

#include <stdint.h>
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Hook function for packing extensions of client and server.
 */
typedef int32_t (*PACK_EXT_FUNC)(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len);

/**
 * PackExtInfo structure, used to transfer extension information of ClientHello messages
 */
typedef struct {
    uint16_t exMsgType;            /**< Extension type of message*/
    bool needPack;                 /**< Whether packing is needed */
    PACK_EXT_FUNC packFunc;        /**< Hook for packing extensions*/
} PackExtInfo;

typedef void (*GET_EXTSIZE_FUNC)(const TLS_Ctx *ctx, uint32_t *exSize);

typedef struct {
    bool needCheck;
    GET_EXTSIZE_FUNC getSizeFunc;
} GetExtFieldSize;

/**
 * @brief   Pack Client Hello extension
 *
 * @param   ctx [IN] TLS context
 * @param   buf [OUT] Returned handshake message buffer
 * @param   bufLen [IN]  Maximum buffer length of the handshake message
 * @param   len [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH The message buffer length is insufficient
 */
int32_t PackClientExtension(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len);

/**
 * @brief   Pack Server Hello extension
 *
 * @param   ctx [IN] TLS context
 * @param   buf [OUT] Returned handshake message buffer
 * @param   bufLen [IN] Maximum buffer length of the handshake message
 * @param   len [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH The message buffer length is insufficient
 */
int32_t PackServerExtension(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len);

/**
 * @brief   Pack an empty extension
 *
 * @param   ctx [IN] TLS context
 * @param   buf [OUT] Returned handshake message buffer
 * @param   bufLen [IN] Maximum buffer length of the handshake message
 * @param   len [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH The message buffer length is insufficient
 */
int32_t PackEmptyExtension(uint16_t exMsgType, bool needPack, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);
/**
 * @brief   Pack the header of an extension
 *
 * @param   exMsgType [IN] Extension type
 * @param   exMsgLen [IN] Extension length
 * @param   buf [OUT] Returned handshake message buffer
 * @param   bufLen [IN] Maximum buffer length of the handshake message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackExtensionHeader(uint16_t exMsgType, uint16_t exMsgLen, uint8_t *buf, uint32_t bufLen);

int32_t PackServerSelectAlpnProto(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);
#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end PACK_EXTENSIONS_H */