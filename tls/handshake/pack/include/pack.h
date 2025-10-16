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

#ifndef PACK_H
#define PACK_H

#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Pack handshake messages
 *
 * @param   ctx  [IN] TLS context
 * @param   type  [IN] Message type
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t HS_PackMsg(TLS_Ctx *ctx, HS_MsgType type);

/**
 * @brief   Pack uint8_t to buffer
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   value [IN] packed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_MEMALLOC_FAIL Grow buffer failed
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Buffer is not enough
 */
int32_t PackAppendUint8ToBuf(PackPacket *pkt, uint8_t value);

/**
 * @brief   Pack uint16_t to buffer
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   value [IN] packed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_MEMALLOC_FAIL Grow buffer failed
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Buffer is not enough
 */
int32_t PackAppendUint16ToBuf(PackPacket *pkt, uint16_t value);

/**
 * @brief   Pack uint24_t to buffer
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   value [IN] packed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_MEMALLOC_FAIL Grow buffer failed
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Buffer is not enough
 */
int32_t PackAppendUint24ToBuf(PackPacket *pkt, uint32_t value);

/**
 * @brief   Pack uint32_t to buffer
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   value [IN] packed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_MEMALLOC_FAIL Grow buffer failed
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Buffer is not enough
 */
int32_t PackAppendUint32ToBuf(PackPacket *pkt, uint32_t value);

/**
 * @brief   Pack uint64_t to buffer
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   value [IN] packed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_MEMALLOC_FAIL Grow buffer failed
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Buffer is not enough
 */
int32_t PackAppendUint64ToBuf(PackPacket *pkt, uint64_t value);

/**
 * @brief   Pack data to buffer
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   data [IN] packed data
 * @param   size [IN] size of packed data
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_MEMALLOC_FAIL Grow buffer failed
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Buffer is not enough
 */
int32_t PackAppendDataToBuf(PackPacket *pkt, const uint8_t *data, uint32_t size);

/**
 * @brief   Reserve bytes in the handshake buffer for packing, without increasing offset.
 * The reservedBuf should be used immediately after this function is called. Since the buffer may be reallocated.
 * If input reservedBuf == NULL, just prepare Handshake message buffer for handshake message packing.
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   size [IN] reserved data size
 * @param   reservedBuf [OUT] reserved buffer pointer
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_MEMALLOC_FAIL Grow buffer failed
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Buffer is not enough
 */
int32_t PackReserveBytes(PackPacket *pkt, uint32_t size, uint8_t **reservedBuf);

/**
 * @brief   It means a buffer with size bytes length is needed to be packed. It reserves bytes to be filled as length.
 * After the bytes is reserved, the offset will increase, and return the position of the length value.
 * After the following buffer has been packed, use the PackCloseUintXField fucntion with returned position before to
 * calculate the length and fill the length value.
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   size [IN] allocate data size
 * @param   allocatedPosition [OUT] allocated buffer offset
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_MEMALLOC_FAIL Grow buffer failed
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Buffer is not enough
 */
int32_t PackStartLengthField(PackPacket *pkt, uint32_t size, uint32_t *allocatedPosition);

/**
 * @brief   Increasing offset in the handshake buffer, without allocating memory.
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   size [IN] Offset size to skip
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Buffer is not enough
 */
int32_t PackSkipBytes(PackPacket *pkt, uint32_t size);

/**
 * @brief   After finish packing a buffer with a uint8_t length, pack the length field at the start of the buffer.
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   position [IN] The start position of the field
 */
void PackCloseUint8Field(const PackPacket *pkt, uint32_t position);

/**
 * @brief   After finish packing a buffer with a uint16_t length, pack the length field at the start of the buffer.
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   position [IN] The start position of the field
 */
void PackCloseUint16Field(const PackPacket *pkt, uint32_t position);

/**
 * @brief   After finish packing a buffer with a uint24_t length, pack the length field at the start of the buffer.
 *
 * @param   pkt [IN/OUT] Context for packing
 * @param   position [IN] The start position of the field
 */
void PackCloseUint24Field(const PackPacket *pkt, uint32_t position);

/**
 * @brief   Get a subbuffer from the handshake buffer, which starts from the start position,
 * ends at the current offset, and length is the length of the sub-buffer.
 *
 * @attention The reservedBuf should be used immediately after this function is called.
 * @param   pkt [IN] Context for packing
 * @param   start [IN] The start position of the sub-buffer
 * @param   length [OUT] The length of the sub-buffer
 * @param   buf [OUT] The pointer of the sub-buffer
 *
 * @retval  HITLS_SUCCESS success
 * @retval  HITLS_PACK_NOT_ENOUGH_BUF_LENGTH Start exceeds the current offset
 */
int32_t PackGetSubBuffer(const PackPacket *pkt, uint32_t start, uint32_t *length, uint8_t **buf);
#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif