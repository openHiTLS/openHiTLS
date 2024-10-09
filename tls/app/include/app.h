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

#ifndef APP_H
#define APP_H

#include <stdint.h>
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup app
 * @brief Initialize the app module.
 *
 * @param ctx [IN] TLS context
 * @retval HITLS_SUCCESS Initializition successful.
 * @retval HITLS_MEMALLOC_FAIL Failed to apply for memory.
 */
int32_t APP_Init(TLS_Ctx *ctx);

/**
 * @ingroup app
 * @brief Deinitialize the app module.
 * @param ctx [IN] TLS context
 */
void APP_DeInit(TLS_Ctx *ctx);

/**
 * @ingroup app
 * @brief TLS can read data of any length, rather than in the unit of record. DTLS can read data in the unit of record.
 * Reads num number of bytes from the CTX to the buffer. Support input of any num bytes (num must be greater than 0).
 *
 * @attention Reads only the application data decrypted by one record at a time.
 * HITLS copies the application data to the input cache.
 * If the cache size is less than 16K, the maximum size of the application message decrypted from a single record is 16K
 * This will result in a partial copy of the application data.
 * You can call APP_GetReadPendingBytes to obtain the size of the remaining readable application data in current record.
 * This is useful in DTLS scenarios.
 *
 * @param ctx [IN] TLS context
 * @param buf [OUT] Place the data which read from the TLS context into the buffer.
 * @param num [IN] Attempting to read num bytes
 * @param readLen [OUT] Read length
 *
 * @retval HITLS_SUCCESS Read successful.
 * @retval Other return value refers to REC_Read.
 */
int32_t APP_Read(TLS_Ctx *ctx, uint8_t *buf, uint32_t num, uint32_t *readLen);

/**
 * @ingroup app
 * @brief Obtain the maximum writable plaintext length of a single record.
 *
 * @param ctx [IN] TLS_Ctx context
 * @param len [OUT] Maximum length of the plaintext
 *
 * @retval HITLS_SUCCESS Obtain successful.
 * @retval Other return value refers to REC_GetMaxWriteSize.
 */
int32_t APP_GetMaxWriteSize(const TLS_Ctx *ctx, uint32_t *len);

/**
 * @ingroup app
 * @brief Send app message in the unit of record.
 *
 * @param ctx [IN] TLS context
 * @param data [IN] Data to be written
 * @param dataLen [IN] Data length
 *
 * @retval HITLS_SUCCESS Write successful.
 * @retval HITLS_APP_ERR_TOO_LONG_TO_WRITE The data to be written is too long.
 * @retval Other reuturn value referst to REC_Write.
 */
int32_t APP_Write(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen);

/**
 * @ingroup app
 * @brief Processing of unexpected APP messages.
 * When receiving an APP message in the handshake, call this function to process the message.
 *
 * @param ctx [IN] TLS context
 * @param data [IN] Message body
 * @param len [IN] Message length
 *
 */
void APP_RecvUnexpectedMsgProcess(TLS_Ctx *ctx, const uint8_t *data, uint32_t len);

/**
 * @ingroup app
 * @brief Obtain the length of the remaining readable app messages in the current record.
 *
 * @param ctx [IN] TLS object
 * @retval Length of the remaining readable app message
 */
uint32_t APP_GetReadPendingBytes(const TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
