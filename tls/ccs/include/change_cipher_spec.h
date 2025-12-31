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

#ifndef CHANGE_CIPHER_SPEC_H
#define CHANGE_CIPHER_SPEC_H

#include <stdint.h>
#include "hitls_build.h"
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup change cipher spec
 * @brief CCS initialization function
 *
 * @param ctx [IN] SSL context
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_INTERNAL_EXCEPTION     An unexpected internal error occurs.
 * @retval HITLS_MEMALLOC_FAIL          Failed to apply for memory.
 */
int32_t CCS_Init(TLS_Ctx *ctx);

/**
 * @ingroup change cipher spec
 * @brief   CCS deinitialization function
 *
 * @param   ctx [IN] ssl context
 *
 */
void CCS_DeInit(TLS_Ctx *ctx);

/**
 * @ingroup change cipher spec
 * @brief   Check whether the Change cipher spec message is received.
 *
 * @param   ctx [IN] TLS context
 *
 * @return  Check whether the Change cipher spec message is received.
 */
bool CCS_IsRecv(const TLS_Ctx *ctx);

/**
 * @ingroup change cipher spec
 * @brief Send a packet for changing the cipher suite.
 *
 * @param ctx [IN] TLS context
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_INTERNAL_EXCEPTION     An unexpected internal error occurs.
 * @retval For other error codes, see REC_Write.
 */
int32_t CCS_Send(TLS_Ctx *ctx);

/**
 * @ingroup change cipher spec
 * @brief Control function
 *
 * @param ctx [IN] TLS context
 * @param cmd [IN] Control command
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_INTERNAL_EXCEPTION     An unexpected internal error
 * @retval HITLS_CCS_INVALID_CMD        Invalid instruction
 */
int32_t CCS_Ctrl(TLS_Ctx *ctx, CCS_Cmd cmd);

/**
 * @brief Process CCS message after decryption
 *
 * @attention ctx cannot be empty.
 * @param ctx [IN] tls Context
 * @param data [IN] ccs data
 * @param dataLen [IN] ccs data length
 * @retval HITLS_REC_NORMAL_RECV_UNEXPECT_MSG
 */
int32_t ProcessDecryptedCCS(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen);

/**
 * @brief Process plaintext CCS message in TLS13
 *
 * @attention ctx cannot be empty.
 * @param ctx [IN] tls Context
 * @param data [IN] ccs data
 * @param dataLen [IN] ccs data length
 * @retval HITLS_REC_NORMAL_RECV_UNEXPECT_MSG
 */
int32_t ProcessPlainCCS(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen);
#ifdef __cplusplus
}
#endif

#endif
