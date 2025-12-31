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

#ifndef REC_WRITE_H
#define REC_WRITE_H

#include <stdint.h>
#include "rec.h"
#include "rec_buf.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Write a record in TLS
 *
 * @param   ctx [IN] TLS context
 * @param   recordType [IN] Record type
 * @param   data [IN] Data to be written
 * @param   plainLen [IN] plain length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval  HITLS_REC_NORMAL_IO_BUSY I/O busy
 * @retval  HITLS_REC_ERR_SN_WRAPPING Sequence number wrap
 */
int32_t TlsRecordWrite(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t plainLen);

#ifdef HITLS_TLS_PROTO_DTLS12

/**
 * @brief   Write a record in DTLS
 *
 * @param   ctx [IN] TLS context
 * @param   recordType [IN] Record type
 * @param   data [IN] Data to be written
 * @param   plainLen [IN] plain length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval  HITLS_REC_NORMAL_IO_BUSY I/O busy
 * @retval  HITLS_REC_ERR_SN_WRAPPING Sequence number wrap
 */
int32_t DtlsRecordWrite(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t plainLen);

#endif

/*
 * @brief   Write data to the UIO of the TLS context
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Send buffer
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval  HITLS_REC_NORMAL_IO_BUSY I/O busy
 */
int32_t StreamWrite(TLS_Ctx *ctx, RecBuf *buf);

#ifdef __cplusplus
}
#endif

#endif