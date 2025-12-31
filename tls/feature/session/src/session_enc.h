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

#ifndef SESSION_ENC_H
#define SESSION_ENC_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enumerated value of session information
 *  Do not change the enumerated value. If need add the enumerated value, add at the end
 */
typedef enum {
    SESS_OBJ_VERSION = 0x0101,
    SESS_OBJ_CIPHER_SUITE = 0x0102,
    SESS_OBJ_MASTER_SECRET = 0x0103,
    SESS_OBJ_PEER_CERT = 0x0104,
    SESS_OBJ_START_TIME = 0x0106,
    SESS_OBJ_TIMEOUT = 0x0107,
    SESS_OBJ_HOST_NAME = 0x0108,
    SESS_OBJ_SESSION_ID_CTX = 0x0109,
    SESS_OBJ_SESSION_ID = 0x010A,
    SESS_OBJ_SUPPORT_EXTEND_MASTER_SECRET = 0x010B,
    SESS_OBJ_VERIFY_RESULT = 0x010C,
    SESS_OBJ_AGE_ADD = 0x010D,
} SessionObjType;

/**
 * @brief   Obtain the length of the encoded SESS information
 *
 * @param   sess [IN] sess structure
 *
 * @retval  Length of the encoded data
 */
uint32_t SESS_GetTotalEncodeSize(const HITLS_Session *sess);

/**
 * @brief   Encode the SESS information to generate data
 *
 * @param   sess [IN] sess structure
 * @param   data [OUT] Packed data
 * @param   length [IN] Maximum length of the data array
 * @param   usedLen [OUT] Data length after packing
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t SESS_Encode(const HITLS_Session *sess, uint8_t *data, uint32_t length, uint32_t *usedLen);

/**
 * @brief   Decode data into SESS information
 *
 * @param   sess [OUT] sess structure
 * @param   data [IN] Data to be parsed
 * @param   length [IN] Length of the data to be parsed
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t SESS_Decode(HITLS_Session *sess, const uint8_t *data, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif
