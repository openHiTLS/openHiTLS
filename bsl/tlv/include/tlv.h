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

#ifndef TLV_H
#define TLV_H

#include "hitls_build.h"
#ifdef HITLS_BSL_TLV

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLV_HEADER_LENGTH (sizeof(uint32_t) + sizeof(uint32_t))

typedef struct {
    uint32_t type;
    uint32_t length;
    uint8_t *value;
} BSL_Tlv;

/**
 * @ingroup bsl_tlv
 * @brief Construct a TLV message based on the TLV structure.
 *
 * @param tlv [IN] TLV structure
 * @param buffer [OUT] Message memory
 * @param bufLen [IN] Memory length
 * @param usedLen [OUT] Message length
 *
 * @retval BSL_SUCCESS              successfully created.
 * @retval BSL_TLV_ERR_BAD_PARAM    Parameter incorrect
 * @retval BSL_MEMCPY_FAIL  Memory Copy Failure
 */
int32_t BSL_TLV_Pack(const BSL_Tlv *tlv, uint8_t *buffer, uint32_t bufLen, uint32_t *usedLen);

/**
 * @ingroup bsl_tlv
 * @brief Parse the TLV message of the specified type and generate the TLV structure.
 *
 * @param wantType [IN] TLV type
 * @param data [IN] TLV message memory
 * @param dataLen [IN] Message length
 * @param tlv [OUT] TLV Structure
 * @param readLen [OUT] Length of the parsed message
 *
 * @retval BSL_SUCCESS              parsed successfully.
 * @retval BSL_TLV_ERR_BAD_PARAM    Parameter incorrect
 * @retval BSL_MEMCPY_FAIL  Memory Copy Failure
 * @retval BSL_TLV_ERR_NO_WANT_TYPE No TLV found
 */
int32_t BSL_TLV_Parse(uint32_t wantType, const uint8_t *data, uint32_t dataLen, BSL_Tlv *tlv, uint32_t *readLen);

/**
 * @ingroup bsl_tlv
 * @brief Find the TLV of the specified type
 *        and calculate the offset from the memory start address to the TLV data.
 *
 * @param wantType [IN] TLV type
 * @param data [IN] TLV message memory
 * @param dataLen [IN] Message length
 * @param offset [OUT] TLV data offset
 * @param length [OUT] Data length
 *
 * @retval BSL_SUCCESS              succeeded.
 * @retval BSL_TLV_ERR_BAD_PARAM    Parameter incorrect
 * @retval BSL_TLV_ERR_NO_WANT_TYPE No TLV found
 */
int32_t BSL_TLV_FindValuePos(uint32_t wantType, const uint8_t *data, uint32_t dataLen,
    uint32_t *offset, uint32_t *length);

#ifdef __cplusplus
}
#endif
#endif /* HITLS_BSL_TLV */
#endif // TLV_H
