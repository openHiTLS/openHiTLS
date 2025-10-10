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

#ifndef BSL_PRINT_H
#define BSL_PRINT_H

#include "hitls_build.h"
#ifdef HITLS_BSL_PRINT
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "bsl_types.h"
#include "bsl_sal.h"
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const char BSL_PRINT_MONTH_STR[12][4];

#define BSL_PRINT_TIME_FMT "%s %u %02u:%02u:%02u %u GMT"

/**
 * @ingroup bsl_print
 * @brief Print asn1 data.
 *
 * @param layer   [IN] Print layer.
 * @param uio     [IN/OUT] Print uio context.
 * @param buff    [IN] Print buffer.
 * @param buffLen [IN] Print buffer length.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_PRINT_Buff(uint32_t layer, BSL_UIO *uio, const void *buff, uint32_t buffLen);

/**
 * @ingroup bsl_print
 * @brief Print the format string..
 *
 * @param layer [IN] Print layer.
 * @param uio   [IN/OUT] Print uio context.
 * @param fmt   [IN] Print format.
 * @param ...   [IN] Print data.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_PRINT_Fmt(uint32_t layer, BSL_UIO *uio, const char *fmt, ...);

/**
 * @ingroup bsl_print
 * @brief Print Hex function.
 *
 * @param layer   [IN] Print layer.
 * @param data    [IN] Print data.
 * @param oneLine [IN] Print on one line.
 * @param dataLen [IN] Print data length
 * @param uio     [IN/OUT] Print uio context.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_PRINT_Hex(uint32_t layer, bool oneLine, const uint8_t *data, uint32_t dataLen, BSL_UIO *uio);

/**
 * @ingroup bsl_print
 * @brief Print time function.
 *
 * @param layer   [IN] Print layer.
 * @param time    [IN] Time.
 * @param uio     [IN/OUT] Print uio context.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_PRINT_Time(uint32_t layer, const BSL_TIME *time, BSL_UIO *uio);

/**
 * @ingroup bsl_print
 * @brief Print Number function.
 *
 * @param layer   [IN] Print layer.
 * @param title   [IN] Print title.
 * @param data    [IN] Print data.
 * @param dataLen [IN] Print data length
 * @param uio     [IN/OUT] Print uio context.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_PRINT_Number(uint32_t layer, const char *title, const uint8_t *data, uint32_t dataLen, BSL_UIO *uio);

#ifdef __cplusplus
}
#endif

#endif

#endif // BSL_PRINT_H
