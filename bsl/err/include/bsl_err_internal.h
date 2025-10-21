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

#ifndef BSL_ERR_INTERNAL_H
#define BSL_ERR_INTERNAL_H

#include <stdint.h>
#include "hitls_build.h"
#include "bsl_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HITLS_BSL_ERR

/**
 * @ingroup bsl_err
 * @brief Save the error information to the error information stack.
 *
 * @par Description:
 * Save the error information to the error information stack.
 *
 * @attention err cannot be 0.
 * @param err [IN] Error code. The most significant 16 bits indicate the submodule ID,
 *                 and the least significant 16 bits indicate the error ID.
 * @param file [IN] File name, excluding the directory path
 * @param lineNo [IN] Number of the line where the error occurs.
 */
void BSL_ERR_PushError(int32_t err, const char *file, uint32_t lineNo);

#ifdef HITLS_BSL_ERR_ENHANCE
/**
 * @ingroup bsl_err
 * @brief Save the error information to the error information stack.
 *
 * @par Description:
 * Save the error information to the error information stack.
 *
 * @attention err cannot be 0.
 * @param err [IN] Error code. The most significant 16 bits indicate the submodule ID,
 *                 and the least significant 16 bits indicate the error ID.
 * @param format [IN] Log format character string
 * @param ... [IN] format Parameter
 */
void BSL_ERR_SetErrorReason(int32_t err, const char *format, ...);

/**
 * @ingroup bsl_err
 * @brief Obtain the error code, file name, and line number of the earliest push message in the error stack.
 *
 * @par Description:
 * When an error occurs on a HiTLS interface, the user obtains an error code, file name, and line number.
 * The obtained information is not deleted from the error stack.
 *
 * @param reason [OUT] Obtain the err reason of the file where the error occurs.
 * @param file [OUT] Obtains the name of the file where the error occurs, excluding the directory path.
 * @param lineNo [OUT] Obtain the line number of the file where the error occurs.
 * @return Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : It may be blocked.
 * Time consuming  : Not time-consuming.
 * If either of the two parameters is null, the file name and line number cannot be obtained.
 */
int32_t BSL_ERR_GetErrorReason(const char **reason, const char **file, uint32_t *lineNo);

/**
 * @ingroup bsl_err
 * @brief Obtain the error code, file name, and line number of the earliest push message in the error stack.
 *
 * @par Description:
 * When an error occurs on a HiTLS interface, the user obtains an error code, file name, and line number.
 * The obtained information is not deleted from the error stack.
 *
 * @param reason [OUT] Obtain the err reason of the file where the error occurs.
 * @param file [OUT] Obtains the name of the file where the error occurs, excluding the directory path.
 * @param lineNo [OUT] Obtain the line number of the file where the error occurs.
 * @return Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : It may be blocked.
 * Time consuming  : Not time-consuming.
 * If either of the two parameters is null, the file name and line number cannot be obtained.
 */
int32_t BSL_ERR_PeekErrorReason(const char **reason, const char **file, uint32_t *lineNo);

/**
 * @ingroup bsl_err
 * @brief Obtain the error code, file name, and line number of the last push message in the error stack.
 *
 * @par Description:
 * When an error occurs on a HiTLS interface, the user obtains an error code, file name, and line number.
 * The obtained information is not deleted from the error stack.
 *
 * @param reason [OUT] Obtain the err reason of the file where the error occurs.
 * @param file [OUT] Obtains the name of the file where the error occurs, excluding the directory path.
 * @param lineNo [OUT] Obtain the line number of the file where the error occurs.
 * @return Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : It may be blocked.
 * Time consuming  : Not time-consuming.
 * If either of the two parameters is null, the file name and line number cannot be obtained.
 */
int32_t BSL_ERR_GetLastErrorReason(const char **reason, const char **file, uint32_t *lineNo);

/**
 * @ingroup bsl_err
 * @brief Obtain the error code, file name, and line number of the last push message in the error stack.
 *
 * @par Description:
 * When an error occurs on a HiTLS interface, the user obtains an error code, file name, and line number.
 * The obtained information is not deleted from the error stack.
 *
 * @param reason [OUT] Obtain the err reason of the file where the error occurs.
 * @param file [OUT] Obtains the name of the file where the error occurs, excluding the directory path.
 * @param lineNo [OUT] Obtain the line number of the file where the error occurs.
 * @return Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : It may be blocked.
 * Time consuming  : Not time-consuming.
 * If either of the two parameters is null, the file name and line number cannot be obtained.
 */
int32_t BSL_ERR_PeekLastErrorReason(const char **reason, const char **file, uint32_t *lineNo);
#endif

/**
 * @ingroup bsl_err
 * @brief Save the error information to the error information stack.
 *
 * @par Description:
 * Save the error information to the error information stack.
 *
 * @attention e cannot be 0.
 */
#define BSL_ERR_PUSH_ERROR(e) BSL_ERR_PushError((e), __FILENAME__, __LINE__)

#else

#define BSL_ERR_PUSH_ERROR(e)

#endif /* HITLS_BSL_ERR */

#ifdef __cplusplus
}
#endif

#endif // BSL_ERR_INTERNAL_H
