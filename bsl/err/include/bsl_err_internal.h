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

#define BSL_ERR_SET_MARK() (void)BSL_ERR_SetMark()

#define BSL_ERR_POP_TO_MARK() (void)BSL_ERR_PopToMark()

#else

#define BSL_ERR_PUSH_ERROR(e)

#define BSL_ERR_SET_MARK()

#define BSL_ERR_POP_TO_MARK()

#endif /* HITLS_BSL_ERR */

#ifdef __cplusplus
}
#endif

#endif // BSL_ERR_INTERNAL_H
