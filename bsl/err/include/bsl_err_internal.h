/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

#else

#define BSL_ERR_PUSH_ERROR(e)

#endif /* HITLS_BSL_ERR */

#ifdef __cplusplus
}
#endif

#endif // BSL_ERR_INTERNAL_H
