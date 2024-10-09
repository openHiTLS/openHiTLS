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

/**
 * @defgroup bsl_init
 * @ingroup bsl
 * @brief initialization
 */

#ifndef BSL_INIT_H
#define BSL_INIT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_init
 * @brief Initialize the BSL module.
 *
 * The user must call this interface to initialize.
 *
 * @attention None.
 * @retval #BSL_SUCCESS, error code module is successfully initialized.
 * @retval #BSL_MALLOC_FAIL, memory space is insufficient and thread lock space cannot be applied for.
 * @retval #BSL_SAL_ERR_UNKNOWN, thread lock initialization failed.
 */
int32_t BSL_GLOBAL_Init(void);

/**
 * @ingroup bsl_init
 * @brief Deinitialize the BSL module.
 *
 * The user calls this interface when the process exits.
 *
 * @attention None
 */
int32_t BSL_GLOBAL_DeInit(void);

#ifdef __cplusplus
}
#endif

#endif // BSL_INIT_H