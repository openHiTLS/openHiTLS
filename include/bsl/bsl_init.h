/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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