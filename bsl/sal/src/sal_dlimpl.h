/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SAL_DLIMPL_H
#define SAL_DLIMPL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_DL

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Load a dynamic library
 * @param fileName Name of the library file to load
 * @param handle Pointer to store the handle of the loaded library
 * @return 0 on success, non-zero error code on failure
 */
int32_t SAL_LoadLib(const char *fileName, void **handle);

/**
 * @brief Unload a previously loaded dynamic library
 * @param handle Handle of the library to unload
 * @return 0 on success, non-zero error code on failure
 */
int32_t SAL_UnLoadLib(void *handle);

/**
 * @brief Get a function pointer from a loaded library
 * @param handle Handle of the loaded library
 * @param funcName Name of the function to retrieve
 * @param func Pointer to store the function pointer
 * @return 0 on success, non-zero error code on failure
 */
int32_t SAL_GetFunc(void *handle, const char *funcName, void **func);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_SAL_DL */

#endif // SAL_DLIMPL_H
