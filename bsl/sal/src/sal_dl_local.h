/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef BSL_SAL_DL_LOCAL_H
#define BSL_SAL_DL_LOCAL_H

#include <stdint.h>
#include "sal_atomic.h"
#include "crypt_eal_implprovider.h"
#include "bsl_list.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @ingroup bsl_sal
 *
 * Registrable function structure for loading dynamic libraries.
 */
struct DlCallback {
    /**
     * @ingroup bsl_sal
     * @brief Loading dynamic libraries.
     *
     * Loading dynamic libraries.
     *
     * @param fileName [IN] Path of dl
     * @param handle [OUT] Dynamic library handle
     * @retval #BSL_SUCCESS Succeeded.
     * @retval #BSL_SAL_ERR_DL_NOT_FOUND Library file not found.
     * @retval #BSL_SAL_ERR_DL_LOAD_FAIL Failed to load the library.
     */
    int32_t (*pdlopen)(const char *fileName, void **handle);

    /**
     * @ingroup bsl_sal
     * @brief Close dynamic library.
     *
     * Close dynamic library.
     *
     * @param handle [IN] Dynamic library handle
     * @retval #BSL_SUCCESS Succeeded.
     * @retval #BSL_SAL_ERR_DL_UNLOAAD_FAIL Failed to unload the library.
     */
    int32_t (*pdlclose)(void *handle);

    /**
     * @ingroup bsl_sal
     * @brief Get function symbol from dynamic library.
     *
     * Get function symbol from dynamic library.
     *
     * @param handle [IN] Dynamic library handle
     * @param funcName [IN] Function name
     * @param func [OUT] Function pointer
     * @retval #BSL_SUCCESS Succeeded.
     * @retval #BSL_SAL_ERR_DL_NON_FUNCTION Symbol found but is not a function.
     * @retval #BSL_SAL_ERR_DL_LOOKUP_METHOD Failed to lookup the function.
     */
    int32_t (*pdlsym)(void *handle, const char *funcName, void **func);
};

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // BSL_SAL_DL_LOCAL_H
