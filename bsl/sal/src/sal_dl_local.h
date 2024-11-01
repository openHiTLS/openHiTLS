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
