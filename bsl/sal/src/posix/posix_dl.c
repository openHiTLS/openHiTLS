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

#include "hitls_build.h"
#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)) && defined(HITLS_BSL_SAL_DL)

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include "bsl_errno.h"
#include "bsl_err_internal.h"

int32_t SAL_LoadLib(const char *fileName, void **handle)
{
    /* Pre-check file accessibility to distinguish "not found" from "load failure"
     * access() is POSIX-standard and works on both Linux and macOS
     */
    if (access(fileName, R_OK) != 0) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_NOT_FOUND);
        return BSL_SAL_ERR_DL_NOT_FOUND;
    }

    void *tempHandle = dlopen(fileName, RTLD_NOW);
    if (tempHandle == NULL) {
        /* Clear any old error */
        (void)dlerror(); 
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_LOAD_FAIL);
        return BSL_SAL_ERR_DL_LOAD_FAIL;
    }
    *handle = tempHandle;
    return BSL_SUCCESS;
}

int32_t SAL_UnLoadLib(void *handle)
{
    int32_t ret = dlclose(handle);
    if (ret != 0) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_UNLOAAD_FAIL);
        return BSL_SAL_ERR_DL_UNLOAAD_FAIL;
    }
    return BSL_SUCCESS;
}

int32_t SAL_GetFunc(void *handle, const char *funcName, void **func)
{
    void *tempFunc = dlsym(handle, funcName);
    if (tempFunc == NULL) {
        char *error = dlerror();
        /* Check for symbol not found errors across different platforms:
         * - Linux: "undefined symbol"
         * - macOS: "symbol not found"
         */
        if (strstr(error, "undefined symbol") != NULL || strstr(error, "symbol not found") != NULL) {
            BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_NON_FUNCTION);
            return BSL_SAL_ERR_DL_NON_FUNCTION;
        }
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_LOOKUP_METHOD);
        return BSL_SAL_ERR_DL_LOOKUP_METHOD;
    }
    *func = tempFunc;
    return BSL_SUCCESS;
}

#endif
