/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_BSL_SAL_LINUX) && defined(HITLS_BSL_SAL_DL)

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "bsl_errno.h"
#include "bsl_err_internal.h"

int32_t SAL_LoadLib(const char *fileName, void **handle)
{
    void *tempHandle = dlopen(fileName, RTLD_NOW);
    if (tempHandle == NULL) {
        char *error = dlerror();
        if (strstr(error, "No such file or directory") != NULL) {
            BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_NOT_FOUND);
            return BSL_SAL_ERR_DL_NOT_FOUND;
        }
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
        if (strstr(error, "undefined symbol") != NULL) {
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
