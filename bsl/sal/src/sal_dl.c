/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"

#if defined(HITLS_BSL_SAL_DL)
#include <stdio.h>
#include <stdint.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"

#include "string.h"
#include "sal_dlimpl.h"
#include "sal_dl_local.h"
#include "bsl_binlog_id.h"
#include "bsl_log_internal.h"

static BSL_SAL_DlCallback g_dlCallback = {0};

// Define macro for path reserve length
#define BSL_SAL_PATH_RESERVE 10

#define BSL_SAL_PATH_MAX 4095

int32_t BSL_SAL_ConverterName(BSL_SAL_ConverterCmd cmd, const char *fileName, const char *dirName, char **name)
{
    if (fileName == NULL || dirName == NULL || name == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    int32_t ret = 0;
    char *tempName = NULL;
    // BSL_SAL_PATH_RESERVE is reserved for path separator, trailing \0, and possible future extensions
    uint32_t dlPathLen = strlen(dirName) + strlen(fileName);
    if (dlPathLen > BSL_SAL_PATH_MAX) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_PATH_EXCEED);
        return BSL_SAL_ERR_DL_PATH_EXCEED;
    }
    dlPathLen += BSL_SAL_PATH_RESERVE;
    tempName = (char *)BSL_SAL_Calloc(1, dlPathLen);
    if (tempName == NULL) {
        return BSL_MALLOC_FAIL;
    }
    switch (cmd) {
        case BSL_SAL_CONVERTER_LIBSO:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "%s/lib%s.so", dirName, fileName);
            break;
        case BSL_SAL_CONVERTER_LIBDLL:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "%s/lib%s.dll", dirName, fileName);
            break;
        case BSL_SAL_CONVERTER_DLL:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "%s/%s.dll", dirName, fileName);
            break;
        default:
            // Default to the first(BSL_SAL_CONVERTER_SO) conversion
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "%s/%s.so", dirName, fileName);
            break;
    }
    if (ret < 0) {
        BSL_SAL_Free(tempName);
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }
    *name = tempName;
    return BSL_SUCCESS;
}
    
int32_t BSL_SAL_LoadLib(const char *fileName, void **handle)
{
    if (fileName == NULL || handle == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_dlCallback.pdlopen != NULL) {
        return g_dlCallback.pdlopen(fileName, handle);
    }
#ifdef HITLS_BSL_SAL_DL
    return SAL_LoadLib(fileName, handle);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_LOAD_FAIL);
    return BSL_SAL_ERR_DL_LOAD_FAIL;
#endif
}


int32_t BSL_SAL_UnLoadLib(void *handle)
{
    if (handle == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_dlCallback.pdlclose != NULL) {
        return g_dlCallback.pdlclose(handle);
    }
#ifdef HITLS_BSL_SAL_DL
    return SAL_UnLoadLib(handle);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_UNLOAAD_FAIL);
    return BSL_SAL_ERR_DL_UNLOAAD_FAIL;
#endif
}

int32_t BSL_SAL_GetFuncAddress(void *handle, const char *funcName, void **func)
{
    if (handle == NULL || func == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_dlCallback.pdlsym != NULL) {
        return g_dlCallback.pdlsym(handle, funcName, func);
    }
#ifdef HITLS_BSL_SAL_DL
    return SAL_GetFunc(handle, funcName, func);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_LOOKUP_METHOD);
    return BSL_SAL_ERR_DL_LOOKUP_METHOD;
#endif
}


int32_t BSL_SAL_RegdlCallback(BSL_SAL_DlCallback *cb)
{
    if ((cb == NULL) || (cb->pdlopen == NULL) || (cb->pdlclose == NULL) || (cb->pdlsym == NULL)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05066, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid params", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    g_dlCallback.pdlopen = cb->pdlopen;
    g_dlCallback.pdlclose = cb->pdlclose;
    g_dlCallback.pdlsym = cb->pdlsym;
    return BSL_SUCCESS;
}


#endif /* HITLS_BSL_SAL_DL */
