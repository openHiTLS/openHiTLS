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

#if defined(HITLS_BSL_SAL_DL)
#include <stdio.h>
#include <stdint.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"

#include "string.h"
#include "sal_dlimpl.h"
#include "bsl_log_internal.h"

static BSL_SAL_DlCallback g_dlCallback = {0};

// Define macro for path reserve length
#define BSL_SAL_PATH_RESERVE 10
#define BSL_SAL_NAME_MAX 255

int32_t SAL_DlCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type > BSL_SAL_DL_SYM_CB_FUNC || type < BSL_SAL_DL_OPEN_CB_FUNC) {
        return BSL_SAL_DL_NO_REG_FUNC;
    }
    uint32_t offset = (uint32_t)(type - BSL_SAL_DL_OPEN_CB_FUNC);
    ((void **)&g_dlCallback)[offset] = funcCb;
    return BSL_SUCCESS;
}

int32_t BSL_SAL_LibNameFormat(BSL_SAL_LibFmtCmd cmd, const char *fileName, char **name)
{
    if (fileName == NULL || name == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    int32_t ret = 0;
    char *tempName = NULL;
    size_t fileNameLen = strlen(fileName);
    if (fileNameLen > (BSL_SAL_NAME_MAX - BSL_SAL_PATH_RESERVE)) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_PATH_EXCEED);
        return BSL_SAL_ERR_DL_PATH_EXCEED;
    }
    size_t dlPathLen = fileNameLen + BSL_SAL_PATH_RESERVE;
    tempName = (char *)BSL_SAL_Calloc(1, dlPathLen);
    if (tempName == NULL) {
        return BSL_MALLOC_FAIL;
    }

    /* Select appropriate library extension based on operating system:
     * - Darwin (macOS/iOS): .dylib (Mach-O dynamic library format)
     * - Linux/Unix (Linux, Solaris, AIX, FreeBSD, OpenBSD, NetBSD): .so (ELF shared object)
     */
#if defined(HITLS_BSL_SAL_DARWIN)
    const char *lib_ext = "dylib";
#else /* HITLS_BSL_SAL_LINUX and other Unix-like systems (Solaris, AIX, *BSD) */
    const char *lib_ext = "so";
#endif

    switch (cmd) {
        case BSL_SAL_LIB_FMT_SO:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "%s.%s", fileName, lib_ext);
            break;
        case BSL_SAL_LIB_FMT_LIBSO:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "lib%s.%s", fileName, lib_ext);
            break;
        case BSL_SAL_LIB_FMT_LIBDLL:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "lib%s.dll", fileName);
            break;
        case BSL_SAL_LIB_FMT_DLL:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "%s.dll", fileName);
            break;
        case BSL_SAL_LIB_FMT_OFF:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "%s", fileName);
            break;
        default:
            // Default to the first(BSL_SAL_LIB_FMT_SO) conversion
            BSL_SAL_Free(tempName);
            BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
            return BSL_SAL_ERR_BAD_PARAM;
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
    if (g_dlCallback.pfDlOpen != NULL && g_dlCallback.pfDlOpen != BSL_SAL_LoadLib) {
        return g_dlCallback.pfDlOpen(fileName, handle);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_LoadLib(fileName, handle);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_DL_NO_REG_FUNC);
    return BSL_SAL_DL_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_UnLoadLib(void *handle)
{
    if (handle == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_dlCallback.pfDlClose != NULL && g_dlCallback.pfDlClose != BSL_SAL_UnLoadLib) {
        return g_dlCallback.pfDlClose(handle);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_UnLoadLib(handle);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_DL_NO_REG_FUNC);
    return BSL_SAL_DL_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_GetFuncAddress(void *handle, const char *funcName, void **func)
{
    if (func == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_dlCallback.pfDlSym != NULL && g_dlCallback.pfDlSym != BSL_SAL_GetFuncAddress) {
        return g_dlCallback.pfDlSym(handle, funcName, func);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_GetFunc(handle, funcName, func);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_DL_NO_REG_FUNC);
    return BSL_SAL_DL_NO_REG_FUNC;
#endif
}

#endif /* HITLS_BSL_SAL_DL */
