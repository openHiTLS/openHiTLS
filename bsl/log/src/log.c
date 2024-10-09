/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_BSL_LOG

#include <stdbool.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_log.h"
#include "bsl_log_internal.h"

/* string of HiTLS version */
static char g_openHiTLSVersion[HITLS_VERSION_LEN] = OPENHITLS_VERSION_S;
static uint32_t g_openHiTLSNumVersion = OPENHITLS_VERSION_I;

int32_t BSL_LOG_GetVersion(char *version, uint32_t *versionLen)
{
    if (version == NULL || versionLen == NULL) {
        return BSL_LOG_ERR_BAD_PARAM;
    }

    if (*versionLen < HITLS_VERSION_LEN) {
        return BSL_LOG_ERR_BAD_PARAM;
    }

    uint32_t len = (uint32_t)strlen(g_openHiTLSVersion);
    if (memcpy_s(version, *versionLen, g_openHiTLSVersion, len) != EOK) {
        return BSL_MEMCPY_FAIL;
    }

    *versionLen = len;
    return BSL_SUCCESS;
}

uint32_t BSL_LOG_GetVersionNum(void)
{
    return g_openHiTLSNumVersion;
}

static BSL_LOG_BinLogFixLenFunc g_fixLenFunc = NULL;
static BSL_LOG_BinLogVarLenFunc g_varLenFunc = NULL;
static uint32_t g_binlogLevel = BSL_LOG_LEVEL_ERR; // error-level is enabled by default
static uint32_t g_binlogType = BSL_LOG_BINLOG_TYPE_RUN; // type run is enabled by default, other types can be added.

int32_t BSL_LOG_RegBinLogFunc(const BSL_LOG_BinLogFuncs *funcs)
{
    bool invalid = funcs == NULL || funcs->fixLenFunc == NULL || funcs->varLenFunc == NULL;
    if (invalid) {
        return BSL_NULL_INPUT;
    }
    g_fixLenFunc = funcs->fixLenFunc;
    g_varLenFunc = funcs->varLenFunc;
    return BSL_SUCCESS;
}

int32_t BSL_LOG_SetBinLogLevel(uint32_t level)
{
    if (level > BSL_LOG_LEVEL_DEBUG) {
        return BSL_LOG_ERR_BAD_PARAM;
    }
    g_binlogLevel = level;
    return BSL_SUCCESS;
}

uint32_t BSL_LOG_GetBinLogLevel(void)
{
    return g_binlogLevel;
}

void BSL_LOG_BinLogFixLen(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4)
{
    bool invalid = (logLevel > g_binlogLevel) || ((logType & g_binlogType) == 0) || (g_fixLenFunc == NULL);
    if (!invalid) {
        g_fixLenFunc(logId, logLevel, logType, format, para1, para2, para3, para4);
    }
}

void BSL_LOG_BinLogVarLen(uint32_t logId, uint32_t logLevel, uint32_t logType, void *format, void *para)
{
    bool invalid = (logLevel > g_binlogLevel) || ((logType & g_binlogType) == 0) || (g_varLenFunc == NULL);
    if (!invalid) {
        g_varLenFunc(logId, logLevel, logType, format, para);
    }
}
#endif /* HITLS_BSL_LOG */
