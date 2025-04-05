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

#if defined(HITLS_BSL_SAL_FILE)
#include <stdint.h>
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "sal_fileimpl.h"

static BSL_SAL_FileCallback g_filleCallBack = {0};

int32_t SAL_FileCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type > BSL_SAL_FILE_LENGTH_CB_FUNC || type < BSL_SAL_FILE_OPEN_CB_FUNC) {
        return BSL_SAL_FILE_NO_REG_FUNC;
    }
    uint32_t offet = (uint32_t)(type - BSL_SAL_FILE_OPEN_CB_FUNC);
    ((void **)&g_filleCallBack)[offet] = funcCb;
    return BSL_SUCCESS;
}

int32_t BSL_SAL_FileOpen(bsl_sal_file_handle *stream, const char *path, const char *mode)
{
    if (g_filleCallBack.pfFileOpen != NULL && g_filleCallBack.pfFileOpen != BSL_SAL_FileOpen) {
        return g_filleCallBack.pfFileOpen(stream, path, mode);
    }
#ifdef HITLS_BSL_SAL_LINUX
    return SAL_FileOpen(stream, path, mode);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_FileRead(bsl_sal_file_handle stream, void *buffer, size_t size, size_t num, size_t *len)
{
    if (g_filleCallBack.pfFileRead != NULL && g_filleCallBack.pfFileRead != BSL_SAL_FileRead) {
        return g_filleCallBack.pfFileRead(stream, buffer, size, num, len);
    }
#ifdef HITLS_BSL_SAL_LINUX
    return SAL_FileRead(stream, buffer, size, num, len);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_FileWrite(bsl_sal_file_handle stream, const void *buffer, size_t size, size_t num)
{
    if (g_filleCallBack.pfFileWrite != NULL && g_filleCallBack.pfFileWrite != BSL_SAL_FileWrite) {
        return g_filleCallBack.pfFileWrite(stream, buffer, size, num);
    }
#ifdef HITLS_BSL_SAL_LINUX
    return SAL_FileWrite(stream, buffer, size, num);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

void BSL_SAL_FileClose(bsl_sal_file_handle stream)
{
    if (g_filleCallBack.pfFileClose != NULL && g_filleCallBack.pfFileClose != BSL_SAL_FileClose) {
        g_filleCallBack.pfFileClose(stream);
        return;
    }
#ifdef HITLS_BSL_SAL_LINUX
    SAL_FileClose(stream);
#endif
}

int32_t BSL_SAL_FileLength(const char *path, size_t *len)
{
    if (g_filleCallBack.pfFileLength != NULL && g_filleCallBack.pfFileLength != BSL_SAL_FileLength) {
        return g_filleCallBack.pfFileLength(path, len);
    }
#ifdef HITLS_BSL_SAL_LINUX
    return SAL_FileLength(path, len);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_ReadFile(const char *path, uint8_t **buff, uint32_t *len)
{
    size_t readLen;
    size_t fileLen = 0;
    int32_t ret = BSL_SAL_FileLength(path, &fileLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    bsl_sal_file_handle stream = NULL;
    ret = BSL_SAL_FileOpen(&stream, path, "rb");
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    uint8_t *fileBuff = BSL_SAL_Malloc((uint32_t)fileLen + 1);
    if (fileBuff == NULL) {
        BSL_SAL_FileClose(stream);
        return BSL_MALLOC_FAIL;
    }
    do {
        ret = BSL_SAL_FileRead(stream, fileBuff, 1, fileLen, &readLen);
        BSL_SAL_FileClose(stream);
        if (ret != BSL_SUCCESS) {
            break;
        }
        fileBuff[fileLen] = '\0';
        *buff = fileBuff;
        *len = (uint32_t)fileLen;
        return ret;
    } while (0);
    BSL_SAL_FREE(fileBuff);
    return ret;
}

int32_t BSL_SAL_WriteFile(const char *path, const uint8_t *buff, uint32_t len)
{
    bsl_sal_file_handle stream = NULL;
    int32_t ret = BSL_SAL_FileOpen(&stream, path, "wb");
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    ret = BSL_SAL_FileWrite(stream, buff, 1, len);
    BSL_SAL_FileClose(stream);
    return ret;
}

#endif
