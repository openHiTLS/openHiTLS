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
#ifdef HITLS_BSL_SAL_FILE

#include "bsl_err_internal.h"
#include "sal_fileimpl.h"

static BSL_SAL_FileCallback g_fileCallBack = { 0 };

int32_t SAL_FileCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type > BSL_SAL_FILE_GET_ATTR_FUNC || type < BSL_SAL_FILE_OPEN_CB_FUNC) {
        return BSL_SAL_FILE_NO_REG_FUNC;
    }
    uint32_t offset = (uint32_t)(type - BSL_SAL_FILE_OPEN_CB_FUNC);
    ((void **)&g_fileCallBack)[offset] = funcCb;
    return BSL_SUCCESS;
}

int32_t BSL_SAL_FileOpen(bsl_sal_file_handle *stream, const char *path, const char *mode)
{
    if (g_fileCallBack.pfFileOpen != NULL && g_fileCallBack.pfFileOpen != BSL_SAL_FileOpen) {
        return g_fileCallBack.pfFileOpen(stream, path, mode);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FOpen(stream, path, mode);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_FileRead(bsl_sal_file_handle stream, void *buffer, size_t size, size_t num, size_t *len)
{
    if (g_fileCallBack.pfFileRead != NULL && g_fileCallBack.pfFileRead != BSL_SAL_FileRead) {
        return g_fileCallBack.pfFileRead(stream, buffer, size, num, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FRead(stream, buffer, size, num, len);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_FileWrite(bsl_sal_file_handle stream, const void *buffer, size_t size, size_t num)
{
    if (g_fileCallBack.pfFileWrite != NULL && g_fileCallBack.pfFileWrite != BSL_SAL_FileWrite) {
        return g_fileCallBack.pfFileWrite(stream, buffer, size, num);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FWrite(stream, buffer, size, num);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

void BSL_SAL_FileClose(bsl_sal_file_handle stream)
{
    if (g_fileCallBack.pfFileClose != NULL && g_fileCallBack.pfFileClose != BSL_SAL_FileClose) {
        g_fileCallBack.pfFileClose(stream);
        return;
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    SAL_FILE_FClose(stream);
#endif
}

int32_t BSL_SAL_FileLength(const char *path, size_t *len)
{
    if (g_fileCallBack.pfFileLength != NULL && g_fileCallBack.pfFileLength != BSL_SAL_FileLength) {
        return g_fileCallBack.pfFileLength(path, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FLength(path, len);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

bool SAL_FileError(bsl_sal_file_handle stream)
{
    if (g_fileCallBack.pfFileError != NULL && g_fileCallBack.pfFileError != SAL_FileError) {
        return g_fileCallBack.pfFileError(stream);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FError(stream);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_FILE_NO_REG_FUNC);
    return false;
#endif
}

int32_t SAL_FileTell(bsl_sal_file_handle stream, long *pos)
{
    if (g_fileCallBack.pfFileTell != NULL && g_fileCallBack.pfFileTell != SAL_FileTell) {
        return g_fileCallBack.pfFileTell(stream, pos);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FTell(stream, pos);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

int32_t SAL_FileSeek(bsl_sal_file_handle stream, long offset, int32_t origin)
{
    if (g_fileCallBack.pfFileSeek != NULL && g_fileCallBack.pfFileSeek != SAL_FileSeek) {
        return g_fileCallBack.pfFileSeek(stream, offset, origin);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FSeek(stream, offset, origin);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

char *SAL_FGets(bsl_sal_file_handle stream, char *buf, int32_t readLen)
{
    if (g_fileCallBack.pfFileGets != NULL && g_fileCallBack.pfFileGets != SAL_FGets) {
        return g_fileCallBack.pfFileGets(stream, buf, readLen);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FGets(stream, buf, readLen);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_FILE_NO_REG_FUNC);
    return NULL;
#endif
}

bool SAL_FPuts(bsl_sal_file_handle stream, const char *buf)
{
    if (g_fileCallBack.pfFilePuts != NULL && g_fileCallBack.pfFilePuts != SAL_FPuts) {
        return g_fileCallBack.pfFilePuts(stream, buf);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FPuts(stream, buf);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_FILE_NO_REG_FUNC);
    return false;
#endif
}

bool SAL_Flush(bsl_sal_file_handle stream)
{
    if (g_fileCallBack.pfFileFlush != NULL && g_fileCallBack.pfFileFlush != SAL_Flush) {
        return g_fileCallBack.pfFileFlush(stream);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_Flush(stream);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_FILE_NO_REG_FUNC);
    return false;
#endif
}

int32_t SAL_Feof(bsl_sal_file_handle stream)
{
    if (g_fileCallBack.pfFileEof != NULL && g_fileCallBack.pfFileEof != SAL_Feof) {
        return g_fileCallBack.pfFileEof(stream);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_Feof(stream);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_FILE_NO_REG_FUNC);
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

int32_t SAL_FSetAttr(bsl_sal_file_handle stream, int cmd, const void *arg)
{
    if (g_fileCallBack.pfFileSetAttr != NULL && g_fileCallBack.pfFileSetAttr != SAL_FSetAttr) {
        return g_fileCallBack.pfFileSetAttr(stream, cmd, arg);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FSetAttr(stream, cmd, arg);
#else
    return BSL_SAL_FILE_NO_REG_FUNC;
#endif
}

int32_t SAL_FGetAttr(bsl_sal_file_handle stream, void *arg)
{
    if (g_fileCallBack.pfFileGetAttr != NULL && g_fileCallBack.pfFileGetAttr != SAL_FGetAttr) {
        return g_fileCallBack.pfFileGetAttr(stream, arg);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_FILE_FGetAttr(stream, arg);
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
    if (fileLen > UINT32_MAX - 1) {
        return BSL_SAL_ERR_FILE_LENGTH;
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

    ret = BSL_SAL_FileRead(stream, fileBuff, 1, fileLen, &readLen);
    BSL_SAL_FileClose(stream);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(fileBuff);
        return ret;
    }
    fileBuff[fileLen] = '\0';
    *buff = fileBuff;
    *len = (uint32_t)fileLen;
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
