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
#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)) && defined(HITLS_BSL_SAL_FILE)

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include "bsl_errno.h"
#include "sal_file.h"
#include "bsl_sal.h"

int32_t SAL_FILE_FOpen(bsl_sal_file_handle *stream, const char *path, const char *mode)
{
    bsl_sal_file_handle temp = NULL;

    if (path == NULL || path[0] == 0 || mode == NULL || stream == NULL) {
        return BSL_NULL_INPUT;
    }

    temp = (bsl_sal_file_handle)fopen(path, mode);
    if (temp == NULL) {
        return BSL_SAL_ERR_FILE_OPEN;
    }

    (*stream) = temp;
    return BSL_SUCCESS;
}

int32_t SAL_FILE_FRead(bsl_sal_file_handle stream, void *buffer, size_t size, size_t num, size_t *len)
{
    if (stream == NULL || buffer == NULL || len == NULL) {
        return BSL_NULL_INPUT;
    }
    *len = fread(buffer, size, num, stream);
    if (*len != num) {
        return feof(stream) != 0 ? BSL_SUCCESS : BSL_SAL_ERR_FILE_READ;
    }
    return BSL_SUCCESS;
}

int32_t SAL_FILE_FWrite(bsl_sal_file_handle stream, const void *buffer, size_t size, size_t num)
{
    if (stream == NULL || buffer == NULL) { /* size should not be more than 2^31 - 1 */
        return BSL_NULL_INPUT;
    }
    size_t ret = fwrite(buffer, size, num, stream);

    return ret == num ? BSL_SUCCESS : BSL_SAL_ERR_FILE_WRITE;
}

void SAL_FILE_FClose(bsl_sal_file_handle stream)
{
    if (stream == NULL) {
        return;
    }
    (void)fclose(stream);
}

int32_t SAL_FILE_FLength(const char *path, size_t *len)
{
    int32_t ret;
    long tmp;
    bsl_sal_file_handle stream = NULL;

    if (path == NULL || len == NULL) {
        return BSL_NULL_INPUT;
    }

    ret = BSL_SAL_FileOpen(&stream, path, "rb");
    if (ret != BSL_SUCCESS) {
        return BSL_SAL_ERR_FILE_LENGTH;
    }

    ret = fseek(stream, 0, SEEK_END);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FileClose(stream);
        return BSL_SAL_ERR_FILE_LENGTH;
    }

    tmp = ftell(stream);
    if (tmp < 0) {
        BSL_SAL_FileClose(stream);
        return BSL_SAL_ERR_FILE_LENGTH;
    }

    *len = (size_t)tmp;

    BSL_SAL_FileClose(stream);

    return BSL_SUCCESS;
}

bool SAL_FILE_FError(bsl_sal_file_handle stream)
{
    if (stream == NULL) {
        return false;
    }
    return ferror(stream) != 0;
}

int32_t SAL_FILE_FTell(bsl_sal_file_handle stream, long *pos)
{
    if (stream == NULL || pos == NULL) {
        return BSL_NULL_INPUT;
    }

    *pos = ftell(stream);
    return (*pos < 0) ? BSL_SAL_ERR_FILE_TELL : BSL_SUCCESS;
}

int32_t SAL_FILE_FSeek(bsl_sal_file_handle stream, long offset, int32_t origin)
{
    if (stream == NULL) {
        return BSL_NULL_INPUT;
    }

    if (fseek(stream, offset, origin) == 0) {
        return BSL_SUCCESS;
    }

    return BSL_SAL_ERR_FILE_SEEK;
}

char *SAL_FILE_FGets(bsl_sal_file_handle stream, char *buf, int32_t readLen)
{
    if (buf == NULL || readLen <= 0 || stream == NULL) {
        return NULL;
    }

    return fgets(buf, readLen, stream);
}

bool SAL_FILE_FPuts(bsl_sal_file_handle stream, const char *buf)
{
    if (buf == NULL || stream == NULL) {
        return false;
    }
    return fputs(buf, stream) != EOF;
}

bool SAL_FILE_Flush(bsl_sal_file_handle stream)
{
    if (stream == NULL) {
        return false;
    }
    return fflush(stream) != EOF;
}

int32_t SAL_FILE_Feof(bsl_sal_file_handle stream)
{
    if (stream == NULL) {
        return BSL_NULL_INPUT;
    }
    if (feof(stream) != 0) {
        return BSL_SUCCESS;
    }
    return BSL_SAL_NOT_FILE_EOF;
}

int32_t SAL_FILE_FSetAttr(bsl_sal_file_handle stream, int cmd, const void *arg)
{
    if (stream == NULL || arg == NULL) {
        return BSL_NULL_INPUT;
    }
    if (tcsetattr(fileno(stream), cmd, (const struct termios *)arg) != 0) {
        return BSL_SAL_ERR_FILE_SET_ATTR;
    }
    return BSL_SUCCESS;
}

int32_t SAL_FILE_FGetAttr(bsl_sal_file_handle stream, void *arg)
{
    if (stream == NULL || arg == NULL) {
        return BSL_NULL_INPUT;
    }
    if (tcgetattr(fileno(stream), (struct termios *)arg) != 0) {
        return BSL_SAL_ERR_FILE_GET_ATTR;
    }
    return BSL_SUCCESS;
}

#endif