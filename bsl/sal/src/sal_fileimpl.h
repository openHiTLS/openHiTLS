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

#ifndef SAL_FILEIMPL_H
#define SAL_FILEIMPL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_FILE

#include <stdint.h>
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    BslSalFileOpen pfFileOpen;
    BslSalFileRead pfFileRead;
    BslSalFileWrite pfFileWrite;
    BslSalFileClose pfFileClose;
    BslSalFileLength pfFileLength;
    BslSalFileError pfFileError;
    BslSalFileTell pfFileTell;
    BslSalFileSeek pfFileSeek;
    BslSalFGets pfFileGets;
    BslSalFPuts pfFilePuts;
    BslSalFlush pfFileFlush;
    BslSalFeof pfFileEof;
    BslSalFSetAttr pfFileSetAttr;
    BslSalFGetAttr pfFileGetAttr;
} BSL_SAL_FileCallback;

int32_t SAL_FileCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
int32_t SAL_FILE_FOpen(bsl_sal_file_handle *stream, const char *path, const char *mode);
int32_t SAL_FILE_FRead(bsl_sal_file_handle stream, void *buffer, size_t size, size_t num, size_t *len);
int32_t SAL_FILE_FWrite(bsl_sal_file_handle stream, const void *buffer, size_t size, size_t num);
void SAL_FILE_FClose(bsl_sal_file_handle stream);
int32_t SAL_FILE_FLength(const char *path, size_t *len);
bool SAL_FILE_FError(bsl_sal_file_handle stream);
int32_t SAL_FILE_FTell(bsl_sal_file_handle stream, long *pos);
int32_t SAL_FILE_FSeek(bsl_sal_file_handle stream, long offset, int32_t origin);
char *SAL_FILE_FGets(bsl_sal_file_handle stream, char *buf, int32_t readLen);
bool SAL_FILE_FPuts(bsl_sal_file_handle stream, const char *buf);
bool SAL_FILE_Flush(bsl_sal_file_handle stream);
int32_t SAL_FILE_Feof(bsl_sal_file_handle stream);
int32_t SAL_FILE_FSetAttr(bsl_sal_file_handle stream, int cmd, const void *arg);
int32_t SAL_FILE_FGetAttr(bsl_sal_file_handle stream, void *arg);
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_BSL_SAL_FILE
#endif // SAL_FILEIMPL_H
