/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SAL_FILEIMPL_H
#define SAL_FILEIMPL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_FILE

#include <stdint.h>
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    BslSalFileOpen pfFileOpen;
    BslSalFileClose pfFileClose;
    BslSalFileRead pfFileRead;
    BslSalFileWrite pfFileWrite;
    BslSalFileLength pfFileLength;
} BSL_SAL_FileCallback;

int32_t SAL_FileCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);

#ifdef HITLS_BSL_SAL_LINUX
int32_t SAL_FileOpen(bsl_sal_file_handle *stream, const char *path, const char *mode);
int32_t SAL_FileRead(bsl_sal_file_handle stream, void *buffer, size_t size, size_t num, size_t *len);
int32_t SAL_FileWrite(bsl_sal_file_handle stream, const void *buffer, size_t size, size_t num);
void SAL_FileClose(bsl_sal_file_handle stream);
int32_t SAL_FileLength(const char *path, size_t *len);
#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_BSL_SAL_FILE
#endif // SAL_FILEIMPL_H
