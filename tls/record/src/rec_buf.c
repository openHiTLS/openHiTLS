/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "securec.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "tls.h"
#include "record.h"
#include "rec_buf.h"

RecBuf *RecBufNew(uint32_t bufSize)
{
    RecBuf *buf = (RecBuf *)BSL_SAL_Calloc(1, sizeof(RecBuf));
    if (buf == NULL) {
        return NULL;
    }

    buf->buf = (uint8_t *)BSL_SAL_Calloc(1, bufSize);
    if (buf->buf == NULL) {
        BSL_SAL_FREE(buf);
        return NULL;
    }

    buf->bufSize = bufSize;
    return buf;
}

void RecBufFree(RecBuf *buf)
{
    if (buf != NULL) {
        BSL_SAL_FREE(buf->buf);
        BSL_SAL_FREE(buf);
    }
    return;
}

void RecBufClean(RecBuf *buf)
{
    buf->start = 0;
    buf->end = 0;
    return;
}