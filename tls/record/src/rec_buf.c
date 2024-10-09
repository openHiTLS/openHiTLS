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