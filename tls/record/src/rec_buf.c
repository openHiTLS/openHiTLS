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
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "record.h"
#include "rec_buf.h"

RecBuf *RecBufNew(uint32_t bufSize)
{
    RecBuf *buf = (RecBuf *)BSL_SAL_Calloc(1, sizeof(RecBuf));
    if (buf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17210, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return NULL;
    }

    buf->buf = (uint8_t *)BSL_SAL_Calloc(1, bufSize);
    if (buf->buf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17211, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        BSL_SAL_FREE(buf);
        return NULL;
    }
    buf->isHoldBuffer = true;
    buf->bufSize = bufSize;
    return buf;
}

int32_t RecBufResize(RecBuf *recBuf, uint32_t size)
{
    if (recBuf == NULL || recBuf->bufSize == size || recBuf->end - recBuf->start > size) {
        return HITLS_SUCCESS;
    }
    uint8_t *newBuf = BSL_SAL_Calloc(size, sizeof(uint8_t));
    if (newBuf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17212, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(newBuf, size, &recBuf->buf[recBuf->start], recBuf->end - recBuf->start);
    recBuf->end = recBuf->end - recBuf->start;
    recBuf->start = 0;
    BSL_SAL_FREE(recBuf->buf);
    recBuf->buf = newBuf;
    recBuf->bufSize = size;
    return HITLS_SUCCESS;
}

void RecBufFree(RecBuf *buf)
{
    if (buf != NULL) {
        if (buf->isHoldBuffer) {
            BSL_SAL_FREE(buf->buf);
        }
        BSL_SAL_FREE(buf);
    }
}

void RecBufClean(RecBuf *buf)
{
    buf->start = 0;
    buf->end = 0;
}

RecBufList *RecBufListNew(void)
{
    return BSL_LIST_New(sizeof(RecBuf));
}

void RecBufListFree(RecBufList *bufList)
{
    BSL_LIST_FREE(bufList, (void(*)(void*))RecBufFree);
}

int32_t RecBufListDereference(RecBufList *bufList)
{
    RecBuf *recBuf = (RecBuf *)BSL_LIST_GET_FIRST(bufList);
    while (recBuf != NULL) {
        if (!recBuf->isHoldBuffer) {
            uint8_t *buf = (uint8_t *)BSL_SAL_Dump(recBuf->buf, recBuf->bufSize);
            if (buf == NULL) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17215, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "Dump fail", 0, 0, 0, 0);
                BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
                return HITLS_MEMALLOC_FAIL;
            }
            recBuf->buf = buf;
            recBuf->isHoldBuffer = true;
        }
        recBuf = (RecBuf *)BSL_LIST_GET_NEXT(bufList);
    }
    return HITLS_SUCCESS;
}

bool RecBufListEmpty(RecBufList *bufList)
{
    return BSL_LIST_GET_FIRST(bufList) == NULL;
}

int32_t RecBufListGetBuffer(RecBufList *bufList, uint8_t *buf, uint32_t bufLen, uint32_t *getLen, bool isPeek)
{
    RecBuf *recBuf = (RecBuf *)BSL_LIST_GET_FIRST(bufList);
    if (recBuf == NULL || recBuf->buf == NULL) {
        *getLen = 0;
        return HITLS_SUCCESS;
    }
    uint32_t remain = recBuf->end - recBuf->start;
    uint32_t copyLen = (remain > bufLen) ? bufLen : remain;
    if (copyLen == 0) {
        if (recBuf->start == recBuf->end) {
            BSL_LIST_DeleteCurrent(bufList, (void(*)(void*))RecBufFree);
        }
        *getLen = 0;
        return HITLS_SUCCESS;
    }
    uint8_t *startBuf = &recBuf->buf[recBuf->start];
    int32_t ret = memcpy_s(buf, bufLen, startBuf, copyLen);
    if (ret != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16242, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecBufListGetBuffer memcpy_s failed; buf may be nullptr", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }
    if (!isPeek) {
        recBuf->start += copyLen;
    }
    *getLen = copyLen;
    if (recBuf->start == recBuf->end) {
        BSL_LIST_DeleteCurrent(bufList, (void(*)(void*))RecBufFree);
    }
    return HITLS_SUCCESS;
}

int32_t RecBufListAddBuffer(RecBufList *bufList, RecBuf *buf)
{
    RecBuf *newBuf = BSL_SAL_Calloc(1U, sizeof(RecBuf));
    if (newBuf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17216, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(newBuf, sizeof(RecBuf), buf, sizeof(RecBuf));
    if (BSL_LIST_AddElement(bufList, newBuf, BSL_LIST_POS_END) != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17217, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "AddElement fail", 0, 0, 0, 0);
        BSL_SAL_FREE(newBuf);
        return HITLS_MEMCPY_FAIL;
    }
    return HITLS_SUCCESS;
}