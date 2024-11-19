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

#ifndef REC_BUF_H
#define REC_BUF_H

#include <stdint.h>
#include "bsl_list.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    uint8_t *buf;
    uint32_t bufSize;

    uint32_t start;
    uint32_t end;
    uint32_t singleRecStart;
    uint32_t singleRecEnd;
    bool isHoldBuffer;
} RecBuf;

typedef struct BslList RecBufList;
/**
 * @brief   Allocate buffer
 *
 * @param   bufSize [IN] buffer size
 *
 * @return  RecBuf Buffer handle
 */
RecBuf *RecBufNew(uint32_t bufSize);

/**
 * @brief   Release the buffer
 *
 * @param   buf [IN] Buffer handle. The buffer is released by the invoker
 */
void RecBufFree(RecBuf *buf);

/**
 * @brief   Release the data in buffer
 *
 * @param   buf [IN] Buffer handle
 */
void RecBufClean(RecBuf *buf);

RecBufList *RecBufListNew(void);

void RecBufListFree(RecBufList *bufList);

int32_t RecBufListDereference(RecBufList *bufList);

bool RecBufListEmpty(RecBufList *bufList);

int32_t RecBufListGetBuffer(RecBufList *bufList, uint8_t *buf, uint32_t bufLen, uint32_t *getLen, bool isPeek);

int32_t RecBufListAddBuffer(RecBufList *bufList, RecBuf *buf);

int32_t RecBufResize(RecBuf *recBuf, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif