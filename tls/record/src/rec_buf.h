/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef REC_BUF_H
#define REC_BUF_H

#include <stdint.h>

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
} RecBuf;
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

#ifdef __cplusplus
}
#endif

#endif