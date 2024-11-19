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

#ifndef REC_WRAPPER_H
#define REC_WRAPPER_H
#include "rec.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief REC_read, REC_write read/write callback
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN/OUT] Read/write buffer
 * @param   bufLen [IN/OUT] Reads and writes len bytes
 * @param   bufSize [IN] Maximum buffer size
 * @param   userData [IN/OUT] User-defined data
 */
typedef void (*WrapperFunc)(TLS_Ctx *ctx, uint8_t *buf, uint32_t *bufLen, uint32_t bufSize, void* userData);

typedef struct {
    HITLS_HandshakeState ctrlState;
    REC_Type recordType;
    bool isRecRead;
    void *userData;
    WrapperFunc func;
} RecWrapper;

void RegisterWrapper(RecWrapper wrapper);
void ClearWrapper(void);

#ifdef __cplusplus
}
#endif

#endif // REC_WRAPPER_H