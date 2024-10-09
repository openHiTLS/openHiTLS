/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
