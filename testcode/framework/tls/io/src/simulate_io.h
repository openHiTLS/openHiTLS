/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SIMULATE_IO_H
#define SIMULATE_IO_H

#include "frame_io.h"
#include "bsl_bytes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t msg[MAX_RECORD_LENTH];
    uint32_t len;
} FrameMsg;

struct FrameUioUserData_ {
    FrameMsg sndMsg;
    FrameMsg recMsg;
    FrameMsg userInsertMsg;
};

#define REC_RECORD_DTLS_EPOCH_OFFSET 3
#define REC_RECORD_DTLS_LENGTH_OFFSET 11


#ifdef __cplusplus
}
#endif

#endif //  SIMULATE_IO_H