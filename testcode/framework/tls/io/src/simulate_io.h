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