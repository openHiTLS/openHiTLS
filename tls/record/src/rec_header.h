/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef RECORD_HEADER_H
#define RECORD_HEADER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REC_TLS_RECORD_HEADER_LEN 5
#define REC_TLS_RECORD_LENGTH_OFFSET 3
#define REC_TLS_SN_MAX_VALUE (~((uint64_t)0))       /* TLS sequence number wrap Threshold */

#ifndef HITLS_NO_DTLS12

#define REC_DTLS_RECORD_HEADER_LEN 13
#define REC_DTLS_RECORD_EPOCH_OFFSET 3
#define REC_DTLS_RECORD_LENGTH_OFFSET 11
/* DTLS sequence number cannot be greater than this value. Otherwise, it will wrapped */
#define REC_DTLS_SN_MAX_VALUE 0xFFFFFFFFFFFFllu

#define REC_SEQ_GET(n)      ((n) & 0x0000FFFFFFFFFFFFull)
#define REC_EPOCH_GET(n)    ((uint16_t)((n) >> 48))
#define REC_EPOCHSEQ_CAL(epoch, seq) (((uint64_t)(epoch) << 48) | (seq))
/* Epoch cannot be greater than this value. Otherwise, it will wrapped */
#define REC_EPOCH_MAX_VALUE 0xFFFFu

#endif

typedef struct {
    uint8_t type;
    uint8_t reverse[3];     /* Reserved, 4-byte aligned */
    uint16_t version;
    uint16_t bodyLen;       /* body length */

#ifndef HITLS_NO_DTLS12
    uint64_t epochSeq;      /* only for dtls */
#endif
} RecHdr;

#ifdef __cplusplus
}
#endif

#endif /* RECORD_HEADER_H */
