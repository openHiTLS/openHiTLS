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

#ifndef LMS_PARAMS_H
#define LMS_PARAMS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HSS_LMS

#include <stdint.h>
#include <stddef.h>
#include "lms_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LMS_SHA256_N         32
#define LMS_I_LEN            16
#define LMS_SEED_LEN         32
#define LMS_MAX_HASH         32
#define LMS_MAX_MESSAGE_SIZE (16 * 1024 * 1024)

#define LMS_D_PBLC 0x8080
#define LMS_D_MESG 0x8181
#define LMS_D_LEAF 0x8282
#define LMS_D_INTR 0x8383

#define LMS_HASH_SHA256 1

/* LMS implementation constants */
#define LMS_BITS_PER_BYTE             8
#define LMS_BYTE_MASK                 0xff
#define LMS_CHECKSUM_LEN              2

/* Message hash prefix offsets */
#define LMS_MESG_Q_OFFSET 16
#define LMS_MESG_D_OFFSET 20
#define LMS_MESG_C_OFFSET 22

/* OTS iteration hash prefix offsets */
#define LMS_ITER_Q_OFFSET    16
#define LMS_ITER_K_OFFSET    20
#define LMS_ITER_J_OFFSET    22
#define LMS_ITER_PREV_OFFSET 23

/* OTS public key hash prefix offsets */
#define LMS_PBLC_Q_OFFSET   16
#define LMS_PBLC_D_OFFSET   20
#define LMS_PBLC_PREFIX_LEN 22

/* Leaf node hash prefix offsets */
#define LMS_LEAF_R_OFFSET  16
#define LMS_LEAF_D_OFFSET  20
#define LMS_LEAF_PK_OFFSET 22

/* Internal node hash prefix offsets */
#define LMS_INTR_R_OFFSET        16
#define LMS_INTR_D_OFFSET        20
#define LMS_INTR_LEFT_OFFSET     22

typedef struct LmsPara {
    uint32_t lmsType;
    uint32_t otsType;
    uint32_t h;
    uint32_t n;
    uint32_t height;
    uint32_t w;
    uint32_t p;
    uint32_t ls;
    uint32_t pubKeyLen;
    uint32_t prvKeyLen;
    uint32_t sigLen;
    LmsFamilyHashFuncs hashFuncs;
} LMS_Para;

int32_t LmsLookupParamSet(uint32_t paramSet, uint32_t *h, uint32_t *n, uint32_t *height);

typedef struct {
    uint32_t h;
    uint32_t n;
    uint32_t w;
    uint32_t p;
    uint32_t ls;
} LmOtsParams;

int32_t LmOtsLookupParamSet(uint32_t paramSet, LmOtsParams *params);

int32_t LmsParaInit(LMS_Para *para, uint32_t lmsType, uint32_t otsType);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS_LMS */
#endif /* LMS_PARAMS_H */
