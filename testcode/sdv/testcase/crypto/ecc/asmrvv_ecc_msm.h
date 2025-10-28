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

#ifndef ASM_ECC_MSM_H
#define ASM_ECC_MSM_H

#include "../../../../../crypto/ecc/src/ecc_local.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"

struct PointBuffer {
    uint64_t *x;
    uint64_t *y;
    uint64_t *z;
};

typedef struct PointBuffer PT_Buffer;

struct BucketNode {
    uint32_t ready, equal;
    PT_Buffer *pt;
    struct BucketNode *next;
};

typedef struct BucketNode MSM_BucketNode;

struct BucketList {
    MSM_BucketNode *head, *tail;
};

typedef struct BucketList MSM_Bucket;

struct QueueNode {
    PT_Buffer *r, *a, *b;
    MSM_BucketNode *buckNode;
};

typedef struct QueueNode MSM_QueueNode;

struct QueueList {
    MSM_QueueNode *queue;
    uint32_t front, back;
};

typedef struct QueueList MSM_Queue;

int32_t ECC_MSM(ECC_Para *para, ECC_Point *r,
                const BN_BigNum **scalars, const ECC_Point **points, uint32_t n);

void MSM_MEM_SET_ZERO(uint64_t (*limbs)[8], uint32_t len);

void MSM_MEM_LOAD256(uint64_t *nums[8], uint64_t (*limbs)[8]);
void MSM_MEM_STORE256(uint64_t *nums[8], uint64_t (*limbs)[8]);

void MSM_MEM_LOAD128(uint64_t *nums[8], uint64_t (*limbs)[8]);
void MSM_MEM_STORE128(uint64_t *nums[8], uint64_t (*limbs)[8]);

void MSM_VX_SUB(uint64_t result[][8], uint64_t a[][8], uint64_t b[], int len);

void MSM_VV_MOD_ADD(uint64_t result[][8], uint64_t a[][8], uint64_t b[][8], uint64_t N[], int len);

void MSM_VV_MOD_SUB(uint64_t result[][8], uint64_t a[][8], uint64_t b[][8], uint64_t N[], int len);

void MSM_VV_MOD_MUL(uint64_t result[][8], uint64_t a[][8], uint64_t b[][8], uint64_t N[], uint64_t N0, int len);
void MSM_VX_MOD_MUL(uint64_t result[][8], uint64_t a[][8], uint64_t b[], uint64_t N[], uint64_t N0, int len);

#endif
