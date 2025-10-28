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

#include "asmrvv_ecc_msm.h"
#include <pthread.h>

#define MSM_THREAD_STACK_SIZE 65536
#define MSM_COORDS_NUM 3
#define MSM_PARALLEL_LANE 8
#define MSM_THREAD_NUMBER 32
#define MSM_WINDOW_SIZE_MAX 32

#define MSM_INV_N0_ITERATIONS 6
#define MSM_INV_N0_CONST 2

#define MSM_R_INIT_VALUE 2
#define MSM_R_EXP_0 0
#define MSM_R_EXP_1 1
#define MSM_R_EXP_2 2
#define MSM_R_EXP_3 3
#define MSM_R_EXP_4 4
#define MSM_R_EXP_5 5
#define MSM_R_EXP_MAX 6

#define MSM_X_INDEX 0
#define MSM_Y_INDEX 1
#define MSM_Z_INDEX 2
#define MSM_T_INDEX 3

#define MSM_SRC1_INDEX 0
#define MSM_SRC2_INDEX 1
#define MSM_DST_INDEX 2

#define MSM_CHECK_REMAIN_MASK 2
#define MSM_MOD_8_MASK 7
#define MSM_DOUBLEWORDS_PER_ITERATION 4

struct MSM_Context {
    uint32_t n, len, windowSize;
    uint64_t *A, *R, *N;
    uint64_t N0;
    ECC_Para *para;
    const ECC_Point **points;
    PT_Buffer *zeroPt;
    MSM_BucketNode *zeroBucketNode;
};

struct MSM_ThreadArg {
    int32_t ret, result_empty;
    pthread_t tid;
    struct MSM_Context *ctx;
    uint32_t *windowDigits;
    ECC_Point *result;
    ECC_Point *acc;
    ECC_Point *temp;
    void *threadBuffer;
};

int32_t GetWindowDigits(uint32_t *windowDigits, const BN_BigNum **scalars, uint32_t n, uint32_t bits)
{
    int32_t ret;
    const uint32_t numWindows = MSM_THREAD_NUMBER;
    uint32_t len = (bits + 63) >> 6;
    uint32_t windowSize = bits / numWindows;

    if (windowSize > MSM_WINDOW_SIZE_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t (*result)[n] = (uint32_t (*)[n])windowDigits;
    uint64_t *buffer = BSL_SAL_Malloc(len * sizeof(uint64_t));
    if (buffer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint64_t mask = (1ULL << windowSize) - 1;
    for (uint32_t i = 0; i < n; i++) {
        GOTO_ERR_IF_EX(BN_BN2Array(scalars[i], buffer, len), ret);

        uint32_t startBit = 0;
        for (uint32_t w = 0; w < numWindows; w++, startBit += windowSize) {
            uint32_t wordIdx    = startBit >> 6; // startBit / 64
            uint32_t bitOffset  = startBit & 0x3f; // startBit % 64

            uint64_t val = buffer[wordIdx] >> bitOffset;
            if (bitOffset + windowSize > 0x40 && wordIdx + 1 < len) {
                val |= buffer[wordIdx + 1] << (0x40 - bitOffset);
            }

            val &= mask;
            result[w][i] = val;
        }
    }
ERR:
    BSL_SAL_FREE(buffer);
    return ret;
}

void MSM_TRANSPOSE_LOAD256_A_X(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].a->x[index], &q[1].a->x[index], &q[2].a->x[index], &q[3].a->x[index],
        &q[4].a->x[index], &q[5].a->x[index], &q[6].a->x[index], &q[7].a->x[index]
    };
    MSM_MEM_LOAD256(nums, src);
}

void MSM_TRANSPOSE_LOAD256_A_Y(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].a->y[index], &q[1].a->y[index], &q[2].a->y[index], &q[3].a->y[index],
        &q[4].a->y[index], &q[5].a->y[index], &q[6].a->y[index], &q[7].a->y[index]
    };
    MSM_MEM_LOAD256(nums, src);
}

void MSM_TRANSPOSE_LOAD256_A_Z(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].a->z[index], &q[1].a->z[index], &q[2].a->z[index], &q[3].a->z[index],
        &q[4].a->z[index], &q[5].a->z[index], &q[6].a->z[index], &q[7].a->z[index]
    };
    MSM_MEM_LOAD256(nums, src);
}

void MSM_TRANSPOSE_LOAD256_B_X(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].b->x[index], &q[1].b->x[index], &q[2].b->x[index], &q[3].b->x[index],
        &q[4].b->x[index], &q[5].b->x[index], &q[6].b->x[index], &q[7].b->x[index]
    };
    MSM_MEM_LOAD256(nums, src);
}

void MSM_TRANSPOSE_LOAD256_B_Y(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].b->y[index], &q[1].b->y[index], &q[2].b->y[index], &q[3].b->y[index],
        &q[4].b->y[index], &q[5].b->y[index], &q[6].b->y[index], &q[7].b->y[index]
    };
    MSM_MEM_LOAD256(nums, src);
}

void MSM_TRANSPOSE_LOAD256_B_Z(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].b->z[index], &q[1].b->z[index], &q[2].b->z[index], &q[3].b->z[index],
        &q[4].b->z[index], &q[5].b->z[index], &q[6].b->z[index], &q[7].b->z[index]
    };
    MSM_MEM_LOAD256(nums, src);
}

void MSM_TRANSPOSE_LOAD256_R_X(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].r->x[index], &q[1].r->x[index], &q[2].r->x[index], &q[3].r->x[index],
        &q[4].r->x[index], &q[5].r->x[index], &q[6].r->x[index], &q[7].r->x[index]
    };
    MSM_MEM_LOAD256(nums, src);
}

void MSM_TRANSPOSE_LOAD256_R_Y(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].r->y[index], &q[1].r->y[index], &q[2].r->y[index], &q[3].r->y[index],
        &q[4].r->y[index], &q[5].r->y[index], &q[6].r->y[index], &q[7].r->y[index]
    };
    MSM_MEM_LOAD256(nums, src);
}

void MSM_TRANSPOSE_STORE256_A_X(MSM_QueueNode *q, uint32_t index, uint64_t (*dst)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].a->x[index], &q[1].a->x[index], &q[2].a->x[index], &q[3].a->x[index],
        &q[4].a->x[index], &q[5].a->x[index], &q[6].a->x[index], &q[7].a->x[index]
    };
    MSM_MEM_STORE256(nums, dst);
}

void MSM_TRANSPOSE_STORE256_A_Y(MSM_QueueNode *q, uint32_t index, uint64_t (*dst)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].a->y[index], &q[1].a->y[index], &q[2].a->y[index], &q[3].a->y[index],
        &q[4].a->y[index], &q[5].a->y[index], &q[6].a->y[index], &q[7].a->y[index]
    };
    MSM_MEM_STORE256(nums, dst);
}

void MSM_TRANSPOSE_STORE256_R_X(MSM_QueueNode *q, uint32_t index, uint64_t (*dst)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].r->x[index], &q[1].r->x[index], &q[2].r->x[index], &q[3].r->x[index],
        &q[4].r->x[index], &q[5].r->x[index], &q[6].r->x[index], &q[7].r->x[index]
    };
    MSM_MEM_STORE256(nums, dst);
}

void MSM_TRANSPOSE_STORE256_R_Y(MSM_QueueNode *q, uint32_t index, uint64_t (*dst)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].r->y[index], &q[1].r->y[index], &q[2].r->y[index], &q[3].r->y[index],
        &q[4].r->y[index], &q[5].r->y[index], &q[6].r->y[index], &q[7].r->y[index]
    };
    MSM_MEM_STORE256(nums, dst);
}

void MSM_TRANSPOSE_STORE256_R_Z(MSM_QueueNode *q, uint32_t index, uint64_t (*dst)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].r->z[index], &q[1].r->z[index], &q[2].r->z[index], &q[3].r->z[index],
        &q[4].r->z[index], &q[5].r->z[index], &q[6].r->z[index], &q[7].r->z[index]
    };
    MSM_MEM_STORE256(nums, dst);
}

void MSM_TRANSPOSE_LOAD128_A_X(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].a->x[index], &q[1].a->x[index], &q[2].a->x[index], &q[3].a->x[index],
        &q[4].a->x[index], &q[5].a->x[index], &q[6].a->x[index], &q[7].a->x[index]
    };
    MSM_MEM_LOAD128(nums, src);
}

void MSM_TRANSPOSE_LOAD128_A_Y(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].a->y[index], &q[1].a->y[index], &q[2].a->y[index], &q[3].a->y[index],
        &q[4].a->y[index], &q[5].a->y[index], &q[6].a->y[index], &q[7].a->y[index]
    };
    MSM_MEM_LOAD128(nums, src);
}

void MSM_TRANSPOSE_LOAD128_A_Z(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].a->z[index], &q[1].a->z[index], &q[2].a->z[index], &q[3].a->z[index],
        &q[4].a->z[index], &q[5].a->z[index], &q[6].a->z[index], &q[7].a->z[index]
    };
    MSM_MEM_LOAD128(nums, src);
}

void MSM_TRANSPOSE_LOAD128_B_X(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].b->x[index], &q[1].b->x[index], &q[2].b->x[index], &q[3].b->x[index],
        &q[4].b->x[index], &q[5].b->x[index], &q[6].b->x[index], &q[7].b->x[index]
    };
    MSM_MEM_LOAD128(nums, src);
}

void MSM_TRANSPOSE_LOAD128_B_Y(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].b->y[index], &q[1].b->y[index], &q[2].b->y[index], &q[3].b->y[index],
        &q[4].b->y[index], &q[5].b->y[index], &q[6].b->y[index], &q[7].b->y[index]
    };
    MSM_MEM_LOAD128(nums, src);
}

void MSM_TRANSPOSE_LOAD128_B_Z(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].b->z[index], &q[1].b->z[index], &q[2].b->z[index], &q[3].b->z[index],
        &q[4].b->z[index], &q[5].b->z[index], &q[6].b->z[index], &q[7].b->z[index]
    };
    MSM_MEM_LOAD128(nums, src);
}

void MSM_TRANSPOSE_LOAD128_R_X(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].r->x[index], &q[1].r->x[index], &q[2].r->x[index], &q[3].r->x[index],
        &q[4].r->x[index], &q[5].r->x[index], &q[6].r->x[index], &q[7].r->x[index]
    };
    MSM_MEM_LOAD128(nums, src);
}

void MSM_TRANSPOSE_LOAD128_R_Y(MSM_QueueNode *q, uint32_t index, uint64_t (*src)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].r->y[index], &q[1].r->y[index], &q[2].r->y[index], &q[3].r->y[index],
        &q[4].r->y[index], &q[5].r->y[index], &q[6].r->y[index], &q[7].r->y[index]
    };
    MSM_MEM_LOAD128(nums, src);
}

void MSM_TRANSPOSE_STORE128_A_X(MSM_QueueNode *q, uint32_t index, uint64_t (*dst)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].a->x[index], &q[1].a->x[index], &q[2].a->x[index], &q[3].a->x[index],
        &q[4].a->x[index], &q[5].a->x[index], &q[6].a->x[index], &q[7].a->x[index]
    };
    MSM_MEM_STORE128(nums, dst);
}

void MSM_TRANSPOSE_STORE128_A_Y(MSM_QueueNode *q, uint32_t index, uint64_t (*dst)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].a->y[index], &q[1].a->y[index], &q[2].a->y[index], &q[3].a->y[index],
        &q[4].a->y[index], &q[5].a->y[index], &q[6].a->y[index], &q[7].a->y[index]
    };
    MSM_MEM_STORE128(nums, dst);
}

void MSM_TRANSPOSE_STORE128_R_X(MSM_QueueNode *q, uint32_t index, uint64_t (*dst)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].r->x[index], &q[1].r->x[index], &q[2].r->x[index], &q[3].r->x[index],
        &q[4].r->x[index], &q[5].r->x[index], &q[6].r->x[index], &q[7].r->x[index]
    };
    MSM_MEM_STORE128(nums, dst);
}

void MSM_TRANSPOSE_STORE128_R_Y(MSM_QueueNode *q, uint32_t index, uint64_t (*dst)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].r->y[index], &q[1].r->y[index], &q[2].r->y[index], &q[3].r->y[index],
        &q[4].r->y[index], &q[5].r->y[index], &q[6].r->y[index], &q[7].r->y[index]
    };
    MSM_MEM_STORE128(nums, dst);
}

void MSM_TRANSPOSE_STORE128_R_Z(MSM_QueueNode *q, uint32_t index, uint64_t (*dst)[MSM_PARALLEL_LANE])
{
    uint64_t *nums[MSM_PARALLEL_LANE] = {
        &q[0].r->z[index], &q[1].r->z[index], &q[2].r->z[index], &q[3].r->z[index],
        &q[4].r->z[index], &q[5].r->z[index], &q[6].r->z[index], &q[7].r->z[index]
    };
    MSM_MEM_STORE128(nums, dst);
}

void MSM_PaddingZeros(MSM_Queue *tasks, PT_Buffer *zeroPt, MSM_BucketNode *zeroBucketNode)
{
    for (uint32_t q = tasks->front + 7; q >= tasks->back; q--) {
            tasks->queue[q].r = zeroPt;
            tasks->queue[q].a = zeroPt;
            tasks->queue[q].b = zeroPt;
            tasks->queue[q].buckNode = zeroBucketNode;
    }
    tasks->back = tasks->front + MSM_PARALLEL_LANE;
}

void MSM_TransposeLoad(MSM_QueueNode *q, uint32_t front, uint64_t *x_buf, uint64_t *y_buf,
                       uint64_t *z_buf, uint64_t *t_buf, uint32_t len)
{
    uint64_t (*x)[len][MSM_PARALLEL_LANE] = (uint64_t (*)[len][MSM_PARALLEL_LANE])x_buf;
    uint64_t (*y)[len][MSM_PARALLEL_LANE] = (uint64_t (*)[len][MSM_PARALLEL_LANE])y_buf;
    uint64_t (*z)[len][MSM_PARALLEL_LANE] = (uint64_t (*)[len][MSM_PARALLEL_LANE])z_buf;
    uint64_t (*t)[len][MSM_PARALLEL_LANE] = (uint64_t (*)[len][MSM_PARALLEL_LANE])t_buf;
    uint32_t i;
    uint32_t l = len - (len % MSM_DOUBLEWORDS_PER_ITERATION);

    for (i = 0; i < l; i += MSM_DOUBLEWORDS_PER_ITERATION) {
        MSM_TRANSPOSE_LOAD256_A_X(&q[front], i, &x[MSM_SRC1_INDEX][i]);
        MSM_TRANSPOSE_LOAD256_A_Y(&q[front], i, &y[MSM_SRC1_INDEX][i]);
        MSM_TRANSPOSE_LOAD256_A_Z(&q[front], i, &z[MSM_SRC1_INDEX][i]);
        MSM_TRANSPOSE_LOAD256_B_Z(&q[front], i, &z[MSM_SRC2_INDEX][i]);
        if (t_buf) {
            MSM_TRANSPOSE_LOAD256_R_X(&q[front], i, &t[MSM_SRC1_INDEX][i]);
            MSM_TRANSPOSE_LOAD256_R_Y(&q[front], i, &t[MSM_SRC2_INDEX][i]);
        } else {
            MSM_TRANSPOSE_LOAD256_B_X(&q[front], i, &x[MSM_SRC2_INDEX][i]);
            MSM_TRANSPOSE_LOAD256_B_Y(&q[front], i, &y[MSM_SRC2_INDEX][i]);
        }
    }
    if (len & MSM_CHECK_REMAIN_MASK) {
        MSM_TRANSPOSE_LOAD128_A_X(&q[front], i, &x[MSM_SRC1_INDEX][i]);
        MSM_TRANSPOSE_LOAD128_A_Y(&q[front], i, &y[MSM_SRC1_INDEX][i]);
        MSM_TRANSPOSE_LOAD128_A_Z(&q[front], i, &z[MSM_SRC1_INDEX][i]);
        MSM_TRANSPOSE_LOAD128_B_Z(&q[front], i, &z[MSM_SRC2_INDEX][i]);
        if (t_buf) {
            MSM_TRANSPOSE_LOAD128_R_X(&q[front], i, &t[MSM_SRC1_INDEX][i]);
            MSM_TRANSPOSE_LOAD128_R_Y(&q[front], i, &t[MSM_SRC2_INDEX][i]);
        } else {
            MSM_TRANSPOSE_LOAD128_B_X(&q[front], i, &x[MSM_SRC2_INDEX][i]);
            MSM_TRANSPOSE_LOAD128_B_Y(&q[front], i, &y[MSM_SRC2_INDEX][i]);
        }
        i += MSM_CHECK_REMAIN_MASK;
    }
    if (len & 1) {
        for (int j = 0; j < MSM_PARALLEL_LANE; i++) {
            MSM_QueueNode* node = &q[front+j];
            x[MSM_SRC1_INDEX][i][j] = node->a->x[i];
            y[MSM_SRC1_INDEX][i][j] = node->a->y[i];
            z[MSM_SRC1_INDEX][i][j] = node->a->z[i];
            z[MSM_SRC2_INDEX][i][j] = node->b->z[i];
            if (t_buf) {
                t[MSM_SRC1_INDEX][i][j] = node->r->x[i];
                t[MSM_SRC2_INDEX][i][j] = node->r->y[i];
            } else {
                x[MSM_SRC2_INDEX][i][j] = node->b->x[i];
                y[MSM_SRC2_INDEX][i][j] = node->b->y[i];
            }
        }
    }
}

void MSM_TransposeStore(MSM_QueueNode *q, uint32_t front, uint64_t *buffer,
                        uint32_t len, uint32_t H_r)
{
    // store
    uint64_t (*buf)[MSM_COORDS_NUM][len][MSM_PARALLEL_LANE]
           = (uint64_t (*)[MSM_COORDS_NUM][len][MSM_PARALLEL_LANE])buffer;
    uint64_t (*x)[len][MSM_PARALLEL_LANE] = buf[MSM_X_INDEX];
    uint64_t (*y)[len][MSM_PARALLEL_LANE] = buf[MSM_Y_INDEX];
    uint64_t (*z)[len][MSM_PARALLEL_LANE] = buf[MSM_Z_INDEX];
    uint32_t i;
    uint32_t l = len - (len % MSM_DOUBLEWORDS_PER_ITERATION);

    for (i = 0; i < l; i += MSM_DOUBLEWORDS_PER_ITERATION) {
        MSM_TRANSPOSE_STORE256_R_X(&q[front], i, &x[MSM_DST_INDEX][i]);
        MSM_TRANSPOSE_STORE256_R_Y(&q[front], i, &y[MSM_DST_INDEX][i]);
        MSM_TRANSPOSE_STORE256_R_Z(&q[front], i, &z[MSM_DST_INDEX][i]);
        if (H_r) {
            MSM_TRANSPOSE_STORE256_A_X(&q[front], i, &x[MSM_SRC1_INDEX][i]);
            MSM_TRANSPOSE_STORE256_A_Y(&q[front], i, &y[MSM_SRC1_INDEX][i]);
        }
    }
    if (len & MSM_CHECK_REMAIN_MASK) {
        MSM_TRANSPOSE_STORE128_R_X(&q[front], i, &x[MSM_DST_INDEX][i]);
        MSM_TRANSPOSE_STORE128_R_Y(&q[front], i, &y[MSM_DST_INDEX][i]);
        MSM_TRANSPOSE_STORE128_R_Z(&q[front], i, &z[MSM_DST_INDEX][i]);
        if (H_r) {
            MSM_TRANSPOSE_STORE128_A_X(&q[front], i, &x[MSM_SRC1_INDEX][i]);
            MSM_TRANSPOSE_STORE128_A_Y(&q[front], i, &y[MSM_SRC1_INDEX][i]);
        }
        i += MSM_CHECK_REMAIN_MASK;
    }
    if (len & 1) {
        for (int j = 0; j < MSM_PARALLEL_LANE; j++) {
            MSM_QueueNode* node = &q[front+j];
            node->r->x[i] = x[MSM_DST_INDEX][i][j];
            node->r->y[i] = y[MSM_DST_INDEX][i][j];
            node->r->z[i] = z[MSM_DST_INDEX][i][j];
            if (H_r) {
                node->a->x[i] = x[MSM_SRC1_INDEX][i][j];
                node->a->y[i] = y[MSM_SRC1_INDEX][i][j];
            }
        }
    }
}

void MSM_CheckEqual(MSM_Queue *tasks, uint64_t *buffer, uint64_t *N, uint64_t N0, uint32_t len)
{
    uint64_t (*buf)[MSM_COORDS_NUM][len][MSM_PARALLEL_LANE]
           = (uint64_t (*)[MSM_COORDS_NUM][len][MSM_PARALLEL_LANE])buffer;
    uint64_t (*x)[len][MSM_PARALLEL_LANE] = (uint64_t (*)[len][MSM_PARALLEL_LANE])buf[MSM_X_INDEX];
    uint64_t (*y)[len][MSM_PARALLEL_LANE] = (uint64_t (*)[len][MSM_PARALLEL_LANE])buf[MSM_Y_INDEX];
    uint64_t (*z)[len][MSM_PARALLEL_LANE] = (uint64_t (*)[len][MSM_PARALLEL_LANE])buf[MSM_Z_INDEX];
    uint64_t (*t)[len][MSM_PARALLEL_LANE] = (uint64_t (*)[len][MSM_PARALLEL_LANE])buf[MSM_T_INDEX];
    uint32_t front = tasks->front;
    uint32_t back = tasks->back;
    MSM_QueueNode* q = tasks->queue;

    MSM_MEM_SET_ZERO(z[MSM_DST_INDEX], len); // Z2 = 0

    while (back - front >= MSM_PARALLEL_LANE) {
        MSM_TransposeLoad(q, front, (uint64_t *)x, (uint64_t *)y, (uint64_t *)z, NULL, len);

        // calc
        MSM_VV_MOD_MUL(t[MSM_SRC1_INDEX], z[MSM_SRC1_INDEX], z[MSM_SRC1_INDEX], N, N0, len);
        // T0 = Z0^2 * R^-1
        MSM_VV_MOD_MUL(x[MSM_SRC2_INDEX], t[MSM_SRC1_INDEX], x[MSM_SRC2_INDEX], N, N0, len);
        // X1 = X1*Z0^2 * R^-2
        MSM_VV_MOD_MUL(t[MSM_SRC2_INDEX], z[MSM_SRC2_INDEX], z[MSM_SRC2_INDEX], N, N0, len);
        // T1 = Z1^2 * R^-1
        MSM_VV_MOD_MUL(x[MSM_SRC1_INDEX], t[MSM_SRC2_INDEX], x[MSM_SRC1_INDEX], N, N0, len);
        // X0 = X0*Z1^2 * R^-2
        MSM_VV_MOD_SUB(x[MSM_DST_INDEX], x[MSM_SRC2_INDEX], x[MSM_SRC1_INDEX], N, len);
        // H = X2 = (X1*Z0^2 - X0*Z1^2) * R^-2
        MSM_VV_MOD_MUL(t[MSM_SRC1_INDEX], t[MSM_SRC1_INDEX], z[MSM_SRC1_INDEX], N, N0, len);
        // T0 = Z0^3 * R^-2
        MSM_VV_MOD_MUL(y[MSM_SRC2_INDEX], t[MSM_SRC1_INDEX], y[MSM_SRC2_INDEX], N, N0, len);
        // Y1 = Y1*Z0^3 * R^-3
        MSM_VV_MOD_MUL(t[MSM_SRC2_INDEX], t[MSM_SRC2_INDEX], z[MSM_SRC2_INDEX], N, N0, len);
        // T1 = Z1^3 * R^-2
        MSM_VV_MOD_MUL(y[MSM_SRC1_INDEX], t[MSM_SRC2_INDEX], y[MSM_SRC1_INDEX], N, N0, len);
        // Y0 = Y0*Z1^3 * R^-3
        MSM_VV_MOD_SUB(y[MSM_DST_INDEX], y[MSM_SRC2_INDEX], y[MSM_SRC1_INDEX], N, len);
        // r = Y2 = (Y1*Z0^3 - Y0*Z1^3) * R^-3

        // store
        MSM_TransposeStore(q, front, buffer, len, 1);

        for (int j = 0; j < MSM_PARALLEL_LANE; j++) {
            MSM_QueueNode* node = &q[front+j];
            uint32_t HIsZero;
            uint32_t rIsZero;
            uint32_t i;
            for (i = 0; i < len && x[MSM_DST_INDEX][i][j] == 0; i++) { }
            HIsZero = i == len;
            
            for (i = 0; i < len && y[MSM_DST_INDEX][i][j] == 0; i++) { }
            rIsZero = i == len;
            
            node->buckNode->equal = HIsZero & rIsZero;
            node->buckNode->ready = HIsZero & (!rIsZero);
        }

        front += MSM_PARALLEL_LANE;
    }
}

void MSM_PointAdd(MSM_Queue *tasks, uint64_t *buffer, uint64_t *N,
                  uint64_t *R_buf, uint64_t N0, uint32_t len)
{
    uint64_t (*buf)[MSM_COORDS_NUM][len][MSM_PARALLEL_LANE]
           = (uint64_t (*)[MSM_COORDS_NUM][len][MSM_PARALLEL_LANE])buffer;
    uint64_t (*x)[len][MSM_PARALLEL_LANE] = buf[MSM_X_INDEX];
    uint64_t (*y)[len][MSM_PARALLEL_LANE] = buf[MSM_Y_INDEX];
    uint64_t (*z)[len][MSM_PARALLEL_LANE] = buf[MSM_Z_INDEX];
    uint64_t (*t)[len][MSM_PARALLEL_LANE] = buf[MSM_T_INDEX];
    uint64_t (*R)[len] = (uint64_t (*)[len])R_buf;
    uint32_t front = tasks->front;
    uint32_t back = tasks->back;
    MSM_QueueNode* q = tasks->queue;

    while (back - front >= MSM_PARALLEL_LANE) {
        MSM_TransposeLoad(q, front, (uint64_t *)x, (uint64_t *)y, (uint64_t *)z, (uint64_t *)t, len);

        // calc
        // X0 = U0 * R^-2
        // Y0 = S0 * R^-3
        // T0 = H * R^-2
        // T1 = r * R^-3

        MSM_VX_MOD_MUL(x[MSM_SRC1_INDEX], x[MSM_SRC1_INDEX], R[MSM_R_EXP_3], N, N0, len);
        // X0 = U0
        MSM_VX_MOD_MUL(x[MSM_DST_INDEX], t[MSM_SRC1_INDEX], R[MSM_R_EXP_3], N, N0, len);
        // X2 = H
        MSM_VX_MOD_MUL(y[MSM_SRC1_INDEX], y[MSM_SRC1_INDEX], R[MSM_R_EXP_4], N, N0, len);
        // Y0 = S0
        MSM_VX_MOD_MUL(y[MSM_DST_INDEX], t[MSM_SRC2_INDEX], R[MSM_R_EXP_4], N, N0, len);
        // Y2 = r

        MSM_VV_MOD_MUL(z[MSM_SRC1_INDEX], x[MSM_DST_INDEX], z[MSM_SRC1_INDEX], N, N0, len);
        // Z0 = H*Z0 * R^-1
        MSM_VV_MOD_MUL(t[MSM_SRC1_INDEX], y[MSM_DST_INDEX], y[MSM_DST_INDEX], N, N0, len);
        // T0 = r^2 * R^-1
        MSM_VV_MOD_MUL(t[MSM_SRC2_INDEX], x[MSM_DST_INDEX], x[MSM_DST_INDEX], N, N0, len);
        // T1 = H^2 * R^-1

        MSM_VV_MOD_MUL(t[MSM_DST_INDEX], x[MSM_SRC1_INDEX], t[MSM_SRC2_INDEX], N, N0, len);
        // T2 = U0*H^2 * R^-2
        MSM_VV_MOD_MUL(z[MSM_DST_INDEX], t[MSM_SRC2_INDEX], x[MSM_DST_INDEX], N, N0, len);
        // Z2 = H^3 * R^-2
        MSM_VV_MOD_ADD(x[MSM_DST_INDEX], z[MSM_DST_INDEX], t[MSM_DST_INDEX], N, len);
        MSM_VV_MOD_ADD(x[MSM_DST_INDEX], x[MSM_DST_INDEX], t[MSM_DST_INDEX], N, len);
        // X2 = (H^3 + 2*U0*H^2) * R^-2

        MSM_VX_MOD_MUL(x[MSM_DST_INDEX], x[MSM_DST_INDEX], R[MSM_R_EXP_3], N, N0, len);
        // X2 = H^3 + 2*U0*H^2
        MSM_VX_MOD_MUL(t[MSM_SRC1_INDEX], t[MSM_SRC1_INDEX], R[MSM_R_EXP_2], N, N0, len);
        // T0 = r^2

        MSM_VV_MOD_SUB(x[MSM_DST_INDEX], t[MSM_SRC1_INDEX], x[MSM_DST_INDEX], N, len);
        // X2 = r^2 - (H^3 + 2*U0*H^2)

        MSM_VV_MOD_MUL(t[MSM_SRC1_INDEX], y[MSM_DST_INDEX], t[MSM_DST_INDEX], N, N0, len);
        // T0 = r * U0 * H^2 * R^-3
        MSM_VV_MOD_MUL(t[MSM_SRC2_INDEX], y[MSM_SRC1_INDEX], z[MSM_DST_INDEX], N, N0, len);
        // T1 = S0 * H^3 * R^-3
        MSM_VV_MOD_MUL(t[MSM_DST_INDEX], x[MSM_DST_INDEX], y[MSM_DST_INDEX], N, N0, len);
        // T2 = X2 * r * R^-1

        MSM_VV_MOD_SUB(y[MSM_DST_INDEX], t[MSM_SRC1_INDEX], t[MSM_SRC2_INDEX], N, len);
        // Y2 = (r * U0 * H^2 - S0 * H^3) * R^-3
        MSM_VX_MOD_MUL(y[MSM_DST_INDEX], y[MSM_DST_INDEX], R[MSM_R_EXP_4], N, N0, len);
        // Y2 = r * U0 * H^2 - S0 * H^3
        MSM_VX_MOD_MUL(t[MSM_DST_INDEX], t[MSM_DST_INDEX], R[MSM_R_EXP_2], N, N0, len);
        // T2 = X2 * r
        MSM_VV_MOD_SUB(y[MSM_DST_INDEX], y[MSM_DST_INDEX], t[MSM_DST_INDEX], N, len);
        // Y2 = r * U0 * H^2 - S0 * H^3 - X2 * r

        MSM_VV_MOD_MUL(z[MSM_DST_INDEX], z[MSM_SRC1_INDEX], z[MSM_SRC2_INDEX], N, N0, len);
        // Z2 = H*Z0*Z1 * R^-2
        MSM_VX_MOD_MUL(z[MSM_DST_INDEX], z[MSM_DST_INDEX], R[MSM_R_EXP_3], N, N0, len);
        // Z2 = H*Z0*Z1

        // store
        MSM_TransposeStore(q, front, buffer, len, 0);
        for (int j = 0; j < MSM_PARALLEL_LANE; j++) {
            q[front+j].buckNode->ready = 1;
        }
        front += MSM_PARALLEL_LANE;
    }
    tasks->front = front;
}

void MSM_PointDouble(MSM_Queue *tasks, uint64_t *buffer, uint64_t *N,
                     uint64_t *R_buf, uint64_t *a_buf, uint64_t N0, uint32_t len)
{
    uint64_t (*buf)[MSM_COORDS_NUM][len][MSM_PARALLEL_LANE]
           = (uint64_t (*)[MSM_COORDS_NUM][len][MSM_PARALLEL_LANE])buffer;
    uint64_t (*x)[len][MSM_PARALLEL_LANE] = buf[MSM_X_INDEX];
    uint64_t (*y)[len][MSM_PARALLEL_LANE] = buf[MSM_Y_INDEX];
    uint64_t (*z)[len][MSM_PARALLEL_LANE] = buf[MSM_Z_INDEX];
    uint64_t (*t)[len][MSM_PARALLEL_LANE] = buf[MSM_T_INDEX];
    uint64_t (*R)[len] = (uint64_t (*)[len])R_buf;
    uint32_t front = tasks->front;
    uint32_t back = tasks->back;
    MSM_QueueNode* q = tasks->queue;

    while (back - front >= MSM_PARALLEL_LANE) {
        MSM_TransposeLoad(q, front, (uint64_t *)x, (uint64_t *)y, (uint64_t *)z, NULL, len);

        // Prepare A, B, C
        MSM_VV_MOD_MUL(x[MSM_DST_INDEX], x[MSM_SRC2_INDEX], x[MSM_SRC2_INDEX], N, N0, len);
        // X2 = A * R^-1 = X1^2 * R^-1
        MSM_VV_MOD_MUL(y[MSM_DST_INDEX], y[MSM_SRC2_INDEX], y[MSM_SRC2_INDEX], N, N0, len);
        // Y2 = B * R^-1 = Y1^2 * R^-1
        MSM_VX_MOD_MUL(y[MSM_DST_INDEX], y[MSM_DST_INDEX], R[MSM_R_EXP_2], N, N0, len);
        // Y2 = B = Y1^2
        MSM_VV_MOD_MUL(z[MSM_DST_INDEX], x[MSM_DST_INDEX], x[MSM_DST_INDEX], N, N0, len);
        // Z2 = C * R^-1 = Y1^4 * R^-1

        // Calculate D
        MSM_VV_MOD_ADD(y[MSM_DST_INDEX], y[MSM_DST_INDEX], x[MSM_SRC2_INDEX], N, len);
        // Y2 = X1 + Y1^2
        MSM_VV_MOD_MUL(y[MSM_DST_INDEX], y[MSM_DST_INDEX], y[MSM_DST_INDEX], N, N0, len);
        // Y2 = (X1 + Y1^2)^2 * R^-1
        MSM_VV_MOD_SUB(y[MSM_DST_INDEX], y[MSM_DST_INDEX], x[MSM_DST_INDEX], N, len);
        // Y2 = ((X1 + Y1^2)^2 - X1^2) * R^-1
        MSM_VV_MOD_SUB(y[MSM_DST_INDEX], y[MSM_DST_INDEX], z[MSM_DST_INDEX], N, len);
        // Y2 = ((X1 + Y1^2)^2 - X1^2 - Y1^4) * R^-1
        MSM_VV_MOD_ADD(y[MSM_DST_INDEX], y[MSM_DST_INDEX], y[MSM_DST_INDEX], N, len);
        // Y2 = D * R^-1 = 2*((X1 + Y1^2)^2 - X1^2 - Y1^4) * R^-1
        
        // Calculate E, F
        MSM_VV_MOD_ADD(t[MSM_SRC1_INDEX], x[MSM_DST_INDEX], x[MSM_DST_INDEX], N, len);
        MSM_VV_MOD_ADD(t[MSM_SRC1_INDEX], t[MSM_SRC1_INDEX], x[MSM_DST_INDEX], N, len);
        // T0 = 3*X0^2 * R^-1
        MSM_VX_MOD_MUL(t[MSM_SRC1_INDEX], t[MSM_SRC1_INDEX], R[MSM_R_EXP_2], N, N0, len);
        // T0 = 3*X0^2

        MSM_VV_MOD_MUL(t[MSM_SRC2_INDEX], z[MSM_SRC2_INDEX], z[MSM_SRC2_INDEX], N, N0, len);
        // T1 = Z1^2 * R^-1
        MSM_VV_MOD_MUL(t[MSM_SRC2_INDEX], t[MSM_SRC2_INDEX], t[MSM_SRC2_INDEX], N, N0, len);
        // T1 = Z1^4 * R^-3
        MSM_VX_MOD_MUL(t[MSM_SRC2_INDEX], t[MSM_SRC2_INDEX], a_buf, N, N0, len);
        // T1 = a * Z1^4 * R^-4
        MSM_VX_MOD_MUL(t[MSM_SRC2_INDEX], t[MSM_SRC2_INDEX], R[MSM_R_EXP_5], N, N0, len);
        // T1 = a * Z1^4
        MSM_VV_MOD_SUB(t[MSM_SRC1_INDEX], t[MSM_SRC1_INDEX], t[MSM_SRC2_INDEX], N, len);
        // T0 = E = 3*X0^2 + a*Z1^4

        MSM_VV_MOD_MUL(t[MSM_SRC2_INDEX], t[MSM_SRC1_INDEX], t[MSM_SRC1_INDEX], N, N0, len);
        // T1 = F * R^-1 = E^2 * R^-1

        // Calculate X2, Y2, Z2
        MSM_VV_MOD_SUB(x[MSM_DST_INDEX], t[MSM_SRC2_INDEX], y[MSM_DST_INDEX], N, len);
        // X2 = (F - D) * R^-1
        MSM_VV_MOD_SUB(x[MSM_DST_INDEX], x[MSM_DST_INDEX], y[MSM_DST_INDEX], N, len);
        // X2 = (F - 2*D) * R^-1

        MSM_VX_MOD_MUL(x[MSM_DST_INDEX], x[MSM_DST_INDEX], R[MSM_R_EXP_2], N, N0, len);
        // X2 = F - 2*D
        MSM_VX_MOD_MUL(y[MSM_DST_INDEX], y[MSM_DST_INDEX], R[MSM_R_EXP_2], N, N0, len);
        // Y2 = D

        MSM_VV_MOD_SUB(y[MSM_DST_INDEX], y[MSM_DST_INDEX], x[MSM_DST_INDEX], N, len);
        // Y2 = D - X2
        MSM_VV_MOD_MUL(y[MSM_DST_INDEX], t[MSM_SRC1_INDEX], y[MSM_DST_INDEX], N, N0, len);
        // Y2 = E*(D - X2) * R^-1
        MSM_VV_MOD_ADD(z[MSM_DST_INDEX], z[MSM_DST_INDEX], z[MSM_DST_INDEX], N, len);
        // Z2 = 2*C * R^-1
        MSM_VV_MOD_ADD(z[MSM_DST_INDEX], z[MSM_DST_INDEX], z[MSM_DST_INDEX], N, len);
        // Z2 = 4*C * R^-1
        MSM_VV_MOD_ADD(z[MSM_DST_INDEX], z[MSM_DST_INDEX], z[MSM_DST_INDEX], N, len);
        // Z2 = 8*C * R^-1

        MSM_VV_MOD_SUB(y[MSM_DST_INDEX], y[MSM_DST_INDEX], z[MSM_DST_INDEX], N, len);
        // Y2 = (E*(D - X2) - 8*C) * R^-1
        MSM_VX_MOD_MUL(y[MSM_DST_INDEX], y[MSM_DST_INDEX], R[MSM_R_EXP_2], N, N0, len);
        // Y2 = E*(D - X2) - 8*C

        MSM_VV_MOD_MUL(z[MSM_DST_INDEX], y[MSM_SRC2_INDEX], z[MSM_SRC1_INDEX], N, N0, len);
        // Z2 = Y1 * Z1 * R^-1
        MSM_VX_MOD_MUL(z[MSM_DST_INDEX], z[MSM_DST_INDEX], R[MSM_R_EXP_2], N, N0, len);
        // Z2 = Y1 * Z1

        MSM_TransposeStore(q, front, buffer, len, 0);
        for (int j = 0; j < MSM_PARALLEL_LANE; j++) {
            q[front+j].buckNode->ready = 1;
        }
        front += MSM_PARALLEL_LANE;
    }
    tasks->front = front;
}

uint64_t *MSM_ThreadFunc(void *arg)
{
    int32_t ret = CRYPT_SUCCESS;
    struct MSM_ThreadArg *targ = (struct MSM_ThreadArg *)arg;
    struct MSM_Context *ctx = targ->ctx;

    uint32_t res_empty = 1;
    uint32_t acc_empty = 1;
    uint32_t n = ctx->n;
    uint64_t N0 = ctx->N0;
    uint32_t len = ctx->len;
    uint32_t windowSize = ctx->windowSize;
    uint32_t numBuckets = (1 << windowSize);
    uint64_t *A = ctx->A;
    uint64_t *N = ctx->N;
    uint64_t (*R)[len] = (uint64_t (*)[len])ctx->R;
    uint32_t *windowDigits = targ->windowDigits;
    ECC_Para *para = ctx->para;
    const ECC_Point **points = ctx->points;
    
    ECC_Point *temp = targ->temp;
    ECC_Point *acc  = targ->acc;
    ECC_Point *result = targ->result;
    PT_Buffer *zeroPt = ctx->zeroPt;
    MSM_BucketNode *zeroBucketNode = ctx->zeroBucketNode;
    uint64_t (*simd_buffer)[MSM_COORDS_NUM][ctx->len][MSM_PARALLEL_LANE] = NULL;
    
    struct MSM_ThreadBuffer {
        MSM_QueueNode taskQueue[n];
        MSM_QueueNode equalsQueue[n];
        MSM_Bucket buckets[numBuckets];
        PT_Buffer *buffer[numBuckets];
        MSM_BucketNode bucketNodes[n];
        PT_Buffer ptBuf[n];
        uint64_t ptCoords[n*MSM_COORDS_NUM*len];
        PT_Buffer newptBuffer[n];
        uint64_t newptBufferCoords[n*MSM_COORDS_NUM*len];
        uint64_t simd_buffer[MSM_COORDS_NUM+1][MSM_COORDS_NUM][len][MSM_PARALLEL_LANE];
    } *tBuffer = (struct MSM_ThreadBuffer *)targ->threadBuffer;

    MSM_Queue tasks = {
        .queue = tBuffer->taskQueue,
        .front = 0,
        .back = 0
    };
    MSM_Queue equals = {
        .queue = tBuffer->equalsQueue,
        .front = 0,
        .back = 0
    };

    MSM_Bucket *buckets = tBuffer->buckets;
    PT_Buffer **buffer = tBuffer->buffer;
    MSM_BucketNode *bucketNodes = tBuffer->bucketNodes;
    PT_Buffer *newptBuffer = tBuffer->newptBuffer;
    uint64_t *newptBufferCoords = tBuffer->newptBufferCoords;
    simd_buffer = tBuffer->simd_buffer;
    PT_Buffer *ptBuf = tBuffer->ptBuf;
    uint64_t *ptCoords = tBuffer->ptCoords;
    for (uint32_t i = 0; i < n; i++) {
        ptBuf[i].x = &ptCoords[(i*MSM_COORDS_NUM+MSM_X_INDEX)*len];
        ptBuf[i].y = &ptCoords[(i*MSM_COORDS_NUM+MSM_Y_INDEX)*len];
        ptBuf[i].z = &ptCoords[(i*MSM_COORDS_NUM+MSM_Z_INDEX)*len];

        GOTO_ERR_IF_EX(BN_BN2Array(points[i]->x, ptBuf[i].x, len), ret);
        GOTO_ERR_IF_EX(BN_BN2Array(points[i]->y, ptBuf[i].y, len), ret);
        GOTO_ERR_IF_EX(BN_BN2Array(points[i]->z, ptBuf[i].z, len), ret);
    }

    for (uint32_t i = 0; i < n; i++) {
        newptBuffer[i].x = &newptBufferCoords[(i*MSM_COORDS_NUM+MSM_X_INDEX)*len];
        newptBuffer[i].y = &newptBufferCoords[(i*MSM_COORDS_NUM+MSM_Y_INDEX)*len];
        newptBuffer[i].z = &newptBufferCoords[(i*MSM_COORDS_NUM+MSM_Z_INDEX)*len];
    }

    uint32_t newptBufferTop = 0;
    uint32_t bucketNodesTop = 0;

    for (uint32_t i = 0; i < n; i++) {
        uint32_t d = windowDigits[i];
        if (d == 0) {
            continue;
        }

        if (buffer[d]) {
            tasks.queue[tasks.back].r = &newptBuffer[newptBufferTop];
            tasks.queue[tasks.back].a = buffer[d];
            tasks.queue[tasks.back].b = &ptBuf[i];

            if (buckets[d].tail) {
                buckets[d].tail->next = &bucketNodes[bucketNodesTop];
                buckets[d].tail = &bucketNodes[bucketNodesTop];
            } else {
                buckets[d].head = buckets[d].tail = &bucketNodes[bucketNodesTop];
            }
            tasks.queue[tasks.back].buckNode = buckets[d].tail;
            buckets[d].tail->pt = &newptBuffer[newptBufferTop];
            buckets[d].tail->next = NULL;
            buckets[d].tail->ready = 0;
            buckets[d].tail->equal = 0;
            bucketNodesTop++;
            newptBufferTop++;
            tasks.back++;
            buffer[d] = NULL;
        } else {
            buffer[d] = &ptBuf[i];
        }
    }

    for (uint32_t d = 1; d < numBuckets; d++) {
        if (buffer[d]) {
            if (buckets[d].tail) {
                buckets[d].tail = buckets[d].tail->next = &bucketNodes[bucketNodesTop];
            } else {
                buckets[d].head = buckets[d].tail = &bucketNodes[bucketNodesTop];
            }
            bucketNodesTop++;
            buckets[d].tail->pt = buffer[d];
            buckets[d].tail->next = NULL;
            buckets[d].tail->ready = 1;
            buckets[d].tail->equal = 0;
        }
    }

    do {
        // check if H or s is zero
        MSM_CheckEqual(&tasks, (uint64_t *)simd_buffer, N, N0, len);
        
        // regenerate task queue
        int f = tasks.front;
        int b = ((tasks.back - f) & MSM_MOD_8_MASK) ? tasks.back - ((tasks.back - f) & MSM_MOD_8_MASK) : tasks.back;
        for (; f < b; f++) {
            if (tasks.queue[f].buckNode == zeroBucketNode) {
                break;
            }
            if (tasks.queue[f].buckNode->equal) {
                equals.queue[equals.back].r = tasks.queue[f].r;
                equals.queue[equals.back].a = tasks.queue[f].a;
                equals.queue[equals.back].b = tasks.queue[f].b;
                equals.queue[equals.back].buckNode = tasks.queue[f].buckNode;
                equals.back++;
                tasks.queue[f].r = tasks.queue[tasks.front].r;
                tasks.queue[f].a = tasks.queue[tasks.front].a;
                tasks.queue[f].b = tasks.queue[tasks.front].b;
                tasks.queue[f].buckNode = tasks.queue[tasks.front].buckNode;
                tasks.front++;
                continue;
            }
            if (tasks.queue[f].buckNode->ready) {
                tasks.queue[f].r = tasks.queue[tasks.front].r;
                tasks.queue[f].a = tasks.queue[tasks.front].a;
                tasks.queue[f].b = tasks.queue[tasks.front].b;
                tasks.queue[f].buckNode = tasks.queue[tasks.front].buckNode;
                tasks.front++;
            }
        }
        
        // try to do simd point add & point double
        MSM_PointAdd(&tasks, (uint64_t *)simd_buffer, N, (uint64_t *)R, N0, len);
        MSM_PointDouble(&equals, (uint64_t *)simd_buffer, N, (uint64_t *)R, A, N0, len);

        for (f = 0, b = tasks.back - 1; tasks.queue[b].buckNode == zeroBucketNode; b--, f++) { }
        if (f) {
            tasks.front = tasks.back = b + 1;
        }

        for (f = 0, b = equals.back - 1; equals.queue[b].buckNode == zeroBucketNode; b--, f++) { }
        if (f) {
            equals.front = equals.back = b + 1;
        }

        // merge new points
        for (uint32_t d = 1; d < numBuckets; d++) {
            MSM_BucketNode *ptr = buckets[d].head;
            while (ptr) {
                if (ptr->ready) {
                    MSM_BucketNode *p = ptr;
                    MSM_BucketNode *pn = ptr->next;
                    for (; pn && !(pn->ready); p = p->next, pn = pn->next) ;
                    if (pn) {
                        PT_Buffer *new_point = &newptBuffer[newptBufferTop];
                        tasks.queue[tasks.back].r = new_point;
                        tasks.queue[tasks.back].a = ptr->pt;
                        tasks.queue[tasks.back].b = pn->pt;
                        tasks.queue[tasks.back].buckNode = ptr;
                        tasks.back++;
                        ptr->pt = new_point;
                        ptr->ready = 0;
                        ptr->equal = 0;
                        newptBufferTop++;
                        p->next = pn->next;
                        ptr = pn->next;
                    } else {
                        ptr = ptr->next;
                    }
                } else {
                    ptr = ptr->next;
                }
            }
        }

        uint32_t tasks_need_padding = tasks.back - tasks.front < MSM_PARALLEL_LANE;
        uint32_t tasks_is_empty = tasks.back - tasks.front == 0;
        uint32_t equals_need_padding = equals.back - equals.front < MSM_PARALLEL_LANE;
        uint32_t equals_is_empty = equals.back - equals.front == 0;

        if (tasks_need_padding && !tasks_is_empty && equals_need_padding && !equals_is_empty) {
            MSM_PaddingZeros(&tasks, zeroPt, zeroBucketNode);
            MSM_PaddingZeros(&equals, zeroPt, zeroBucketNode);
        } else if (tasks_need_padding && !tasks_is_empty && equals_is_empty) {
            MSM_PaddingZeros(&tasks, zeroPt, zeroBucketNode);
        } else if (equals_need_padding && !equals_is_empty && tasks_is_empty) {
            MSM_PaddingZeros(&equals, zeroPt, zeroBucketNode);
        }
    } while (tasks.back - tasks.front || equals.back - equals.front);
    // back to step 1 if queue length >= MSM_PARALLEL_LANE

    // add to result[i]
    for (uint32_t d = numBuckets - 1; d > 0; d--) {
        if (buckets[d].head != NULL) {
            PT_Buffer *pt = buckets[d].head->pt;
        
            GOTO_ERR_IF_EX(BN_Array2BN(temp->x, pt->x, len), ret);
            GOTO_ERR_IF_EX(BN_Array2BN(temp->y, pt->y, len), ret);
            GOTO_ERR_IF_EX(BN_Array2BN(temp->z, pt->z, len), ret);

            if (!BN_IsZero(temp->z)) {
                if (acc_empty) {
                    GOTO_ERR_IF_EX(ECC_CopyPoint(acc, temp), ret);
                    acc_empty = 0;
                } else {
                    GOTO_ERR_IF_EX(para->method->point2Affine(para, temp, temp), ret);
                    GOTO_ERR_IF_EX(para->method->pointAdd(para, acc, acc, temp), ret);
                }
            }
        }

        if (!acc_empty) {
            if (res_empty) {
                GOTO_ERR_IF_EX(ECC_CopyPoint(result, acc), ret);
                res_empty = 0;
            } else {
                GOTO_ERR_IF_EX(para->method->point2Affine(para, acc, acc), ret);
                GOTO_ERR_IF_EX(para->method->pointAdd(para, result, result, acc), ret);
            }
        }
    }
    if (!res_empty) {
        GOTO_ERR_IF_EX(para->method->point2Affine(para, result, result), ret);
    }

ERR:
    targ->ret = ret;
    targ->result_empty = res_empty;
    return 0;
}

int32_t ECC_MSM(ECC_Para *para, ECC_Point *r,
                const BN_BigNum **scalars, const ECC_Point **points, uint32_t n)
{
    if (para == NULL || r == NULL || scalars == NULL || points == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    int32_t ret = CRYPT_SUCCESS;
    uint32_t bits       = ECC_ParaBits(para);   // number of bits in curve order
    uint32_t len        = (bits + 63) >> 6;      // bits / 64 + 1
    const uint32_t numWindows = MSM_THREAD_NUMBER;
    uint32_t w          = bits / numWindows;
    uint32_t r_empty = 1;
    uint32_t numBuckets = (1 << w);
    uint64_t N0;
    uint64_t A[len];
    uint64_t N[len];
    uint64_t R[MSM_R_EXP_MAX][len];
    uint64_t zero[len];
    BN_BigNum *R_acc = NULL;
    BN_BigNum *R_bn = NULL;
    BN_Optimizer *opt = NULL;
    ECC_Point **results = NULL;

    struct MSM_ThreadBuffer {
        MSM_QueueNode taskQueue[n];
        MSM_QueueNode equalsQueue[n];
        MSM_Bucket buckets[numBuckets];
        PT_Buffer *buffer[numBuckets];
        MSM_BucketNode bucketNodes[n];
        PT_Buffer ptBuf[n];
        uint64_t ptCoords[n*MSM_COORDS_NUM*len];
        PT_Buffer newptBuffer[n];
        uint64_t newptBufferCoords[n*MSM_COORDS_NUM*len];
        uint64_t simd_buffer[MSM_COORDS_NUM+1][MSM_COORDS_NUM][len][MSM_PARALLEL_LANE];
    } *threadBuffers = NULL;

    struct MSM_MainBuffer {
        ECC_Point *results[numWindows];
        uint32_t windowDigits[numWindows][n];
        struct MSM_ThreadBuffer t_buffers[numWindows];
        struct MSM_ThreadArg targs[numWindows];
    } *bufferPtr = NULL;
    uint32_t (*windowDigits)[n] = NULL;
    struct MSM_ThreadArg *targs = NULL;

    for (uint32_t i = 0; i < len; i++) {
        zero[i] = 0;
        R[MSM_R_EXP_0][i] = 0;
        R[MSM_R_EXP_1][i] = 0;
    }
    R[MSM_R_EXP_0][0] = MSM_R_INIT_VALUE;
    R[MSM_R_EXP_1][len - 1] = (1uLL << ((bits-1)&0x3f));
    R_acc = BN_Create(bits);
    R_bn = BN_Create(bits);
    opt = BN_OptimizerCreate();
    if (R_acc == NULL || R_bn == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    GOTO_ERR_IF_EX(BN_Array2BN(R_acc, R[MSM_R_EXP_0], len), ret);
    R[MSM_R_EXP_0][0] = 1;
    GOTO_ERR_IF_EX(BN_Array2BN(R_bn, R[MSM_R_EXP_1], len), ret);
    
    GOTO_ERR_IF_EX(BN_Mul(R_bn, R_bn, R_acc, opt), ret);
    GOTO_ERR_IF_EX(BN_Mod(R_bn, R_bn, para->p, opt), ret);
    BN_SetLimb(R_acc, 1);
    
    for (uint32_t i = 1; i < MSM_R_EXP_MAX; i++) {
        GOTO_ERR_IF_EX(BN_ModMul(R_acc, R_acc, R_bn, para->p, opt), ret);
        GOTO_ERR_IF_EX(BN_BN2Array(R_acc, R[i], len), ret);
    }

    bufferPtr = (struct MSM_MainBuffer *)BSL_SAL_Calloc(1, sizeof(struct MSM_MainBuffer));
    if (bufferPtr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }

    results = bufferPtr->results;
    windowDigits = bufferPtr->windowDigits;
    threadBuffers = bufferPtr->t_buffers;
    targs = bufferPtr->targs;

    GOTO_ERR_IF_EX(BN_BN2Array(para->a, A, len), ret);
    GOTO_ERR_IF_EX(BN_BN2Array(para->p, N, len), ret);
    N0 = 1;
    for (uint64_t i = 0, t = -N[0]; i < MSM_INV_N0_ITERATIONS; i++) {
        N0 = N0 * (MSM_INV_N0_CONST - t * N0);
    }
    
    GOTO_ERR_IF_EX(GetWindowDigits((uint32_t *)windowDigits, scalars, n, bits), ret);

    PT_Buffer zeroPt = {
        .x = zero,
        .y = zero,
        .z = zero,
    };
    MSM_BucketNode zeroBucketNode = {
        .pt = &zeroPt,
        .next = NULL,
        .ready = 0,
        .equal = 0
    };

    struct MSM_Context ctx = {
        .n = n, .len = len, .windowSize = w,
        .A = A, .R = (uint64_t *)R, .N = N, .N0 = N0,
        .para = para, .points = points,
        .zeroPt = &zeroPt, .zeroBucketNode = &zeroBucketNode
    };

    for (int32_t i = numWindows - 1; i >= 0; i--) {
        results[i] = ECC_NewPoint(para);
        targs[i].acc = ECC_NewPoint(para);
        targs[i].temp = ECC_NewPoint(para);

        if (results[i] == NULL || targs[i].acc == NULL || targs[i].temp == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            ret = CRYPT_MEM_ALLOC_FAIL;
            goto ERR;
        }

        targs[i].ctx = &ctx;
        targs[i].windowDigits = windowDigits[i];
        targs[i].result = results[i];
        targs[i].ret = CRYPT_SUCCESS;
        targs[i].result_empty = 0;
        targs[i].threadBuffer = (void *)&threadBuffers[i];
        // go MSM_ThreadFunc(&targs[i])
        pthread_create(&targs[i].tid, NULL, (void *(*)(void *))MSM_ThreadFunc, (void*)&targs[i]);
        if (targs[i].tid == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
            ret = CRYPT_ECC_NOT_SUPPORT;
            goto ERR;
        }
    }

    for (int32_t d = numWindows - 1; d >= 0; d--) {
        pthread_join(targs[d].tid, NULL);
        ECC_FreePoint(targs[d].acc);
        ECC_FreePoint(targs[d].temp);
        if (targs[d].ret != CRYPT_SUCCESS) {
            ret = targs[d].ret;
            goto ERR;
        }

        targs[d].tid = 0;
        if (!r_empty) {
            for (uint32_t i = 0; i < w; i++) {
                GOTO_ERR_IF_EX(para->method->pointDouble(para, r, r), ret);
            }
        }

        if (!targs[d].result_empty) {
            BN_BN2Array(results[d]->x, A, len);
            BN_BN2Array(results[d]->y, N, len);
            BN_BN2Array(results[d]->z, zero, len);
            
            if (r_empty) {
                GOTO_ERR_IF_EX(ECC_CopyPoint(r, results[d]), ret);
                r_empty = 0;
            } else {
                GOTO_ERR_IF_EX(para->method->pointAdd(para, r, r, results[d]), ret);
            }
        }
    }

    GOTO_ERR_IF_EX(para->method->point2Affine(para, r, r), ret);

ERR:
    for (uint32_t i = 0; i < numWindows; i++) {
        if (targs[i].tid != 0) {
            pthread_join(targs[i].tid, NULL);
            ECC_FreePoint(targs[i].acc);
            ECC_FreePoint(targs[i].temp);
        }
    }

    BN_OptimizerDestroy(opt);
    for (uint32_t i = 0; i < numWindows; i++) {
        ECC_FreePoint(results[i]);
    }
    BSL_SAL_FREE(bufferPtr);
    BN_Destroy(R_acc);
    BN_Destroy(R_bn);
    return ret;
}
