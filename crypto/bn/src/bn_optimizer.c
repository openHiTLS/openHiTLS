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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bn_optimizer.h"

static Chunk *NewChunk(void)
{
    Chunk *chunk = BSL_SAL_Malloc(sizeof(Chunk));
    if (chunk == NULL) {
        return NULL;
    }
    memset_s(chunk, sizeof(Chunk), 0, sizeof(Chunk));
    return chunk;
}

BN_Optimizer *BN_OptimizerCreate(void)
{
    BN_Optimizer *opt = BSL_SAL_Malloc(sizeof(BN_Optimizer));
    if (opt == NULL) {
        return NULL;
    }
    memset_s(opt, sizeof(BN_Optimizer), 0, sizeof(BN_Optimizer));
    opt->chunk = NewChunk();
    if (opt->chunk == NULL) {
        BSL_SAL_FREE(opt);
        return NULL;
    }
    return opt;
}

void BN_OptimizerDestroy(BN_Optimizer *opt)
{
    if (opt == NULL) {
        return;
    }
    Chunk *head = opt->chunk;
    while (head != NULL) {
        for (uint32_t i = 0; i < CRYPT_OPTIMIZER_BN_NUM; i++) {
            BSL_SAL_CleanseData((void *)(head->bigNums[i].data), head->bigNums[i].size * sizeof(BN_UINT));
            BSL_SAL_FREE(head->bigNums[i].data);
        }
        opt->chunk = opt->chunk->prev;
        BSL_SAL_FREE(head);
        head = opt->chunk;
    }
    BSL_SAL_FREE(opt);
}

int32_t OptimizerStart(BN_Optimizer *opt)
{
    if (opt->deep != CRYPT_OPTIMIZER_MAXDEEP) {
        opt->deep++;
        return CRYPT_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_STACK_FULL);
    return CRYPT_BN_OPTIMIZER_STACK_FULL;
}

/* create a new room that has not been initialized */
BN_BigNum *GetPresetBn(BN_Optimizer *opt)
{
    if (opt->deep == 0) {
        return NULL;
    }
    if ((opt->used[opt->deep - 1] + 1) < opt->used[opt->deep - 1]) {
        // reverse
        return NULL;
    }
    Chunk *chunk = opt->chunk;
    if (chunk->size >= CRYPT_OPTIMIZER_BN_NUM) { /* expand it if it's not enough */
        Chunk *newChunk = NewChunk(); /* create a chunk and use this chunk as the header of opt->chunk linked list */
        if (newChunk == NULL) {
            return NULL;
        }
        newChunk->prev = chunk;
        chunk = newChunk;
        opt->chunk = chunk;
    }
    chunk->size++;
    opt->used[opt->deep - 1]++;

    return &chunk->bigNums[chunk->size - 1];
}

static BN_BigNum *BnMake(BN_BigNum *r, uint32_t room)
{
    if (BnExtend(r, room) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    memset_s(r->data, r->room * sizeof(BN_UINT), 0, r->room * sizeof(BN_UINT));
    r->size = 0;
    BN_CLRNEG(r->flag);
    r->flag |= CRYPT_BN_FLAG_OPTIMIZER;
    return r;
}

/* create a BigNum and initialize to 0 */
BN_BigNum *OptimizerGetBn(BN_Optimizer *opt, uint32_t room)
{
    BN_BigNum *tmp = GetPresetBn(opt);
    if (tmp == NULL) {
        return NULL;
    }
    return BnMake(tmp, room);
}

void OptimizerEnd(BN_Optimizer *opt)
{
    if (opt->deep == 0) {
        return;
    }
    opt->deep--;
    uint32_t used = opt->used[opt->deep];
    opt->used[opt->deep] = 0;
    Chunk *chunk = opt->chunk;

    if (chunk->size >= used) {
        opt->chunk->size -= used;
        return;
    }
    opt->chunk->size = 0;
    return;
}
#endif /* HITLS_CRYPTO_BN */
