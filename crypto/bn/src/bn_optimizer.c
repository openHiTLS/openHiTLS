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
#include <string.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bn_optimizer.h"

BN_Optimizer *BN_OptimizerCreate(void)
{
    BN_Optimizer *opt = BSL_SAL_Calloc(1u, sizeof(BN_Optimizer));
    if (opt == NULL) {
        return NULL;
    }
    opt->curChunk = BSL_SAL_Calloc(1u, sizeof(Chunk));
    if (opt->curChunk == NULL) {
        BSL_SAL_FREE(opt);
        return NULL;
    }
    return opt;
}

void BN_OptimizerSetLibCtx(void *libCtx, BN_Optimizer *opt)
{
    opt->libCtx = libCtx;
}

void BN_OptimizerDestroy(BN_Optimizer *opt)
{
    if (opt == NULL) {
        return;
    }
    Chunk *curChunk = opt->curChunk;
    Chunk *nextChunk = curChunk->next;
    Chunk *prevChunk = curChunk->prev;

    while (nextChunk != NULL) {
        for (uint32_t i = 0; i < HITLS_CRYPT_OPTIMIZER_BN_NUM; i++) {
            BSL_SAL_CleanseData((void *)(nextChunk->bigNums[i].data), nextChunk->bigNums[i].size * sizeof(BN_UINT));
            BSL_SAL_FREE(nextChunk->bigNums[i].data);
        }
        Chunk *tmp = nextChunk->next;
        BSL_SAL_Free(nextChunk);
        nextChunk = tmp;
    }

    while (prevChunk != NULL) {
        for (uint32_t i = 0; i < HITLS_CRYPT_OPTIMIZER_BN_NUM; i++) {
            BSL_SAL_CleanseData((void *)(prevChunk->bigNums[i].data), prevChunk->bigNums[i].size * sizeof(BN_UINT));
            BSL_SAL_FREE(prevChunk->bigNums[i].data);
        }
        Chunk *tmp = prevChunk->prev;
        BSL_SAL_Free(prevChunk);
        prevChunk = tmp;
    }
    // curChunk != NULL
    for (uint32_t i = 0; i < HITLS_CRYPT_OPTIMIZER_BN_NUM; i++) {
        BSL_SAL_CleanseData((void *)(curChunk->bigNums[i].data), curChunk->bigNums[i].size * sizeof(BN_UINT));
        BSL_SAL_FREE(curChunk->bigNums[i].data);
    }
    BSL_SAL_Free(curChunk);
    BSL_SAL_Free(opt);
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
static BN_BigNum *GetPresetBn(BN_Optimizer *opt, Chunk *curChunk)
{
    if (curChunk->occupied != HITLS_CRYPT_OPTIMIZER_BN_NUM) {
        curChunk->occupied++;
        return &curChunk->bigNums[curChunk->occupied - 1];
    }
    if (curChunk->prev != NULL) {
        opt->curChunk = curChunk->prev;
        opt->curChunk->occupied++; // new chunk and occupied = 0;
        return &opt->curChunk->bigNums[opt->curChunk->occupied - 1];
    }
    // We has used all chunks.
    Chunk *newChunk = BSL_SAL_Calloc(1u, sizeof(Chunk));
    if (newChunk == NULL) {
        return NULL;
    }
    newChunk->next = curChunk;
    curChunk->prev = newChunk;
    opt->curChunk = newChunk;
    newChunk->occupied++;
    return &newChunk->bigNums[newChunk->occupied - 1];
}

static int32_t BnMake(BN_BigNum *r, uint32_t room)
{
    if (r->room < room) {
        if (room > BITS_TO_BN_UNIT(BN_MAX_BITS)) {
            BSL_ERR_PUSH_ERROR(CRYPT_BN_BITS_TOO_MAX);
            return CRYPT_BN_BITS_TOO_MAX;
        }
        BN_UINT *tmp = (BN_UINT *)BSL_SAL_Calloc(1u, room * sizeof(BN_UINT));
        if (tmp == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        if (r->size > 0) {
            BSL_SAL_CleanseData(r->data, r->size * sizeof(BN_UINT));
        }
        BSL_SAL_FREE(r->data);
        r->data = tmp;
        r->room = room;
    } else {
        (void)memset_s(r->data, r->room * sizeof(BN_UINT), 0, r->room * sizeof(BN_UINT));
    }
    r->size = 0;
    r->sign = false;
    r->flag |= CRYPT_BN_FLAG_OPTIMIZER;
    return CRYPT_SUCCESS;
}
/* create a BigNum and initialize to 0 */
BN_BigNum *OptimizerGetBn(BN_Optimizer *opt, uint32_t room)
{
    if (opt->deep == 0) {
        return NULL;
    }
    if ((opt->used[opt->deep - 1] + 1) < opt->used[opt->deep - 1]) {
        // Avoid overflow
        return NULL;
    }
    BN_BigNum *tmp = GetPresetBn(opt, opt->curChunk);
    if (tmp == NULL) {
        return NULL;
    }
    if (BnMake(tmp, room) != CRYPT_SUCCESS) {
        return NULL;
    }
    opt->used[opt->deep - 1]++;
    return tmp;
}

void OptimizerEnd(BN_Optimizer *opt)
{
    if (opt->deep == 0) {
        return;
    }
    opt->deep--;
    uint32_t usedNum = opt->used[opt->deep];
    opt->used[opt->deep] = 0;
    Chunk *curChunk = opt->curChunk;
    if (usedNum <= curChunk->occupied) {
        curChunk->occupied -= usedNum;
        return;
    }
    usedNum -= curChunk->occupied;
    curChunk->occupied = 0;
    while (usedNum >= HITLS_CRYPT_OPTIMIZER_BN_NUM) {
        curChunk = curChunk->next;
        curChunk->occupied = 0;
        usedNum -= HITLS_CRYPT_OPTIMIZER_BN_NUM;
    }
    if (usedNum != 0) {
        curChunk = curChunk->next;
        curChunk->occupied = HITLS_CRYPT_OPTIMIZER_BN_NUM - usedNum;
    }
    opt->curChunk = curChunk;
    return;
}
#endif /* HITLS_CRYPTO_BN */
