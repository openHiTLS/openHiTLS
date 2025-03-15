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

#ifndef BN_OPTIMIZER_H
#define BN_OPTIMIZER_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include "bn_basic.h"

#ifdef __cplusplus
extern "c" {
#endif

#define CRYPT_OPTIMIZER_MAXDEEP 10
#define CRYPT_OPTIMIZER_BN_NUM 16

typedef struct ChunkStruct {
    uint32_t size;       /** < offset of used chunk */
    BN_BigNum bigNums[CRYPT_OPTIMIZER_BN_NUM];       /** < preset BN_BigNums */
    struct ChunkStruct *prev;  /** < prev optimizer node */
} Chunk;

struct BnOptimizer {
    uint32_t deep;      /* depth of stack */
    uint32_t used[CRYPT_OPTIMIZER_MAXDEEP];   /* size of the used stack */
    Chunk *chunk;         /** < chunk, the last point*/
    void *libCtx;
};

int32_t OptimizerStart(BN_Optimizer *opt);

/* match OptimizerStart */
void OptimizerEnd(BN_Optimizer *opt);
/* create a BigNum and initialize to 0 */
BN_BigNum *OptimizerGetBn(BN_Optimizer *opt, uint32_t room);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_BN

#endif // BN_OPTIMIZER_H
