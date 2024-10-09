/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
