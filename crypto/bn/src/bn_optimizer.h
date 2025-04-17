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

/*
 * Peak memory usage of the bn process during RSA key generation. BN_NUM stands for HITLS_CRYPT_OPTIMIZER_BN_NUM.
 * |----------------------------+--------+--------+--------+--------+--------|
 * | key bits\memory(Kb)\BN_NUM |   16   |   24   |   32   |   48   |   64   |
 * |----------------------------+--------+--------+--------+--------+--------|
 * |           rsa1024          |  9.0   |  9.7   |  9.7   |  10.8  |  12.0  |
 * |           rsa2048          |  20.4  |  21.0  |  21.1  |  22.6  |  22.6  |
 * |           rsa3072          |  37.8  |  38.3  |  38.5  |  40.0  |  40.0  |
 * |           rsa4096          |  73.5  |  73.5  |  74.2  |  75.7  |  75.7  |
 * |----------------------------+--------+--------+--------+--------+--------|
 *
 * The number of chunk during RSA key generation. BN_NUM stands for HITLS_CRYPT_OPTIMIZER_BN_NUM.
 * |----------------------------+--------+--------+--------+--------+--------|
 * |key bits\chunk number\BN_NUM|   16   |   24   |   32   |   48   |   64   |
 * |----------------------------+--------+--------+--------+--------+--------|
 * |           rsa1024          |  352   |  352   |  193   |  193   |  193   |
 * |           rsa2048          |  1325  |  1035  |  745   |  745   |  455   |
 * |           rsa3072          |  1597  |  1227  |  857   |  857   |  487   |
 * |           rsa4096          |  2522  |  1967  |  1412  |  1412  |  857   |
 * |----------------------------+--------+--------+--------+--------+--------|
 */
#ifndef HITLS_CRYPT_OPTIMIZER_BN_NUM
    #define HITLS_CRYPT_OPTIMIZER_BN_NUM 32
#endif

typedef struct ChunkStruct {
    uint32_t occupied;       /** < occupied of current chunk */
    BN_BigNum bigNums[HITLS_CRYPT_OPTIMIZER_BN_NUM];       /** < preset BN_BigNums */
    struct ChunkStruct *prev;  /** < prev optimizer node */
    struct ChunkStruct *next;  /** < prev optimizer node */
} Chunk;

struct BnOptimizer {
    uint32_t deep;      /* depth of stack */
    uint32_t used[CRYPT_OPTIMIZER_MAXDEEP];   /* size of the used stack */
    Chunk *curChunk;         /** < chunk, the last point*/
    void *libCtx;
};

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_BN */

#endif
