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

#ifndef ENTROPY_SEED_POOL_H
#define ENTROPY_SEED_POOL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ENTROPY

#include <stdint.h>
#include "crypt_entropy.h"
#include "bsl_list.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    bool isPhysical;
    uint32_t minEntropy;
    void *ctx;
    EntropyGet entropyGet;
} ENTROPY_Source;

struct EntropySeedPool {
    bool isContainFes;
    bool isContainPes;
    uint32_t minEntropy;
    BslList *esList;
};

uint32_t ENTROPY_HWEntropyGet(void *ctx, uint8_t *buf, uint32_t bufLen);

uint32_t ENTROPY_SysEntropyGet(void *ctx, uint8_t *buf, uint32_t bufLen);

#ifdef __cplusplus
}
#endif

#endif

#endif