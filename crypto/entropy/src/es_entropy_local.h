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

#ifndef ES_ENTROPY_LOCAL_H
#define ES_ENTROPY_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>
#include <stdbool.h>
#include "bsl_list.h"
#include "crypt_eal_entropy.h"
#include "es_entropy_pool.h"
#include "es_cf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Entropy-source aggregate, src-level so white-box tests can drive the
   noise-source list directly. */
struct ES_Entropy {
    bool isWork;           // Whether in working state
    bool enableTest;       // Whether to enable the health test
    uint32_t poolSize;     // Entropy pool size
    ES_EntropyPool *pool;  // Entropy pool
    ES_CfMethod *cfMeth;   // compression function handle
    BslList *nsList;
    CRYPT_EAL_EsLogFunc runLog;
};

#ifdef __cplusplus
}
#endif

#endif

#endif
