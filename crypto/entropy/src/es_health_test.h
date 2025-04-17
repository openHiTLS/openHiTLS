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

#ifndef ES_HEALTH_TEST_H
#define ES_HEALTH_TEST_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // RCT
    uint32_t rctCutoff; // NIST SP800-90B 4.4.1 Parameter C
    uint32_t rctCount; // NIST SP800-90B 4.4.1 Parameter B
    // APT
    uint32_t aptBaseSet; // Indicates whether aptBaseData has been set. The value must be initialized to 0.
    uint32_t aptCount; // NIST SP800-90B 4.4.2 Parameter B
    uint32_t aptWindowSize; // NIST SP800-90B 4.4.2 Parameter W
    uint32_t aptI; // counters
    uint32_t aptCutOff; // NIST SP800-90B 4.4.2 Parameter C
    uint64_t aptBaseData; // NIST SP800-90B 4.4.2 Parameter A
    uint64_t lastData; // NIST SP800-90B 4.4.1 Parameter A
} ES_HealthTest;

/* Repetition Count Test */
int32_t ES_HealthTestRct(ES_HealthTest *state, uint64_t data);

/* Adaptive Proportion Test */
int32_t ES_HealthTestApt(ES_HealthTest *state, uint64_t data);

#ifdef __cplusplus
}
#endif

#endif

#endif