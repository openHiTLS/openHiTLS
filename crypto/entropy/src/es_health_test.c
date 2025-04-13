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
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>
#include <stddef.h>
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "es_health_test.h"

int32_t ES_HealthTestRct(ES_HealthTest *state, uint64_t data)
{
    if (data == state->lastData) {
        state->rctCount++;
        if (state->rctCount >= state->rctCutoff) {
            BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_RCT_FAILURE);
            return CRYPT_ENTROPY_RCT_FAILURE;
        }
    } else {
        state->lastData = data;
        state->rctCount = 1;
    }

    return CRYPT_SUCCESS;
}

int32_t ES_HealthTestApt(ES_HealthTest *state, uint64_t data)
{
    if (state->aptBaseSet == 0) { // NIST SP800-90B section 4.4.2 step 1/2
        state->aptBaseSet = 1;
        state->aptBaseData = data;
        state->aptCount = 1;
        state->aptI = 1;
        return CRYPT_SUCCESS;
    }

    if (state->aptBaseData == data) {
        state->aptCount++;
        if (state->aptCount >= state->aptCutOff) {
            state->aptBaseSet = 0; // Restart an APT window next time.
            BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_APT_FAILURE);
            return CRYPT_ENTROPY_APT_FAILURE;
        }
    }

    state->aptI++;
    if (state->aptI >= state->aptWindowSize) {
        state->aptBaseSet = 0;
    }
    return CRYPT_SUCCESS;
}

#endif