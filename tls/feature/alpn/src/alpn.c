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

#include <stdint.h>
#include "securec.h"
#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "alpn.h"

int32_t ALPN_SelectProtocol(uint8_t **out, uint32_t *outLen, uint8_t *clientAlpnList, uint32_t clientAlpnListLen,
    uint8_t *servAlpnList, uint32_t servAlpnListLen)
{
    if (out == NULL || outLen == NULL || clientAlpnList == NULL || servAlpnList == NULL ||
        servAlpnListLen == 0 || clientAlpnListLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    uint32_t i, j;
    for (i = 0; i < servAlpnListLen;) {
        for (j = 0; j < clientAlpnListLen;) {
            if (servAlpnList[i] == clientAlpnList[j] &&
                (memcmp(&servAlpnList[i + 1], &clientAlpnList[j + 1], servAlpnList[i]) == 0)) {
                *out = &servAlpnList[i];
                *outLen = servAlpnList[i] + 1;
                goto END;
            }
            j = j + clientAlpnList[j];
            ++j;
        }
        i = i + servAlpnList[i];
        ++i;
    }

END:
    return HITLS_SUCCESS;
}