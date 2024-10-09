/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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