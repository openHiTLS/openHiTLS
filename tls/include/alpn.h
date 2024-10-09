/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef ALPN_H
#define ALPN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t ALPN_SelectProtocol(uint8_t **out, uint32_t *outLen, uint8_t *clientAlpnList, uint32_t clientAlpnListLen,
    uint8_t *servAlpnList, uint32_t servAlpnListLen);

#ifdef __cplusplus
}
#endif
#endif // ALPN_H