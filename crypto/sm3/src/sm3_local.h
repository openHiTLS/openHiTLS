/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SM3_LOCAL_H
#define SM3_LOCAL_H


#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM3

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

void SM3_Compress(uint32_t state[8], const uint8_t *data, uint32_t blockCnt);
/* assembly interface */
void SM3_CompressAsm(uint32_t state[8], const uint8_t *data, uint32_t blockCnt);


#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif // HITLS_CRYPTO_SM3

#endif // SM3_LOCAL_H
