/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM3

#include "sm3_local.h"
#include "crypt_utils.h"

void SM3_Compress(uint32_t state[8], const uint8_t *data, uint32_t blockCnt)
{
    return SM3_CompressAsm(state, data, blockCnt);
}
#endif // HITLS_CRYPTO_SM3
