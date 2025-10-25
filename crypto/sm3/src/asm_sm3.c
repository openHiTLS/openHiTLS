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
#ifdef HITLS_CRYPTO_SM3

#include "sm3_local.h"
#include "crypt_utils.h"

void SM3_Compress(uint32_t state[8], const uint8_t *data, uint32_t blockCnt)
{
#if defined (__x86_64__)
    if (IsSupportAVX() && IsSupportSSE3()) {
        return SM3_CompressSIMD(state, data, blockCnt);
    }
#endif
    return SM3_CompressAsm(state, data, blockCnt);
}
#endif // HITLS_CRYPTO_SM3
