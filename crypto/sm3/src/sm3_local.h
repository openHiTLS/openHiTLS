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

#ifndef SM3_LOCAL_H
#define SM3_LOCAL_H


#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM3

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

void SM3_Compress(uint32_t state[8], const uint8_t *data, uint32_t blockCnt);

/* x86_64 AVX and SSE3 */
void SM3_CompressSIMD(uint32_t state[8], const uint8_t *data, uint32_t blockCnt);

/* assembly interface */
void SM3_CompressAsm(uint32_t state[8], const uint8_t *data, uint32_t blockCnt);


#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif // HITLS_CRYPTO_SM3

#endif // SM3_LOCAL_H
