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

#ifndef BSL_COMP_H
#define BSL_COMP_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_COMP_ALG_ZLIB 1u

typedef int32_t (*BSL_COMP_OperateCb)(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
typedef uint32_t (*BSL_COMP_BoundCb)(uint32_t inLen);

typedef struct {
    uint16_t algId;
    BSL_COMP_OperateCb compress;
    BSL_COMP_OperateCb decompress;
    BSL_COMP_BoundCb bound;
} BSL_COMP_Method;

bool BSL_COMP_IsAlgSupported(uint16_t algId);

int32_t BSL_COMP_Compress(uint16_t algId, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

int32_t BSL_COMP_Decompress(uint16_t algId, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

uint32_t BSL_COMP_GetCompressBound(uint16_t algId, uint32_t inLen);

#ifdef __cplusplus
}
#endif

#endif /* BSL_COMP_H */
