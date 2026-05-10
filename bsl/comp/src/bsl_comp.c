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

#include <stddef.h>
#include "hitls_build.h"
#include "bsl_errno.h"
#include "bsl_comp_internal.h"
#include "bsl_comp.h"

static const BSL_COMP_Method *BSL_COMP_GetMethod(uint16_t algId)
{
#ifdef HITLS_BSL_COMP_ZLIB
    const BSL_COMP_Method *method = BSL_COMP_GetZlibMethod();
    if (method != NULL && method->algId == algId) {
        return method;
    }
#else
    (void)algId;
#endif
    return NULL;
}

bool BSL_COMP_IsAlgSupported(uint16_t algId)
{
    return BSL_COMP_GetMethod(algId) != NULL;
}

int32_t BSL_COMP_Compress(uint16_t algId, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (in == NULL || out == NULL || outLen == NULL) {
        return BSL_NULL_INPUT;
    }

    const BSL_COMP_Method *method = BSL_COMP_GetMethod(algId);
    if (method == NULL || method->compress == NULL) {
        return BSL_INVALID_ARG;
    }
    return method->compress(in, inLen, out, outLen);
}

int32_t BSL_COMP_Decompress(uint16_t algId, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (in == NULL || out == NULL || outLen == NULL) {
        return BSL_NULL_INPUT;
    }

    const BSL_COMP_Method *method = BSL_COMP_GetMethod(algId);
    if (method == NULL || method->decompress == NULL) {
        return BSL_INVALID_ARG;
    }
    return method->decompress(in, inLen, out, outLen);
}

uint32_t BSL_COMP_GetCompressBound(uint16_t algId, uint32_t inLen)
{
    const BSL_COMP_Method *method = BSL_COMP_GetMethod(algId);
    if (method == NULL || method->bound == NULL) {
        return 0;
    }
    return method->bound(inLen);
}
