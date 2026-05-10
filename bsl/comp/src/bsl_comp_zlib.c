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

#ifdef HITLS_BSL_COMP_ZLIB
#include <limits.h>
#include <zlib.h>
#include "bsl_errno.h"
#include "bsl_comp.h"

static int32_t BSL_COMP_ZlibCompress(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (*outLen > UINT_MAX) {
        return BSL_INVALID_ARG;
    }

    uLongf zlibOutLen = (uLongf)*outLen;
    int zret = compress2(out, &zlibOutLen, in, (uLong)inLen, Z_DEFAULT_COMPRESSION);
    if (zret == Z_BUF_ERROR) {
        return BSL_INVALID_ARG;
    }
    if (zret != Z_OK || zlibOutLen > UINT32_MAX) {
        return BSL_INTERNAL_EXCEPTION;
    }
    *outLen = (uint32_t)zlibOutLen;
    return BSL_SUCCESS;
}

static int32_t BSL_COMP_ZlibDecompress(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (*outLen > UINT_MAX) {
        return BSL_INVALID_ARG;
    }

    uLongf zlibOutLen = (uLongf)*outLen;
    int zret = uncompress(out, &zlibOutLen, in, (uLong)inLen);
    if (zret == Z_BUF_ERROR) {
        return BSL_INVALID_ARG;
    }
    if (zret != Z_OK || zlibOutLen > UINT32_MAX) {
        return BSL_INTERNAL_EXCEPTION;
    }
    *outLen = (uint32_t)zlibOutLen;
    return BSL_SUCCESS;
}

static uint32_t BSL_COMP_ZlibBound(uint32_t inLen)
{
    uLong bound = compressBound((uLong)inLen);
    if (bound > UINT32_MAX) {
        return 0;
    }
    return (uint32_t)bound;
}

const BSL_COMP_Method *BSL_COMP_GetZlibMethod(void)
{
    static const BSL_COMP_Method method = {
        BSL_COMP_ALG_ZLIB,
        BSL_COMP_ZlibCompress,
        BSL_COMP_ZlibDecompress,
        BSL_COMP_ZlibBound
    };

    return &method;
}
#endif /* HITLS_BSL_COMP_ZLIB */
