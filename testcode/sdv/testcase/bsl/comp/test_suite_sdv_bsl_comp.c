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

/* BEGIN_HEADER */
#include <stdint.h>
#include <string.h>
#include "bsl_errno.h"
#include "bsl_comp.h"

#ifdef HITLS_BSL_COMP_ZLIB
#define SKIP_IF_ZLIB_UNSUPPORTED()
#else
#define SKIP_IF_ZLIB_UNSUPPORTED() SKIP_TEST()
#endif

/* END_HEADER */

static const uint8_t g_plainText[] =
    "openHiTLS RFC8879 certificate compression zlib round trip data. "
    "openHiTLS RFC8879 certificate compression zlib round trip data. "
    "openHiTLS RFC8879 certificate compression zlib round trip data.";

/* BEGIN_CASE */
void SDV_BSL_COMP_ZLIB_ROUNDTRIP_TC001(void)
{
    SKIP_IF_ZLIB_UNSUPPORTED();

    uint8_t compressed[256] = {0};
    uint8_t decompressed[sizeof(g_plainText)] = {0};
    uint32_t compressedLen = sizeof(compressed);
    uint32_t decompressedLen = sizeof(decompressed) - 1;
    uint32_t plainLen = sizeof(g_plainText) - 1;
    uint32_t bound = BSL_COMP_GetCompressBound(BSL_COMP_ALG_ZLIB, plainLen);

    ASSERT_TRUE(BSL_COMP_IsAlgSupported(BSL_COMP_ALG_ZLIB));
    ASSERT_TRUE(bound >= plainLen);
    ASSERT_TRUE(bound <= sizeof(compressed));
    ASSERT_EQ(BSL_COMP_Compress(BSL_COMP_ALG_ZLIB, g_plainText, plainLen, compressed, &compressedLen), BSL_SUCCESS);
    ASSERT_TRUE(compressedLen > 0);
    ASSERT_TRUE(compressedLen <= bound);
    ASSERT_TRUE(compressedLen < plainLen);
    ASSERT_EQ(BSL_COMP_Decompress(BSL_COMP_ALG_ZLIB, compressed, compressedLen, decompressed, &decompressedLen),
        BSL_SUCCESS);
    ASSERT_EQ(decompressedLen, plainLen);
    ASSERT_EQ(memcmp(g_plainText, decompressed, plainLen), 0);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_COMP_ZLIB_BOUNDARY_TC001(void)
{
    SKIP_IF_ZLIB_UNSUPPORTED();

    uint8_t compressed[256] = {0};
    uint8_t decompressed[sizeof(g_plainText)] = {0};
    uint8_t badCompressed[] = {0x78, 0x9c, 0x01, 0x02, 0x03, 0x04};
    uint32_t plainLen = sizeof(g_plainText) - 1;
    uint32_t compressedLen = 1;
    uint32_t decompressedLen = 1;
    uint32_t nullOutLen = sizeof(compressed);

    ASSERT_EQ(BSL_COMP_GetCompressBound(0xFFFFu, plainLen), 0);
    ASSERT_TRUE(!BSL_COMP_IsAlgSupported(0xFFFFu));
    ASSERT_EQ(BSL_COMP_Compress(0xFFFFu, g_plainText, plainLen, compressed, &nullOutLen), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_COMP_Compress(BSL_COMP_ALG_ZLIB, NULL, plainLen, compressed, &nullOutLen), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_COMP_Compress(BSL_COMP_ALG_ZLIB, g_plainText, plainLen, NULL, &nullOutLen), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_COMP_Compress(BSL_COMP_ALG_ZLIB, g_plainText, plainLen, compressed, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_COMP_Compress(BSL_COMP_ALG_ZLIB, g_plainText, plainLen, compressed, &compressedLen),
        BSL_INVALID_ARG);

    compressedLen = sizeof(compressed);
    ASSERT_EQ(BSL_COMP_Compress(BSL_COMP_ALG_ZLIB, g_plainText, plainLen, compressed, &compressedLen), BSL_SUCCESS);
    ASSERT_EQ(BSL_COMP_Decompress(BSL_COMP_ALG_ZLIB, compressed, compressedLen, decompressed, &decompressedLen),
        BSL_INVALID_ARG);
    decompressedLen = sizeof(decompressed) - 1;
    ASSERT_EQ(BSL_COMP_Decompress(BSL_COMP_ALG_ZLIB, badCompressed, sizeof(badCompressed), decompressed,
        &decompressedLen), BSL_INTERNAL_EXCEPTION);
    ASSERT_EQ(BSL_COMP_Decompress(BSL_COMP_ALG_ZLIB, NULL, compressedLen, decompressed, &decompressedLen),
        BSL_NULL_INPUT);
    ASSERT_EQ(BSL_COMP_Decompress(BSL_COMP_ALG_ZLIB, compressed, compressedLen, NULL, &decompressedLen),
        BSL_NULL_INPUT);
    ASSERT_EQ(BSL_COMP_Decompress(BSL_COMP_ALG_ZLIB, compressed, compressedLen, decompressed, NULL), BSL_NULL_INPUT);
EXIT:
    return;
}
/* END_CASE */
