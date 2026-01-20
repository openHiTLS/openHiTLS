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
#include "bsl_buffer.h"

/* END_HEADER */

/* BEGIN_CASE */
void SDV_BSL_BUFFER_FUNC_buffer_new(void)
{
    TestMemInit();
    // 1. Allocate a buffer.
    BSL_BufMem *buf = BSL_BufMemNew();
    ASSERT_EQ(buf->length, 0);
    ASSERT_EQ(buf->max, 0);

    // 2. len=3, len > buf->max
    (void)BSL_BufMemGrowClean(buf, 3);
    ASSERT_EQ(buf->length, 3);
    ASSERT_EQ(buf->max, 8);

    // 3. len=2, len < buf->length
    (void)BSL_BufMemGrowClean(buf, 2);
    ASSERT_EQ(buf->length, 2);
    ASSERT_EQ(buf->max, 8);

    // 4. len=6, buf->length < len < buf->max
    (void)BSL_BufMemGrowClean(buf, 6);
    ASSERT_EQ(buf->length, 6);
    ASSERT_EQ(buf->max, 8);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_BufMemFree(buf);
}
/* END_CASE */