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

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "sal_ip_util.h"

/* END_HEADER */

/* BEGIN_CASE */
void SDV_BSL_SAL_IP_CHECK_FUNC_TC001(char *str, int len, Hex *data)
{
    unsigned char buff[16];
    int result = sizeof(buff) / sizeof(buff[0]);
    SAL_ParseIp(str, buff, &result);
    ASSERT_EQ(result, len);
    ASSERT_TRUE(memcmp(buff, data->x, data->len) == 0);

    unsigned char expectedBytes[16];
    if (inet_pton(AF_INET, str, expectedBytes) != 1) {
        inet_pton(AF_INET6, str, expectedBytes);
    }
    ASSERT_TRUE(memcmp(buff, expectedBytes, len) == 0);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_SAL_IP_CHECK_FUNC_TC002(char *str, int len)
{
#if defined(__APPLE__) && defined(__MACH__)
    (void)str;
    (void)len;
    SKIP_TEST();
#else
    unsigned char buff[16];
    int result = sizeof(buff) / sizeof(buff[0]);
    SAL_ParseIp(str, buff, &result);
    ASSERT_EQ(result, len);
    unsigned char expectedBytes[16];
    ASSERT_TRUE(inet_pton(AF_INET, str, expectedBytes) != 1);
    ASSERT_TRUE(inet_pton(AF_INET6, str, expectedBytes) != 1);
EXIT:
    return;
#endif
}
/* END_CASE */