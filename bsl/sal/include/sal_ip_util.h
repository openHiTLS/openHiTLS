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

#ifndef SAL_IP_UTIL_H
#define SAL_IP_UTIL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t SAL_ParseIp(const char *ip, unsigned char *bytes, int32_t *outLen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SAL_IP_UTIL_H