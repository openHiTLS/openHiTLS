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

#ifndef SNI_H
#define SNI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SniArg {
    char  *serverName;
    int32_t alert;
} SNI_Arg;

/* compare whether the host names are the same */
int32_t SNI_StrcaseCmp(const char *s1, const char *s2);

#ifdef __cplusplus
}
#endif
#endif // ALPN_H