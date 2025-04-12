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

#ifndef BSL_UTIL_INTERNAL_H
#define BSL_UTIL_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

// check if gcc/clang defined 128 bits int
#ifdef __SIZEOF_INT128__

typedef __int128_t int128_t;
typedef __uint128_t uint128_t;

#endif

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif // BSL_UTIL_INTERNAL_H
