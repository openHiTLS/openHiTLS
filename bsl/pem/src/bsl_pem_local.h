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

#ifndef BSL_PEM_LOCAL_H
#define BSL_PEM_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_PEM
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_PEM_BEGIN_STR "-----BEGIN"
#define BSL_PEM_BEGIN_STR_LEN 10
#define BSL_PEM_END_STR "-----END"
#define BSL_PEM_END_STR_LEN 8
#define BSL_PEM_SHORT_DASH_STR "-----"
#define BSL_PEM_SHORT_DASH_STR_LEN 5

#ifdef __cplusplus
}
#endif
#endif /* HITLS_BSL_PEM */
#endif
