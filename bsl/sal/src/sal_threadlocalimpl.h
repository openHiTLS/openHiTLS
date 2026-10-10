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

#ifndef SAL_THREADLOCALIMPL_H
#define SAL_THREADLOCALIMPL_H

#include "hitls_build.h"

#if defined(HITLS_BSL_ASYNC) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))

#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * POSIX pthread TLS implementation (posix/posix_threadlocal.c), used by the
 * dispatch layer in sal_threadlocal.c. Failure codes are returned without
 * pushing to the BSL error stack; the dispatch layer owns that.
 */
int32_t SAL_ThreadLocalKeyCreate(BSL_SAL_ThreadLocalKey *key, BSL_SAL_ThreadLocalCleanup cleanup);
int32_t SAL_ThreadLocalKeyDelete(BSL_SAL_ThreadLocalKey key);
void *SAL_ThreadLocalGet(BSL_SAL_ThreadLocalKey key);
int32_t SAL_ThreadLocalSet(BSL_SAL_ThreadLocalKey key, void *value);

#ifdef __cplusplus
}
#endif

#endif

#endif
