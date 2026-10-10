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

#ifndef BENCH_HANDSHAKE_H
#define BENCH_HANDSHAKE_H

#include "async_perf_opt.h"
#include "crypt_eal_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

int PerfBenchHandshake(const PerfOptions *opt, const PerfScenario *s, CRYPT_EAL_LibCtx *libCtx,
                       CRYPT_EAL_ProvMgrCtx *mgr);

#ifdef __cplusplus
}
#endif

#endif /* BENCH_HANDSHAKE_H */
